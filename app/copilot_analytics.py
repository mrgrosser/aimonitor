"""Microsoft Graph Copilot adoption and licensed-user usage reports."""
from asyncio import sleep
from contextlib import closing
from datetime import datetime,timezone,timedelta
import calendar
import csv
import io
import json
import logging
import sqlite3
from urllib.parse import urlparse
import httpx
from app import usage_reporting
from app.compliance_http import compliance_gate

status={'state':'pending','message':'Copilot usage waiting for first collection'}
WINDOWS=(7,30,90,180)
APPS={'microsoftTeams':'Teams','word':'Word','excel':'Excel','powerPoint':'PowerPoint','outlook':'Outlook','oneNote':'OneNote','loop':'Loop','copilotChat':'Copilot Chat'}

def database():
    db=sqlite3.connect(usage_reporting.DB_PATH,timeout=30)
    db.execute('CREATE TABLE IF NOT EXISTS copilot_analytics (period TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    db.execute("CREATE TABLE IF NOT EXISTS copilot_snapshots (period TEXT, refresh TEXT, payload TEXT NOT NULL, PRIMARY KEY(period,refresh))")
    return db

def saved(period):
    if period.startswith("Copilot - month "):return monthly(period.removeprefix("Copilot - month "))
    with closing(database()) as db:row=db.execute('SELECT payload FROM copilot_analytics WHERE period=?',(period,)).fetchone()
    return json.loads(row[0]) if row else None

def periods():
    with closing(database()) as db:names={r[0] for r in db.execute('SELECT period FROM copilot_analytics')}
    return [{'period':f'Copilot - last {d} days'} for d in WINDOWS if f'Copilot - last {d} days' in names]+[{'period':'Copilot - month '+m} for m in sorted({d[:7] for d in history()},reverse=True)]

def history():
    # Include legacy cached windows immediately, without waiting for a new sync.
    with closing(database()) as db:
        reports=[json.loads(r[0]) for r in db.execute('SELECT payload FROM copilot_snapshots UNION ALL SELECT payload FROM copilot_analytics')]
    daily={}
    for report in sorted(reports,key=lambda r:(r.get('report_refresh_date',''),r.get('collected_at',''))):
        for row in report.get('copilot_user_trend',[]):
            if row.get('Active users') is not None:
                daily[row['Date']]={**row,'refresh':report.get('report_refresh_date'),'collected':report.get('collected_at')}
    return daily


def monthly(month):
    datetime.strptime(month,'%Y-%m')
    rows=[r for day,r in sorted(history().items()) if day.startswith(month+'-')]
    if not rows:return None
    expected=calendar.monthrange(int(month[:4]),int(month[5:]))[1]
    coverage=f'{len(rows)} of {expected} calendar days available'
    daily=[{'Date':r['Date'],'Active users':r['Active users'],'Enabled users':r.get('Enabled users')} for r in rows]
    average=round(sum(r['Active users'] for r in rows)/len(rows),2)
    peak=max(r['Active users'] for r in rows)
    enabled=[r for r in rows if r.get('Enabled users') is not None]
    metrics=[['Average daily active users',average],['Peak daily active users',peak]]
    if enabled:metrics.append(['Enabled users as of '+enabled[-1]['Date'],enabled[-1]['Enabled users']])
    return {'mode':'live','period':'Copilot - month '+month,'source':'Microsoft Graph Copilot daily adoption history',
        'collected_at':max(r['collected'] for r in rows),'report_refresh_date':max(r['Date'] for r in rows),
        'summary':{'copilot_average_daily_users':average,'copilot_peak_daily_users':peak,'copilot_reported_days':len(rows),'copilot_calendar_days':expected},'top_users':[],'copilot_user_trend':daily,
        'executive_sections':[{'name':'Copilot monthly coverage','rows':[['Measure','Value'],['Calendar month',month],['Coverage',coverage],['Monthly unique active users','Unavailable from daily aggregate counts'],]+metrics},{'name':'Copilot daily active users','rows':[['Date','Active users','Enabled users']]+[[r['Date'],r['Active users'],r.get('Enabled users')] for r in rows]}],
        'caveats':[coverage+'. Missing days are not treated as zero.','Average includes reported zero-activity days and divides by available days only.','Monthly unique users and prompt totals are unavailable from this source; daily users must not be summed.','History is preserved from collected Microsoft rolling reports. Dates outside available history cannot be reconstructed.']}


def count(value):
    if value is None or str(value).strip()=='':return None
    number=int(value)
    if number<0:raise ValueError('Negative adoption count')
    return number

def parse(response,trend=False,detail=False):
    if 'json' in response.headers.get('content-type',''):
        body=response.json();output=[]
        if detail: return body['value']
        for parent in body['value']:
            for row in parent['adoptionByDate' if trend else 'adoptionByProduct']:
                output.append({'reportRefreshDate':parent['reportRefreshDate'],'reportPeriod':parent.get('reportPeriod'),**row})
        return output
    aliases={'Report Refresh Date':'reportRefreshDate','Report Date':'reportDate','Report Period':'reportPeriod','Any App Active Users':'anyAppActiveUsers','Any App Enabled Users':'anyAppEnabledUsers'}
    aliases.update({'User Principal Name':'userPrincipalName','Last Activity Date':'lastActivityDate'})
    for key,name in APPS.items():
        csv_name='Microsoft Teams' if key=='microsoftTeams' else name
        aliases[f'{csv_name} Copilot Last Activity Date' if key!='copilotChat' else 'Copilot Chat Last Activity Date']=key+'LastActivityDate' if key=='copilotChat' else key+'CopilotLastActivityDate'
        for suffix in ('Active Users','Enabled Users'):aliases[f'{csv_name} {suffix}']=key+suffix.replace(' ','')
    rows=list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig'))))
    return [{aliases.get(k.strip(),k.strip()):v.strip() if isinstance(v,str) else v for k,v in row.items() if k is not None} for row in rows]

async def fetch(client,token,days,trend=False,detail=False):
    method='getMicrosoft365CopilotUserCountTrend' if trend else 'getMicrosoft365CopilotUserCountSummary'
    if detail: method='getMicrosoft365CopilotUsageUserDetail'
    url=f"https://graph.microsoft.com/v1.0/copilot/reports/{method}(period='D{days}')"
    return await fetch_report(client,token,url,trend,detail)

async def fetch_report(client,token,url,trend=False,detail=False,seen=None):
    seen=set() if seen is None else seen
    if url in seen or len(seen)>=1000: raise ValueError('Invalid Microsoft report pagination')
    seen.add(url)
    response=await compliance_gate().get(client,url,headers={'Authorization':f'Bearer {token}'},params=None if urlparse(url).query else {'$format':'text/csv'})
    if response.status_code == 302:
        # Graph report URLs are preauthenticated. Never forward the bearer token.
        location=response.headers.get('location','')
        target=urlparse(location)
        host=(target.hostname or '').lower()
        if target.scheme!='https' or target.username or target.password or target.port not in (None,443) or not (host in {'reports.office.com','reportsncu.office.com'} or host.endswith('.reports.office.com')):
            raise ValueError('Unexpected Microsoft report download host: '+host)
        async with httpx.AsyncClient(timeout=60,follow_redirects=False) as download:
            response=await compliance_gate().get(download,location)
    response.raise_for_status()
    rows=parse(response,trend,detail)
    if detail and 'json' in response.headers.get('content-type',''):
        following=response.json().get('@odata.nextLink')
        if following:
            target=urlparse(following)
            if target.scheme!='https' or target.netloc!='graph.microsoft.com' or not target.path.startswith('/v1.0/copilot/reports/getMicrosoft365CopilotUsageUserDetail('):
                raise ValueError('Invalid Microsoft report pagination')
            rows+=await fetch_report(client,token,following,detail=True,seen=seen)
    if not rows and not detail:raise ValueError('Empty Microsoft usage report')
    return rows

def user_rows(rows,days,refresh):
    users={}
    cutoff=(datetime.fromisoformat(refresh).date()-timedelta(days=days-1)).isoformat()
    for row in rows:
        identity=row.get('userPrincipalName')
        if not identity: raise ValueError('Missing Microsoft user identity')
        if row.get('reportRefreshDate')!=refresh: raise ValueError('Inconsistent Microsoft report refresh; retry later')
        periods=row.get('copilotActivityUserDetailsByPeriod') or [{'reportPeriod':row.get('reportPeriod')}]
        if not any(int(p['reportPeriod'])==days for p in periods): raise ValueError('Unexpected reporting window')
        last=row.get('lastActivityDate') or None
        if last: last=datetime.fromisoformat(last).date().isoformat()
        products=[]
        for key,name in APPS.items():
            value=row.get(key+'LastActivityDate' if key=='copilotChat' else key+'CopilotLastActivityDate')
            if value and cutoff<=datetime.fromisoformat(value).date().isoformat()<=refresh: products.append(name)
        users[identity]={'user':identity,'alias':usage_reporting._alias(identity),'provider':'Microsoft 365 Copilot',
            'volume':None,'spend':None,'active_days':None,'last_activity':last,
            'activity_status':'Active in period' if last and cutoff<=last<=refresh else 'No recorded activity in period',
            'license_status':'Included in licensed-user report','products':products,'breakdown':[]}
    return sorted(users.values(),key=lambda r:r['user'].casefold())

async def collect(client,token,days):
    summary=await fetch(client,token,days)
    trend=await fetch(client,token,days,True)
    if len(summary)!=1:raise ValueError('Unexpected summary rows')
    row=summary[0]
    if int(row['reportPeriod'])!=days:raise ValueError('Unexpected reporting window')
    refresh=datetime.fromisoformat(row['reportRefreshDate']).date().isoformat()
    if any(r['reportRefreshDate']!=row['reportRefreshDate'] or int(r['reportPeriod'])!=days for r in trend):raise ValueError('Inconsistent Microsoft report refresh; retry later')
    active=count(row['anyAppActiveUsers']);enabled=count(row['anyAppEnabledUsers'])
    if active is None or enabled is None:raise ValueError('Missing Microsoft adoption totals')
    apps=[{'name':name,'users':count(row.get(key+'ActiveUsers')),'enabled':count(row.get(key+'EnabledUsers'))} for key,name in APPS.items()]
    apps.sort(key=lambda r:r['users'] is None)
    users=user_rows(await fetch(client,token,days,detail=True),days,refresh)
    daily=[{'Date':datetime.fromisoformat(r['reportDate']).date().isoformat(),'Active users':count(r['anyAppActiveUsers']),'Enabled users':count(r.get('anyAppEnabledUsers'))} for r in trend]
    return {'mode':'live','period':f'Copilot - last {days} days','source':f'Microsoft Graph Copilot adoption · {days}-day window · Microsoft refreshed {refresh}','collected_at':datetime.now(timezone.utc).isoformat(),'report_refresh_date':refresh,'summary':{'copilot_active_users':active,'copilot_enabled_users':enabled},'licensing':{},'copilot_adoption':apps,'copilot_user_trend':daily,'copilot_apps':[],'claude_products':[],'claude_models':[],'top_users':users,'user_report_schema':1,'executive_sections':[{'name':'Copilot adoption summary','rows':[['Measure','Value'],['Rolling window days',days],['Microsoft refresh date',refresh],['Active users',active],['Enabled users',enabled]]},{'name':'Copilot users by app','rows':[['App','Active users','Enabled users']]+[[r['name'],r['users'],r['enabled']] for r in apps]},{'name':'Copilot active user trend','rows':[['Date','Active users']]+[[r['Date'],r['Active users']] for r in daily]}],'caveats':['User rows include blank activity records from the licensed-user report. Report membership is not a real-time license assignment check. Microsoft may conceal identities in report settings.','Per-user prompt counts and active-day counts are not supplied by this report version.','Microsoft reports a rolling window, not a calendar month.','Counts are active users, not prompts or interactions. Users can use multiple apps; do not sum app counts.','This source reports enabled Microsoft 365 Copilot adoption; it is not a complete Purview audit of every unlicensed Copilot Chat interaction.','Microsoft report refresh dates can lag collection time. No usage price or seat cost is supplied.']}

def error_detail(response):
    """Retain Microsoft's diagnostic text, never request headers or credentials."""
    try:
        error=response.json().get('error',{})
        code=str(error.get('code',''))[:100]
        message=str(error.get('message',''))[:700]
    except (ValueError,AttributeError):
        code='';message='Microsoft returned a non-JSON error response.'
    request_id=response.headers.get('request-id','')[:100]
    return f"{code}: {message}" + (f" (request ID: {request_id})" if request_id else '')

def failure_detail(exc):
    # Do not expose exception URLs: report download links contain access tokens.
    if isinstance(exc,KeyError):
        return 'Missing report field: '+str(exc.args[0])[:100]
    if isinstance(exc,ValueError):
        message=str(exc)
        known=('Unexpected Microsoft report download host:', 'Empty Microsoft usage report', 'Unexpected summary rows', 'Unexpected reporting window', 'Inconsistent Microsoft report refresh', 'Missing Microsoft adoption totals', 'Negative adoption count')
        return message[:250] if message.startswith(known) else 'Invalid report value or CSV encoding (ValueError)'
    if isinstance(exc,httpx.RequestError):return 'Microsoft download/network failure: '+type(exc).__name__
    if isinstance(exc,sqlite3.Error):return 'Local analytics database failure: '+type(exc).__name__
    return 'Collector failure: '+type(exc).__name__

async def run(token_provider):
    while True:
        status.update(state='syncing',message='Collecting Microsoft Copilot usage')
        try:
            async with httpx.AsyncClient(timeout=60,follow_redirects=False) as client:
                for days in WINDOWS:
                    old=saved(f'Copilot - last {days} days')
                    if old:
                        with closing(database()) as db:
                            db.execute('INSERT OR IGNORE INTO copilot_snapshots VALUES (?,?,?)',(old['period'],old['report_refresh_date'],json.dumps(old)));db.commit()
                    if old and old.get('user_report_schema') == 1 and (datetime.now(timezone.utc)-datetime.fromisoformat(old['collected_at'])).total_seconds()<21600:continue
                    data=await collect(client,await token_provider(),days)
                    with closing(database()) as db:
                        db.execute('INSERT OR REPLACE INTO copilot_snapshots VALUES (?,?,?)',(data['period'],data['report_refresh_date'],json.dumps(data)))
                        db.execute('INSERT OR REPLACE INTO copilot_analytics VALUES (?,?)',(data['period'],json.dumps(data)));db.commit()
            status.update(state='ready',message='Copilot usage collection succeeded')
        except httpx.HTTPStatusError as exc:
            code=exc.response.status_code
            from app.governance import audit
            detail=error_detail(exc.response)
            audit('system','copilot_usage_failed','usage_report',details={'status':code,'diagnostic':detail})
            status.update(state='error',message=f'Copilot usage HTTP {code}. '+('Grant Microsoft Graph application Reports.Read.All and admin consent.' if code in (401,403) else 'Previous results retained; collection will retry.')+' '+detail)
        except Exception as exc:
            from app.governance import audit
            detail=failure_detail(exc)
            logging.getLogger(__name__).error('copilot_usage_failed: %s',detail)
            audit('system','copilot_usage_failed','usage_report',details={'error_type':type(exc).__name__,'diagnostic':detail})
            status.update(state='error',message='Copilot usage failed: '+detail+'. Previous results retained; collection will retry.')
        status["next_refresh_at"]=(datetime.now(timezone.utc)+timedelta(seconds=21600)).isoformat()
        await sleep(21600)
