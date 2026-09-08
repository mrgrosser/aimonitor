"""Microsoft Graph Copilot adoption reports, collected without user enumeration."""
from asyncio import sleep
from contextlib import closing
from datetime import datetime,timezone
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
    return db

def saved(period):
    with closing(database()) as db:row=db.execute('SELECT payload FROM copilot_analytics WHERE period=?',(period,)).fetchone()
    return json.loads(row[0]) if row else None

def periods():
    with closing(database()) as db:names={r[0] for r in db.execute('SELECT period FROM copilot_analytics')}
    return [{'period':f'Copilot - last {d} days'} for d in WINDOWS if f'Copilot - last {d} days' in names]

def count(value):
    if value is None or str(value).strip()=='':return None
    number=int(value)
    if number<0:raise ValueError('Negative adoption count')
    return number

def parse(response,trend=False):
    if 'json' in response.headers.get('content-type',''):
        body=response.json();output=[]
        for parent in body['value']:
            for row in parent['adoptionByDate' if trend else 'adoptionByProduct']:
                output.append({'reportRefreshDate':parent['reportRefreshDate'],'reportPeriod':parent.get('reportPeriod'),**row})
        return output
    aliases={'Report Refresh Date':'reportRefreshDate','Report Date':'reportDate','Report Period':'reportPeriod','Any App Active Users':'anyAppActiveUsers','Any App Enabled Users':'anyAppEnabledUsers'}
    for key,name in APPS.items():
        csv_name='Microsoft Teams' if key=='microsoftTeams' else name
        for suffix in ('Active Users','Enabled Users'):aliases[f'{csv_name} {suffix}']=key+suffix.replace(' ','')
    rows=list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig'))))
    return [{aliases.get(k.strip(),k.strip()):v.strip() if isinstance(v,str) else v for k,v in row.items() if k is not None} for row in rows]

async def fetch(client,token,days,trend=False):
    method='getMicrosoft365CopilotUserCountTrend' if trend else 'getMicrosoft365CopilotUserCountSummary'
    url=f"https://graph.microsoft.com/v1.0/copilot/reports/{method}(period='D{days}')"
    response=await compliance_gate().get(client,url,headers={'Authorization':f'Bearer {token}'},params={'$format':'text/csv'})
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
    rows=parse(response,trend)
    if not rows:raise ValueError('Empty Microsoft usage report')
    return rows

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
    daily=[{'Date':datetime.fromisoformat(r['reportDate']).date().isoformat(),'Active users':count(r['anyAppActiveUsers'])} for r in trend]
    return {'mode':'live','period':f'Copilot - last {days} days','source':f'Microsoft Graph Copilot adoption · {days}-day window · Microsoft refreshed {refresh}','collected_at':datetime.now(timezone.utc).isoformat(),'report_refresh_date':refresh,'summary':{'copilot_active_users':active,'copilot_enabled_users':enabled},'licensing':{},'copilot_adoption':apps,'copilot_user_trend':daily,'copilot_apps':[],'claude_products':[],'claude_models':[],'top_users':[],'executive_sections':[{'name':'Copilot adoption summary','rows':[['Measure','Value'],['Rolling window days',days],['Microsoft refresh date',refresh],['Active users',active],['Enabled users',enabled]]},{'name':'Copilot users by app','rows':[['App','Active users','Enabled users']]+[[r['name'],r['users'],r['enabled']] for r in apps]},{'name':'Copilot active user trend','rows':[['Date','Active users']]+[[r['Date'],r['Active users']] for r in daily]}],'caveats':['Microsoft reports a rolling window, not a calendar month.','Counts are active users, not prompts or interactions. Users can use multiple apps; do not sum app counts.','This source reports enabled Microsoft 365 Copilot adoption; it is not a complete Purview audit of every unlicensed Copilot Chat interaction.','Microsoft report refresh dates can lag collection time. No usage price or seat cost is supplied.']}

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
                    if old and (datetime.now(timezone.utc)-datetime.fromisoformat(old['collected_at'])).total_seconds()<21600:continue
                    data=await collect(client,await token_provider(),days)
                    with closing(database()) as db:
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
        await sleep(21600)
