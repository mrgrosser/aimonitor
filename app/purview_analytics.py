"""Purview Copilot metadata analytics. Never retain prompt/response or resource content."""
import asyncio
import json
import logging
import os
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

import httpx
from app import usage_reporting
from app.claude_analytics import months
from app.copilot_analytics import error_detail
from app.compliance_http import compliance_gate

GRAPH='https://graph.microsoft.com/v1.0'
status={'state':'not_configured','message':'Purview interaction analytics is not enabled'}
APP_NAMES={'Office':'Microsoft 365 Copilot app','m365copilot':'Microsoft 365 Copilot app',
           'OutlookSidepane':'Outlook','Microsoft Teams':'Teams'}


def database():
    db=sqlite3.connect(usage_reporting.DB_PATH,timeout=30)
    db.execute('CREATE TABLE IF NOT EXISTS purview_reports (period TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS purview_jobs (period TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    return db


def saved(period):
    with closing(database()) as db:
        row=db.execute('SELECT payload FROM purview_reports WHERE period=?',(period,)).fetchone()
    return json.loads(row[0]) if row else None


def periods():
    with closing(database()) as db:return [{'period':'Copilot - month '+r[0]} for r in db.execute('SELECT period FROM purview_reports ORDER BY period DESC')]


async def graph_pages(client,token,url,prefix):
    rows=[];seen=set()
    while url:
        parsed=urlparse(url)
        if parsed.scheme!='https' or parsed.netloc!='graph.microsoft.com' or parsed.path!=prefix or url in seen or len(seen)>=10000:
            raise ValueError('Invalid Graph analytics pagination')
        seen.add(url)
        response=await compliance_gate().get(client,url,headers={'Authorization':'Bearer '+token})
        response.raise_for_status();body=response.json()
        if not isinstance(body.get('value'),list):raise ValueError('Invalid Graph analytics response')
        rows.extend(body['value']);url=body.get('@odata.nextLink')
    return rows


def normalize(record):
    raw=record.get('auditData',record.get('AuditData',record))
    if isinstance(raw,str):raw=json.loads(raw)
    if (raw.get('Operation') or record.get('operation'))!='CopilotInteraction':return None
    event=raw.get('CopilotEventData') or {}
    identity=record.get('userPrincipalName') or raw.get('UserId')
    rid=raw.get('Id') or record.get('id')
    timestamp=raw.get('CreationTime') or record.get('createdDateTime')
    if not identity or not rid or not timestamp:raise ValueError('Incomplete Copilot audit identity/date')
    when=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
    if when.tzinfo is None:when=when.replace(tzinfo=timezone.utc)
    host=event.get('AppHost') or raw.get('AppHost') or 'Unknown'
    agent=event.get('TargetAgentName') or raw.get('TargetAgentName') or event.get('AgentName') or raw.get('AgentName')
    if not agent and host=='Copilot Studio':
        app_id=event.get('AppIdentity') or raw.get('AppIdentity')
        if isinstance(app_id,dict):app_id=app_id.get('DisplayName') or app_id.get('AppId') or app_id.get('Id')
        if app_id:agent=str(app_id)
    resources=event.get('AccessedResources')
    return {'id':str(rid),'user':str(identity).strip().lower(),'date':when.astimezone(timezone.utc).isoformat(),
            'app':APP_NAMES.get(host,host),'raw_app':host,'license_type':event.get('LicenseType') or raw.get('LicenseType') or 'Unknown',
            'agent':str(agent) if agent else None,'resources':len(resources) if isinstance(resources,list) else None}


def aggregate(records,start,end):
    unique={}
    for row in records:
        when=datetime.fromisoformat(row['date'])
        if start<=when<end:
            if row['id'] in unique and unique[row['id']]!=row:raise ValueError('Conflicting duplicate audit record')
            unique[row['id']]=row
    records=sorted(unique.values(),key=lambda r:(r['date'],r['id']))
    users={};apps={};agents={};daily={}
    day=start.date()
    while day<end.date() or (day==end.date() and end.time()!=datetime.min.time()):
        daily[day.isoformat()]={'interactions':0,'users':set()};day+=timedelta(days=1)
    for row in records:
        uid=row['user'];app=row['app'];date=row['date'][:10]
        user=users.setdefault(uid,{'apps':Counter(),'days':set(),'licenses':set(),'agents':0,'last':row['date']})
        user['apps'][app]+=1;user['days'].add(date);user['licenses'].add(row['license_type']);user['last']=max(user['last'],row['date'])
        item=apps.setdefault(app,{'count':0,'users':set(),'raw':set()});item['count']+=1;item['users'].add(uid);item['raw'].add(row['raw_app'])
        daily[date]['interactions']+=1;daily[date]['users'].add(uid)
        if row['agent']:
            user['agents']+=1;agent=agents.setdefault(row['agent'],{'count':0,'users':set(),'apps':Counter()})
            agent['count']+=1;agent['users'].add(uid);agent['apps'][app]+=1
    top=[]
    for uid,r in users.items():
        top.append({'user':uid,'alias':usage_reporting._alias(uid),'provider':'Microsoft 365 Copilot','volume':sum(r['apps'].values()),
            'active_days':len(r['days']),'products':sorted(r['apps']),'surfaces':len(r['apps']),'spend':None,
            'agent_interactions':r['agents'],'license_types':sorted(r['licenses']),'last_activity':r['last'],
            'breakdown':[{'name':a,'volume':n,'spend':None,'basis':'Purview audit interactions'} for a,n in r['apps'].items()]})
    return {'mode':'live','period':'Copilot - month '+start.strftime('%Y-%m'),'source':'Microsoft Purview CopilotInteraction audit metadata',
        'range_start':start.isoformat(),'range_end':end.isoformat(),'collected_at':datetime.now(timezone.utc).isoformat(),
        'user_report_schema':2,'summary':{'copilot_active_users':len(users),'copilot_interactions':len(records),'agent_interactions':sum(r['agents'] for r in users.values()),'distinct_surfaces':len(apps)},
        'top_users':sorted(top,key=lambda r:r['volume'],reverse=True),'copilot_detail':records,
        'copilot_apps':[{'name':a,'interactions':r['count'],'users':len(r['users']),'average':r['count']/len(r['users']),'share':r['count']/len(records),'raw_apps':', '.join(sorted(r['raw']))} for a,r in sorted(apps.items(),key=lambda item:item[1]['count'],reverse=True)],
        'copilot_agents':[{'Agent':a,'Interactions':r['count'],'Users':len(r['users']),'Primary host app':r['apps'].most_common(1)[0][0]} for a,r in agents.items()],
        'copilot_daily':[{'Date':d,'Interactions':r['interactions'],'Active users':len(r['users'])} for d,r in sorted(daily.items())],
        'executive_sections':[],'caveats':['Counts are deduplicated audit records in the UTC reporting interval, including licensed and unlicensed usage returned by Purview. They are not Claude API requests.','License type is the value recorded on the event, not a current license inventory. Missing license or resource metadata remains unknown.','Only usage metadata is retained; prompts, responses, resource names and URLs are excluded.','A completed query reflects available audit data and tenant retention. Provider ingestion can lag; historical retention gaps cannot be reconstructed.']}


async def collect_step(client,token,start,end):
    period=start.strftime('%Y-%m')
    old=saved(period)
    if old and (datetime.now(timezone.utc)-datetime.fromisoformat(old['collected_at'])).total_seconds()<21600:return True
    with closing(database()) as db:
        row=db.execute('SELECT payload FROM purview_jobs WHERE period=?',(period,)).fetchone()
    job=json.loads(row[0]) if row else None
    headers={'Authorization':'Bearer '+token}
    if not job:
        status.update(stage='create audit query',period=period)
        response=await client.post(GRAPH+'/security/auditLog/queries',headers=headers,json={
            'displayName':'JO AI Monitor Copilot '+period,'filterStartDateTime':start.isoformat(),
            'filterEndDateTime':end.isoformat(),'operationFilters':['CopilotInteraction']})
        response.raise_for_status()
        job={'id':response.json()['id'],'start':start.isoformat(),'end':end.isoformat()}
        with closing(database()) as db:
            db.execute('INSERT OR REPLACE INTO purview_jobs VALUES (?,?)',(period,json.dumps(job)));db.commit()
        return False
    path='/security/auditLog/queries/'+quote(job['id'],safe='')
    status.update(stage='check audit query',period=period)
    response=await compliance_gate().get(client,GRAPH+path,headers=headers);response.raise_for_status()
    state=response.json()['status']
    if state in ('failed','cancelled'):
        with closing(database()) as db:db.execute('DELETE FROM purview_jobs WHERE period=?',(period,));db.commit()
        raise ValueError('Purview query failed; previous report retained')
    if state!='succeeded':return False
    status.update(stage='download audit records',period=period)
    raw=await graph_pages(client,token,GRAPH+path+'/records','/v1.0'+path+'/records')
    rows=[value for record in raw if (value:=normalize(record)) is not None]
    status.update(stage='aggregate audit records',period=period)
    data=aggregate(rows,datetime.fromisoformat(job['start']),datetime.fromisoformat(job['end']))
    with closing(database()) as db:
        db.execute('INSERT OR REPLACE INTO purview_reports VALUES (?,?)',(period,json.dumps(data)))
        db.execute('DELETE FROM purview_jobs WHERE period=?',(period,));db.commit()
    return True


def http_failure(exc):
    code=exc.response.status_code
    advice={401:'Check the configured Microsoft credentials.',
            403:'Check Graph application AuditLogsQuery.Read.All and tenant admin consent.',
            429:'Microsoft throttled the query; collection will retry.',
            404:'The saved audit query may have expired; inspect its Microsoft request ID.'}.get(code,'Collection will retry.')
    detail=error_detail(exc.response)
    return f"Purview {status.get('period','')} / {status.get('stage','collection')}: HTTP {code}. {advice} {detail} Previous reports retained."


async def run(token_provider):
    while True:
        try:
            complete=True
            async with httpx.AsyncClient(timeout=60,follow_redirects=False) as client:
                for start,end in months()[:max(1,min(12,int(os.getenv('M365_PURVIEW_MONTHS','3'))))]:
                    status.update(stage='authenticate',period=start.strftime('%Y-%m'))
                    if not await collect_step(client,await token_provider(),start,end):complete=False
            status.update(state='ready' if complete else 'syncing',message='Purview usage collection succeeded' if complete else 'Waiting for Purview audit queries')
        except httpx.HTTPStatusError as exc:
            message=http_failure(exc)
            status.update(state='error',message=message)
            logging.getLogger(__name__).warning('%s',message)
        except Exception as exc:
            message=f"Purview {status.get('period','')} / {status.get('stage','collection')} failed ({type(exc).__name__}); previous reports retained."
            status.update(state='error',message=message)
            logging.getLogger(__name__).warning('%s',message)
        status['next_refresh_at']=(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat()
        await asyncio.sleep(60)
