"""Dated Entra department snapshots for usage reports."""
import asyncio
import copy
import json
from contextlib import closing
from datetime import datetime, timedelta, timezone
import httpx
from app.purview_analytics import database, graph_pages, GRAPH

status={'state':'not_configured','message':'Department directory snapshots are not enabled'}


def init_table(db):
    db.execute('CREATE TABLE IF NOT EXISTS usage_directory (collected_at TEXT PRIMARY KEY,payload TEXT NOT NULL)')


def save(rows,stamp):
    clean=[];seen=set()
    for row in rows:
        if row.get('accountEnabled') is not True:continue
        uid=row['id']
        if uid in seen:continue
        seen.add(uid)
        clean.append({'id':uid,'upn':str(row.get('userPrincipalName') or '').lower(),
            'mail':str(row.get('mail') or '').lower(),'department':row.get('department') or '(no department)'})
    with closing(database()) as db:
        init_table(db);db.execute('INSERT OR REPLACE INTO usage_directory VALUES (?,?)',(stamp,json.dumps(clean)));db.commit()


def snapshot(end):
    with closing(database()) as db:
        init_table(db)
        # Prefer the last observed directory at/before the report end. If no such
        # snapshot exists, use the earliest later observation and label its date.
        row=db.execute('SELECT collected_at,payload FROM usage_directory WHERE collected_at<=? ORDER BY collected_at DESC LIMIT 1',(end,)).fetchone()
        if not row:row=db.execute('SELECT collected_at,payload FROM usage_directory ORDER BY collected_at LIMIT 1').fetchone()
    return (row[0],json.loads(row[1])) if row else None


def enrich(data):
    if not data.get('user_report_schema'):return data
    result=copy.deepcopy(data)
    current=snapshot(data.get('range_end') or data.get('collected_at') or '')
    if not current:
        result.setdefault('caveats',[]).append('Department adoption needs a dated directory snapshot. '+status['message'])
        return result
    stamp,people=current;lookup={};departments={}
    for person in people:
        dep=person['department'];departments.setdefault(dep,{'Department':dep,'Headcount':0,'Users':0,'Volume':0,'Spend (USD)':0})['Headcount']+=1
        for key in {person['upn'],person['mail']} - {''}:
            # Ambiguous mail aliases must not silently assign a department.
            lookup[key]=person if key not in lookup else None
    active_ids={}
    for user in result.get('top_users',[]):
        person=lookup.get(user['user'].lower());dep=person['department'] if person else '(unmapped)'
        user['department']=dep
        row=departments.setdefault(dep,{'Department':dep,'Headcount':None,'Users':0,'Volume':0,'Spend (USD)':0})
        active=(user.get('volume') or 0)>0 or user.get('activity_status')=='Active in period'
        if active:active_ids.setdefault(dep,set()).add(person['id'] if person else user['user'].lower())
        row['Users']=len(active_ids.get(dep,set()))
        if user.get('volume') is None:row['Volume']=None
        elif row['Volume'] is not None:row['Volume']+=user['volume']
        if user.get('spend') is None:row['Spend (USD)']=None
        elif row['Spend (USD)'] is not None:row['Spend (USD)']+=user['spend']
    for row in departments.values():row['Adoption']=row['Users']/row['Headcount'] if row['Headcount'] else None
    result['department_adoption']=sorted(departments.values(),key=lambda r:r['Department'])
    result['directory_as_of']=stamp
    result.setdefault('caveats',[]).append('Department mapping and enabled-account headcount were observed '+stamp+'. This is a directory snapshot, not historical staffing proof. Unmatched accounts have no adoption denominator.')
    return result


async def run(token_provider):
    while True:
        try:
            async with httpx.AsyncClient(timeout=60,follow_redirects=False) as client:
                rows=await graph_pages(client,await token_provider(),GRAPH+'/users?$select=id,userPrincipalName,mail,department,accountEnabled&$top=999','/v1.0/users')
            save(rows,datetime.now(timezone.utc).isoformat())
            status.update(state='ready',message='Department directory snapshot collected')
        except httpx.HTTPStatusError as exc:
            status.update(state='error',message=f'Directory HTTP {exc.response.status_code}. Check User.Read.All application consent.')
        except Exception as exc:
            status.update(state='error',message='Directory snapshot failed ('+type(exc).__name__+'); previous snapshots retained.')
        await asyncio.sleep(86400)
