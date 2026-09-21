"""Dated Entra department snapshots for usage reports."""
import asyncio
import copy
import json
from app import database as db_backend
from contextlib import closing
from datetime import datetime, timedelta, timezone
import httpx
from app.purview_analytics import database, graph_pages, GRAPH

status={'state':'not_configured','message':'Department directory snapshots are not enabled'}


@db_backend.initialize_once
def init_directory_db():
    with closing(database()) as db:
        db.execute('CREATE TABLE IF NOT EXISTS usage_directory (collected_at TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        db.commit()


def init_table(db):
    init_directory_db()


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
        init_table(db);db.execute('INSERT INTO usage_directory VALUES (?,?) ON CONFLICT (collected_at) DO UPDATE SET payload=excluded.payload',(stamp,json.dumps(clean)));db.commit()


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
    stamp,people=current if current else (None,[])
    lookup={};departments={}
    # Normalize at report time so existing snapshots benefit without rewriting history.
    labels={}
    for person in people:
        label=' '.join(str(person.get('department') or '').split()) or '(no department)'
        labels.setdefault(label.casefold(),label)
    people=[dict(person,department=labels[(' '.join(str(person.get('department') or '').split()) or '(no department)').casefold()]) for person in people]
    for person in people:
        dep=person['department'];departments.setdefault(dep,{'Department':dep,'Directory accounts':0,'Users':0,'Volume':0,'Spend (USD)':0})['Directory accounts']+=1
        for key in {person['upn'],person['mail']} - {''}:
            # Ambiguous mail aliases must not silently assign a department.
            lookup[key]=person if key not in lookup else None
    active_ids={};matched_ids=set();mapped_ids=set();all_active=set()
    for user in result.get('top_users',[]):
        person=lookup.get(user['user'].lower());dep=person['department'] if person else '(unmapped)'
        user['department']=dep
        row=departments.setdefault(dep,{'Department':dep,'Directory accounts':0,'Users':0,'Volume':0,'Spend (USD)':0})
        active=(user.get('volume') or 0)>0 or user.get('activity_status')=='Active in period'
        if active:
            uid=person['id'] if person else user['user'].lower()
            active_ids.setdefault(dep,set()).add(uid);all_active.add(uid)
            if person:matched_ids.add(uid)
            if person and dep!='(no department)':mapped_ids.add(uid)
        row['Users']=len(active_ids.get(dep,set()))
        if user.get('volume') is None:row['Volume']=None
        elif row['Volume'] is not None:row['Volume']+=user['volume']
        if user.get('spend') is None:row['Spend (USD)']=None
        elif row['Spend (USD)'] is not None:row['Spend (USD)']+=user['spend']
    # Directory accounts are not a verified employee population.
    for row in departments.values():
        row['Headcount']=None;row['Adoption']=None
    result['department_adoption']=sorted(departments.values(),key=lambda r:r['Department'].casefold())
    result['department_usage']=sorted(
        [r for r in departments.values() if r['Users'] or r['Volume'] or r['Spend (USD)']],
        key=lambda r:(-(r['Volume'] or 0),-r['Users'],r['Department'].casefold()))
    result['directory_as_of']=stamp
    result['directory_quality']={
        'enabled_accounts':len(people),
        'missing_department':sum(p['department']=='(no department)' for p in people),
        'guest_style_accounts':sum('#ext#' in p['upn'].lower() for p in people),
        'active_accounts':len(all_active),'matched_active_accounts':len(matched_ids),
        'department_mapped_active_accounts':len(mapped_ids),
        'unmapped_active_accounts':len(all_active-matched_ids),
        'employee_population_verified':False}
    result['report_basis']='Recorded account activity; employee adoption is not available because an employee roster has not been verified.'
    result.setdefault('caveats',[]).append(result['report_basis'])
    result['caveats'].append('Department totals cover available account-attributed records; organization totals may also include activity outside user detail. Department totals retain all usage from those records, including accounts with missing departments or no directory match. Only departments with activity or spend appear in the leadership summary; the full directory counts are in Directory Coverage. Accounts are not excluded based on their names.')
    if stamp:
        result['caveats'].append('Department mapping was observed '+stamp+'. Names are grouped ignoring capitalization and whitespace; abbreviations remain separate. This snapshot includes guest, service and test accounts and is not historical employee headcount.')
    else:
        result['caveats'].append('No directory snapshot is available. Department attribution is unavailable. '+status['message'])
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
