"""Cached, read-only Claude Enterprise analytics collection."""
from asyncio import sleep
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import httpx
from app import usage_reporting
from app.compliance_http import compliance_gate

status = {"state": "pending", "message": "Claude analytics waiting for first collection"}

def months(now=None):
    now=now or datetime.now(timezone.utc)
    start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    result=[]
    for _ in range(12):
        if start < datetime(2026,1,1,tzinfo=timezone.utc) or (now-start).days>=365: break
        end=(start.replace(day=28)+timedelta(days=4)).replace(day=1)
        result.append((start,min(end,now)))
        start=(start-timedelta(days=1)).replace(day=1)
    return result

def database():
    db=sqlite3.connect(usage_reporting.DB_PATH,timeout=30)
    db.execute('CREATE TABLE IF NOT EXISTS claude_analytics (period TEXT PRIMARY KEY, payload TEXT NOT NULL, collected_at TEXT NOT NULL)')
    return db

def saved(period=''):
    with closing(database()) as db:
        row=db.execute('SELECT payload FROM claude_analytics WHERE period=?',(period,)).fetchone() if period else db.execute('SELECT payload FROM claude_analytics ORDER BY period DESC LIMIT 1').fetchone()
    return normalize_cached(json.loads(row[0])) if row else None

def normalize_cached(data):
    """v0.10.2 stored API cents as dollars; repair that known cache schema once."""
    data['caveats']=[c for c in data.get('caveats',[]) if not c.startswith('Copilot usage is not connected.')]
    for section in data.get('executive_sections',[]):
        section['rows']=[r for r in section.get('rows',[]) if not (r and r[0]=='Copilot usage')]
    if data.get('cost_unit') == 'USD': return data
    def dollars(value): return float(Decimal(str(value))/Decimal('100'))
    summary=data.get('summary',{})
    if 'claude_usage_spend' in summary: summary['claude_usage_spend']=dollars(summary['claude_usage_spend'])
    for key in ('claude_products','claude_models'):
        for row in data.get(key,[]):
            if 'spend' in row:row['spend']=dollars(row['spend'])
    for section in data.get('executive_sections',[]):
        for row in section.get('rows',[]):
            if row and row[0]=='Claude usage spend USD':row[1]=dollars(row[1])
            elif section.get('name')=='Claude Product & Model' and len(row)>2 and isinstance(row[2],(int,float)):row[2]=dollars(row[2])
    data['cost_unit']='USD'
    return data

def periods():
    with closing(database()) as db:
        return [{"period":r[0]} for r in db.execute('SELECT period FROM claude_analytics ORDER BY period DESC')]

async def pages(client, endpoint, params):
    result=[]; seen=set()
    for _ in range(1000):
        response=await compliance_gate().get(client, endpoint, params=params)
        response.raise_for_status()
        body=response.json()
        if not isinstance(body.get('data'),list): raise ValueError('Invalid analytics response')
        result.extend(body['data'])
        if not body.get('has_more'): return result
        cursor=body.get('next_page')
        if not isinstance(cursor,str) or not cursor or cursor in seen: raise ValueError('Invalid analytics pagination')
        seen.add(cursor);params={**params,'page':cursor}
    raise ValueError('Analytics pagination exceeded safety limit')

def total(buckets, field):
    value=Decimal('0')
    for bucket in buckets:
        for row in bucket['results']:
            if field=='amount' and row.get('currency','USD').upper()!='USD': raise ValueError('Unexpected analytics currency')
            amount=Decimal(str(row[field]))
            if not amount.is_finite(): raise ValueError('Invalid analytics number')
            value+=amount
    return float(value / Decimal("100") if field == "amount" else value)

def grouped(usage,cost,dimension):
    values={}
    for buckets,field,dest in [(usage,'requests','requests'),(cost,'amount','spend')]:
        for bucket in buckets:
            for row in bucket['results']:
                name=row.get(dimension) or 'Unattributed'
                item=values.setdefault(name,{'name':name,'requests':0,'spend':0})
                item[dest]+=total([{'results':[row]}],field)
    return list(values.values())

def user_detail(usage,cost):
    """Join independent usage and cost aggregates; never count cost rows as requests."""
    values={}
    for rows,kind in ((usage,'usage'),(cost,'cost')):
        for row in rows:
            actor=row.get('actor') or {}
            uid=actor.get('user_id')
            if not uid: continue
            key=(uid,row.get('product') or 'Unattributed',row.get('model') or 'Unattributed')
            item=values.setdefault(key,{'user':actor.get('email') or actor.get('name') or uid,
                'alias':usage_reporting._alias(uid),'product':key[1],'model':key[2],
                'requests':0,'prompt_tokens':0,'completion_tokens':0,'spend':0,'gross_spend':None})
            if kind=='usage':
                item['requests']+=int(row.get('requests',0))
                item['prompt_tokens']+=sum(int(row.get(k,0)) for k in ('uncached_input_tokens','cache_read_input_tokens'))+sum(int(v) for v in (row.get('cache_creation') or {}).values())
                item['completion_tokens']+=int(row.get('output_tokens',0))
            else:
                item['spend']+=total([{'results':[row]}],'amount')
                if row.get('list_amount') is not None:
                    item['gross_spend']=(item['gross_spend'] or 0)+total([{'results':[{**row,'amount':row['list_amount']}]}],'amount')
    return list(values.values())


def user_rows(details):
    users={}
    for row in details:
        item=users.setdefault(row['alias'],{'user':row['user'],'alias':row['alias'],
            'provider':'Claude Enterprise','volume':0,'tokens':0,'spend':0,'active_days':None,
            'products':[],'models':[],'breakdown':[]})
        item['volume']+=row['requests'];item['tokens']+=row['prompt_tokens']+row['completion_tokens'];item['spend']+=row['spend']
        if row['model'] not in item['models']:item['models'].append(row['model'])
        if row['product'] not in item['products']:
            item['products'].append(row['product']);item['breakdown'].append({'name':row['product'],'volume':0,'spend':0,'basis':'Provider reported'})
        part=next(p for p in item['breakdown'] if p['name']==row['product'])
        part['volume']+=row['requests'];part['spend']+=row['spend']
    return sorted((r for r in users.values() if r['volume'] or r['tokens'] or r['spend']),key=lambda r:r['volume'],reverse=True)

async def collect(client,start,end):
    params={'starting_at':start.isoformat(),'ending_at':end.isoformat(),'bucket_width':'1d','limit':31}
    fetched={}
    for dimension in ['', 'product', 'model']:
        for kind in ['usage','cost']:
            query={**params,**({'group_by[]':dimension} if dimension else {})}
            fetched[kind,dimension]=await pages(client,f'/v1/organizations/analytics/{kind}_report',query)
    users=await pages(client,'/v1/organizations/analytics/user_usage_report',{'starting_at':start.isoformat(),'ending_at':end.isoformat(),'limit':1000,'group_by[]':['product','model']})
    costs=await pages(client,'/v1/organizations/analytics/user_cost_report',{'starting_at':start.isoformat(),'ending_at':end.isoformat(),'limit':1000,'group_by[]':['product','model']})
    details=user_detail(users,costs)
    active_users=len({r['actor']['user_id'] for r in users if r.get('actor',{}).get('user_id') and float(r.get('requests',0))>0})
    products=grouped(fetched['usage','product'],fetched['cost','product'],'product')
    models=grouped(fetched['usage','model'],fetched['cost','model'],'model')
    daily=[{'Date':b['starting_at'][:10],'Requests':total([b],'requests')} for b in fetched['usage','']]
    tokens=sum(int(r.get(k,0)) for b in fetched['usage',''] for r in b['results'] for k in ('uncached_input_tokens','cache_read_input_tokens','output_tokens'))+sum(int(v) for b in fetched['usage',''] for r in b['results'] for v in (r.get('cache_creation') or {}).values())
    sections=[{'name':'Claude Product & Model','rows':[['Product','Requests','Spend']]+[[p['name'],p['requests'],p['spend']] for p in products]+[[],['Model','Requests','Spend']]+[[p['name'],p['requests'],p['spend']] for p in models]}, {'name':'Claude Daily Trend','rows':[['Date','Requests']]+[[r['Date'],r['Requests']] for r in daily]}]
    sections.insert(0,{'name':'AI Usage Summary','rows':[['Measure','Value'],['Claude active users',active_users],['Claude requests',total(fetched['usage',''],'requests')],['Claude tokens',tokens],['Claude usage spend USD',total(fetched['cost',''],'amount')],['Collected at',datetime.now(timezone.utc).isoformat()]]})
    return {'cost_unit':'USD','period':start.strftime('%Y-%m'),'mode':'live','source':'Claude Enterprise Analytics API','collected_at':datetime.now(timezone.utc).isoformat(),'range_start':start.isoformat(),'range_end':end.isoformat(), 'summary':{'claude_active_users':active_users,'claude_tokens':tokens,'claude_requests':total(fetched['usage',''],'requests'),'claude_usage_spend':total(fetched['cost',''],'amount')},'licensing':{},'claude_products':products,'claude_models':models,'claude_daily':daily,'copilot_apps':[],'top_users':user_rows(details),'claude_detail':details,'user_report_schema':2,'executive_sections':sections,'caveats':['Spend is reported USD usage cost, excluding seat fees.','User detail includes seat-attributed traffic; organization totals can additionally include API-key or automation traffic. Prompt tokens include uncached input, cache reads, and cache creation.','Product/model breakdowns are limited by the provider to the top 100 groups per day; headline totals use ungrouped results.','Current month is month-to-date; provider analytics may lag recent activity.']}

async def run(key,base_url):
    while True:
        status.update(state='syncing',message='Collecting Claude usage and spend')
        try:
            async with httpx.AsyncClient(base_url=base_url,headers={'x-api-key':key,'anthropic-version':'2023-06-01'},timeout=60,follow_redirects=False) as client:
                for index,(start,end) in enumerate(months()):
                    period=start.strftime('%Y-%m');previous=saved(period)
                    if previous and previous.get('user_report_schema') == 2 and (datetime.now(timezone.utc)-datetime.fromisoformat(previous['collected_at'])).total_seconds()<(86400 if index>1 else 3600): continue
                    data=await collect(client,start,end)
                    with closing(database()) as db:
                        db.execute('INSERT OR REPLACE INTO claude_analytics VALUES (?,?,?)',(period,json.dumps(data),data['collected_at']));db.commit()
            status.update(state='ready',message='Claude analytics collection succeeded')
        except httpx.HTTPStatusError as exc:
            code=exc.response.status_code
            status.update(state='error',message=f'Claude analytics HTTP {code}. '+('Check read:analytics permission on the configured key.' if code in (401,403) else 'Collection will retry; previous results are retained.'))
        except Exception:
            status.update(state='error',message='Claude analytics collection failed; previous results retained. Collection will retry.')
        status["next_refresh_at"]=(datetime.now(timezone.utc)+timedelta(seconds=3600)).isoformat()
        await sleep(3600)
