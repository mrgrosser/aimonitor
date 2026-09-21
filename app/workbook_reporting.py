"""Workbook-shaped sections built only after report identities are authorized."""


def section(name,headers,rows,formats=None):
    result={'name':name,'rows':[headers,*rows]}
    if formats:result['formats']=[['General']*len(headers)]+[formats]*len(rows)
    return result


def sections(data):
    users=data.get('top_users',[]);result=[]
    if data.get('claude_detail') is not None:
        products=sorted({p for u in users for p in u.get('products',[])})
        result.append(section('Claude User by Product',['User','Department',*products,'Total requests','Products used','Models used','Net spend (USD)'],[
            [u['user'],u.get('department','Not supplied'),*[next((p['volume'] for p in u.get('breakdown',[]) if p['name']==name),0) for name in products],u['volume'],len(u.get('products',[])),len(u.get('models',[])),u['spend']] for u in users]))
        result.append(section('Claude Detail',['User','Product','Model','Requests','Prompt tokens','Completion tokens','Net spend (USD)','Gross spend (USD)'],[
            [r['user'],r['product'],r['model'],r['requests'],r['prompt_tokens'],r['completion_tokens'],r['spend'],r['gross_spend']] for r in data['claude_detail']],['General','General','General','#,##0','#,##0','#,##0','$#,##0.00','$#,##0.00']))
        mix=[]
        for label,key in [('Product','claude_products'),('Model','claude_models')]:
            values=data.get(key,[]);requests=sum(r['requests'] for r in values);spend=sum(r['spend'] for r in values)
            if mix:mix.append([])
            mix.append([label,'Requests','Spend (USD)','Share of grouped requests','Share of grouped spend'])
            mix.extend([[r['name'],r['requests'],r['spend'],r['requests']/requests if requests else None,r['spend']/spend if spend else None] for r in values])
        result.append({'name':'Claude Product & Model','rows':mix,'formats':[['General','#,##0','$#,##0.00','0.0%','0.0%'] for _ in mix]})
        result.append(section('Claude users by spend',['User','Requests','Spend (USD)','Share of seat-attributed spend'],[
            [u['user'],u['volume'],u['spend'],u['spend']/sum(r['spend'] for r in users) if sum(r['spend'] for r in users) else None] for u in sorted(users,key=lambda r:r['spend'],reverse=True)]))
    if data.get('copilot_detail') is not None:
        apps=[r['name'] for r in data.get('copilot_apps',[])]
        result.append(section('Copilot User by App',['User','Department',*apps,'Total','Apps used','Active days','Agent interactions'],[
            [u['user'],u.get('department','Not supplied'),*[next((p['volume'] for p in u.get('breakdown',[]) if p['name']==name),0) for name in apps],u['volume'],len(u.get('products',[])),u['active_days'],u['agent_interactions']] for u in users]))
        result.append(section('Copilot App Totals',['App','Interactions','Users','Avg per user','Share of interactions','Raw AppHost value(s)'],[
            [r['name'],r['interactions'],r['users'],r['average'],r['share'],r['raw_apps']] for r in data['copilot_apps']],['General','#,##0','#,##0','0.00','0.0%','General']))
        result.append(section('Copilot Agents',['Agent','Interactions','Users','Primary host app'],[
            [r['Agent'],r['Interactions'],r['Users'],r['Primary host app']] for r in data['copilot_agents']]))
        result.append(section('Copilot Daily Trend',['Date','Interactions','Active users'],[
            [r['Date'],r['Interactions'],r['Active users']] for r in data['copilot_daily']]))
        result.append(section('Copilot Detail',['User','Date (UTC)','App','Raw AppHost','License type','Agent','Resources accessed'],[
            [r['user'],r['date'],r['app'],r['raw_app'],r['license_type'],r['agent'],r['resources']] for r in data['copilot_detail']]))
    if data.get('licensed_users') is not None:
        result.append(section('Copilot licensed users',['User','License report as of','Report membership','Last reported activity'],[
            [r['user'],data.get('license_report_as_of'),r.get('license_status','Included in licensed-user report'),r.get('last_activity')] for r in data['licensed_users']]))
    if data.get('department_usage') is not None:
        unit='Interactions' if 'copilot_interactions' in data.get('summary',{}) else 'Requests' if 'claude_requests' in data.get('summary',{}) else 'Volume (not supplied)'
        spend='claude_requests' in data.get('summary',{})
        result.append(section('Department Summary',['Department','Active accounts',unit]+(['Spend (USD)'] if spend else []),[
            [r['Department'],r['Users'],r['Volume']]+([r['Spend (USD)']] if spend else []) for r in data['department_usage']],
            ['General','#,##0','#,##0']+(['$#,##0.00'] if spend else [])))
        q=data['directory_quality']
        result.append(section('Directory Quality',['Measure','Value'],[
            ['Directory snapshot',data.get('directory_as_of') or 'Unavailable'],
            ['Enabled directory accounts',q['enabled_accounts'] if data.get('directory_as_of') else None],
            ['Accounts missing a department',q['missing_department'] if data.get('directory_as_of') else None],
            ['Guest-style UPNs (subset of enabled accounts)',q['guest_style_accounts'] if data.get('directory_as_of') else None],
            ['Employee population','Not verified'],
            ['Account classification','Guest-style UPNs are identified by #EXT#. Other accounts are unclassified; names alone do not establish employee or service-account status.']]))
        result.append(section('Directory Coverage',['Department','Enabled directory accounts','Active accounts'],[
            [r['Department'],r['Directory accounts'],r['Users']] for r in data['department_adoption']]))
    names={s['name'] for s in result}
    result=[s for s in data.get('executive_sections',[]) if s['name'] not in names]+result
    if not any(s['name']=='AI Usage Summary' for s in result):
        result.insert(0,section('AI Usage Summary',['Measure','Value'],[[k,v] for k,v in data.get('summary',{}).items()]))
    result.append(section('Notes & Caveats',['Notes'],[[c] for c in data.get('caveats',[])]))
    if data.get('report_basis'):
        from app.usage_reporting import summary_metrics, directory_quality_rows
        result.insert(0,section('Leadership Summary',['Measure','Value'],summary_metrics(data)[1:]+directory_quality_rows(data)[1:]))
    return result
