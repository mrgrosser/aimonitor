"""Read-only reconciliation of a supplied reference workbook; no identities printed."""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from openpyxl import load_workbook
from app.usage_reporting import parse_usage_file
from app.purview_analytics import aggregate

def check(path):
    data,_=parse_usage_file(path.read_bytes(),path.name)
    book=load_workbook(path,read_only=True,data_only=True)
    def records(name,header):
        rows=list(book[name].values)
        start=next(i for i,r in enumerate(rows) if r[0]==header)
        out=[]
        for r in rows[start+1:]:
            if str(r[0]).lower() in ('total','grand total') or str(r[0]).lower().startswith('total '):break
            if r[0] is not None:out.append(dict(zip(rows[start],r)))
        return out
    detail=records('Copilot Detail','User')
    start=datetime.strptime(data['period'],'%B %Y').replace(tzinfo=timezone.utc)
    end=start.replace(year=start.year+1,month=1) if start.month==12 else start.replace(month=start.month+1)
    normalized=[{'id':str(i),'user':r['User'].lower(),'date':r['Date'].replace(tzinfo=timezone.utc).isoformat(),
        'app':r['App'],'raw_app':r['Raw AppHost'],'license_type':r['License type'] or 'Unknown','agent':r['Agent'],'resources':r['Resources accessed']} for i,r in enumerate(detail)]
    calendar=aggregate(normalized,start,end)
    outside=sum(not(start<=datetime.fromisoformat(r['date'])<end) for r in normalized)
    print('Date reconciliation:',outside,'source rows fall outside the labeled calendar month;',calendar['summary']['copilot_interactions'],'interactions inside it.')
    # Reconcile the workbook's actual date coverage separately from calendar-month semantics.
    source_end=max(datetime.fromisoformat(r['date']) for r in normalized)+timedelta(days=1)
    computed=aggregate(normalized,start,source_end)
    for key in ('copilot_active_users','copilot_interactions','agent_interactions','distinct_surfaces'):
        assert computed['summary'][key]==data['summary'][key],key
    for expected in records('Copilot App Totals','App'):
        row=next(r for r in computed['copilot_apps'] if r['name']==expected['App'])
        assert (row['interactions'],row['users'])==(expected['Interactions'],expected['Users'])
    expected_users=records('Copilot User by App','User')
    for expected in expected_users:
        row=next(r for r in computed['top_users'] if r['user']==expected['User'].lower())
        assert (row['volume'],row['active_days'],row['agent_interactions'])==(expected['Total'],expected['Active days'],expected['Agent interactions'])
    for expected in records('Copilot Daily Trend','Date'):
        row=next(r for r in computed['copilot_daily'] if r['Date']==expected['Date'].date().isoformat())
        assert (row['Interactions'],row['Active users'])==(expected['Interactions'],expected['Active users'])
    for expected in records('Copilot Agents','Agent'):
        row=next(r for r in computed['copilot_agents'] if r['Agent']==expected['Agent'])
        assert (row['Interactions'],row['Users'])==(expected['Interactions'],expected['Users'])
    book.close()
    print('PASS: all workbook sheets parse; Copilot summary, user, app, agent and daily aggregations reconcile to reference detail.')

if __name__=='__main__':check(Path(sys.argv[1]))
