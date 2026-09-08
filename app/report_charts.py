"""Small, source-labelled executive charts shared by report formats."""
import html
import math
from datetime import datetime

COLORS=["#3865e8","#23988d","#d2993b","#9066b5","#708398","#b4bfcd"]

def series(data):
    def positive(rows,label,value):
        result=[]
        for row in rows:
            v=row.get(value)
            if isinstance(v,(int,float)) and math.isfinite(v) and v>0: result.append((str(row.get(label) or "Unknown"),float(v)))
        return sorted(result,key=lambda r:r[1],reverse=True)
    apps=positive(data.get("copilot_apps",[]),"name","interactions")
    if len(apps)>6: apps=apps[:5]+[("Other apps",sum(v for _,v in apps[5:]))]
    spend=positive(data.get("claude_products",[]),"name","spend")
    daily=[]
    for row in (data.get("copilot_daily") or [{"Date":r["Date"],"Interactions":r["Requests"]} for r in data.get("claude_daily",[])] or [{"Date":r["Date"],"Interactions":r["Active users"]} for r in data.get("copilot_user_trend",[])]):
        try:
            day=datetime.fromisoformat(str(row["Date"]).replace("Z","+00:00")).date().isoformat()
            value=float(row["Interactions"])
            if math.isfinite(value) and value>=0: daily.append((day,value))
        except (ValueError,TypeError,KeyError): continue
    return apps,sorted(daily),spend


def charts_html(data):
    apps,daily,spend=series(data); cards=[]
    def card(title,body,note):
        cards.append(f'<section class="report-chart"><h3>{title}</h3>{body}<p>{note}</p></section>')
    if apps:
        total=sum(v for _,v in apps);offset=0;arcs=[];legend=[]
        for i,(name,value) in enumerate(apps):
            percent=value/total*100;color=COLORS[i%len(COLORS)]
            arcs.append(f'<circle cx="90" cy="90" r="62" fill="none" stroke="{color}" stroke-width="25" pathLength="100" stroke-dasharray="{percent} {100-percent}" stroke-dashoffset="{-offset}" transform="rotate(-90 90 90)"><title>{html.escape(name)}: {value:,.0f} ({percent:.1f}%)</title></circle>');offset+=percent
            legend.append(f'<li><span style="color:{color}">●</span> {html.escape(name)} <b>{percent:.1f}%</b></li>')
        card("Copilot app mix",'<div class="chart-mix"><svg viewBox="0 0 180 180" role="img" aria-label="Copilot interactions by application">'+''.join(arcs)+f'<text x="90" y="94" text-anchor="middle" fill="currentColor" font-size="18">{total:,.0f}</text></svg><ul>'+''.join(legend)+'</ul></div>',"Share of recorded Copilot interactions")
    if daily:
        maximum=max(1,max(v for _,v in daily));coords=[]
        first=datetime.fromisoformat(daily[0][0]);last=datetime.fromisoformat(daily[-1][0]);span=max(1,(last-first).days)
        for day,value in daily:
            x=45+(datetime.fromisoformat(day)-first).days/span*395;y=155-value/maximum*120;coords.append((x,y,day,value))
        points=' '.join(f'{x:.1f},{y:.1f}' for x,y,_,_ in coords)
        dots=''.join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#3865e8"><title>{day}: {value:,.0f}</title></circle>' for x,y,day,value in coords)
        card("Claude daily requests" if data.get("claude_daily") else "Copilot daily active users" if data.get("copilot_user_trend") else "Copilot daily activity",f'<svg viewBox="0 0 470 195" role="img" aria-label="Daily activity"><path d="M45 30 V155 H445" fill="none" stroke="#a0acb8"/><text x="4" y="38" fill="currentColor" font-size="11">{maximum:,.0f}</text><text x="25" y="157" fill="currentColor" font-size="11">0</text><polyline points="{points}" fill="none" stroke="#3865e8" stroke-width="2.5"/>{dots}<text x="45" y="181" fill="currentColor" font-size="11">{daily[0][0]}</text><text x="440" y="181" text-anchor="end" fill="currentColor" font-size="11">{daily[-1][0]}</text></svg>',"Activity by UTC date; only reported dates are shown")
    adoption=[r for r in data.get("copilot_adoption",[]) if r.get("users") is not None]
    if adoption:
        maximum=max(1,max(r['users'] for r in adoption))
        bars=''.join(f'<div class="chart-bar"><span>{html.escape(r["name"])}</span><div><i style="width:{r["users"]/maximum*100:.2f}%"></i></div><b>{r["users"]:,}</b></div>' for r in adoption)
        card("Copilot active users by app",bars,"Users can appear in multiple apps; counts are not additive")
    if spend:
        maximum=max(v for _,v in spend)
        bars=''.join(f'<div class="chart-bar"><span>{html.escape(name)}</span><div><i style="width:{value/maximum*100:.2f}%"></i></div><b>${value:,.2f}</b></div>' for name,value in spend)
        card("Claude spend by product",bars,"Reported usage spend in USD; seat fees excluded")
    return '<div class="report-charts">'+''.join(cards)+'</div>' if cards else ''


def pdf_charts(data):
    from reportlab.graphics.shapes import Drawing,String,Line,Rect,PolyLine,Circle
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.lib.colors import HexColor
    apps,daily,spend=series(data); drawings=[]
    ink=HexColor("#243F65");blue=HexColor(COLORS[0])
    if apps:
        d=Drawing(450,185);d.add(String(0,170,"Copilot app mix - interactions",fontSize=12,fill=ink))
        pie=Pie();pie.x=5;pie.y=10;pie.width=140;pie.height=140;pie.data=[v for _,v in apps];pie.labels=[]
        total=sum(pie.data)
        for i,(name,value) in enumerate(apps):
            color=HexColor(COLORS[i]);pie.slices[i].fillColor=color
            d.add(Rect(170,140-i*20,9,9,fillColor=color,strokeColor=None))
            d.add(String(186,140-i*20,f"{name} ({value/total*100:.1f}%)",fontSize=9,fill=ink))
        d.add(pie);drawings.append(d)
    if daily:
        d=Drawing(450,180);d.add(String(0,164,("Claude daily requests (UTC)" if data.get("claude_daily") else "Copilot daily active users" if data.get("copilot_user_trend") else "Copilot daily interactions (UTC)"),fontSize=12,fill=ink))
        maximum=max(1,max(v for _,v in daily));first=datetime.fromisoformat(daily[0][0]);span=max(1,(datetime.fromisoformat(daily[-1][0])-first).days)
        points=[]
        for day,value in daily:points.extend([45+(datetime.fromisoformat(day)-first).days/span*385,30+value/maximum*110])
        d.add(Line(45,30,430,30,strokeColor=ink));d.add(Line(45,30,45,140,strokeColor=ink))
        if len(points)>=4:d.add(PolyLine(points,strokeColor=blue,strokeWidth=2))
        for x,y in zip(points[::2],points[1::2]):d.add(Circle(x,y,2,fillColor=blue,strokeColor=None))
        d.add(String(0,133,f"{maximum:,.0f}",fontSize=8,fill=ink));d.add(String(28,28,"0",fontSize=8,fill=ink))
        d.add(String(45,12,daily[0][0],fontSize=8,fill=ink));d.add(String(365,12,daily[-1][0],fontSize=8,fill=ink));drawings.append(d)
    if spend:
        d=Drawing(450,40+len(spend)*25);top=d.height-18;d.add(String(0,top,"Claude usage spend by product (USD; excludes seats)",fontSize=12,fill=ink));maximum=max(v for _,v in spend)
        for i,(name,value) in enumerate(spend):
            y=top-27-i*25;d.add(String(0,y,name,fontSize=9,fill=ink));d.add(Rect(125,y-2,235*value/maximum,12,fillColor=blue,strokeColor=None));d.add(String(370,y,f"${value:,.2f}",fontSize=9,fill=ink))
        drawings.append(d)
    return drawings


CHART_CSS=""".report-charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin:22px 0}.report-chart{border:1px solid #dce3ec;border-radius:10px;padding:18px;min-width:0;break-inside:avoid}.report-chart h3{font-size:15px;margin:0 0 16px}.report-chart p{font-size:12px;color:#758194}.report-chart svg{width:100%;max-height:210px}.chart-mix{display:flex;align-items:center;gap:12px}.chart-mix svg{width:45%;flex-shrink:0}.chart-mix ul{list-style:none;padding:0;font-size:11px;flex:1}.chart-mix li{margin:8px 0}.chart-mix b{white-space:nowrap}.chart-bar{display:grid;grid-template-columns:minmax(70px,1fr) 1.3fr auto;gap:8px;align-items:center;margin:14px 0;font-size:12px}.chart-bar>div{background:#e8edf5;height:10px;border-radius:4px;overflow:hidden}.chart-bar i{display:block;height:100%;background:#3865e8}.chart-bar b{font-variant-numeric:tabular-nums}@media print{.report-charts{display:block}.report-chart{margin:12px 0}.report-chart svg{max-width:500px}}"""


def excel_charts(workbook):
    from openpyxl.chart import DoughnutChart,LineChart,BarChart,Reference
    for name,header,col,title,kind in [("Copilot users by app","App",2,"Copilot active users by app","users"),("Copilot active user trend","Date",2,"Copilot daily active users","line"),("Claude Daily Trend","Date",2,"Daily Claude requests (UTC)","line"),("Copilot App Totals","App",2,"Copilot app mix (interactions)","pie"),("Copilot Daily Trend","Date",2,"Daily Copilot interactions (UTC)","line"),("Claude Product & Model","Product",3,"Claude usage spend by product (USD)","bar")]:
        if name not in workbook:continue
        sheet=workbook[name]
        start=next((row[0].row for row in sheet if row[0].value==header),None)
        if start is None:continue
        end=start
        while end<sheet.max_row:
            label=sheet.cell(end+1,1).value;value=sheet.cell(end+1,col).value
            if not label or str(label).lower()=="total" or not isinstance(value,(int,float)):break
            end+=1
        if end==start:continue
        chart=DoughnutChart() if kind=="pie" else LineChart() if kind=="line" else BarChart()
        chart.title=title;chart.style=10;chart.width=23;chart.height=12
        chart.add_data(Reference(sheet,min_col=col,min_row=start,max_row=end),titles_from_data=True)
        chart.set_categories(Reference(sheet,min_col=1,min_row=start+1,max_row=end))
        if kind=="pie":chart.holeSize=65
        else:
            chart.legend=None
            chart.y_axis.title="USD" if kind=="bar" else "Requests" if name=="Claude Daily Trend" else "Active users" if name.startswith("Copilot ") and name not in {"Copilot App Totals","Copilot Daily Trend"} else "Interactions"
        sheet.add_chart(chart,f"A{sheet.max_row+3}")
