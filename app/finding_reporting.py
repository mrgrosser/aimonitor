import csv
import io
import json
import os
import smtplib
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.governance import DB_PATH

REPORT_ROLES = {x.strip() for x in os.getenv("NAMED_USER_REPORT_ROLES", "Compliance.Admin,Compliance.Investigator").split(",") if x.strip()}
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"


def init_reporting_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS report_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, recipients TEXT NOT NULL,
            frequency TEXT NOT NULL, report_format TEXT NOT NULL, include_named_users INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1, next_run_at TEXT NOT NULL, last_run_at TEXT,
            last_status TEXT, created_at TEXT NOT NULL, created_by TEXT NOT NULL)""")
        db.commit()


def parse_dt(value: str | None, end: bool = False) -> datetime | None:
    if not value: return None
    try:
        if len(value) == 10:
            parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
            return parsed + timedelta(days=1) - timedelta(microseconds=1) if end else parsed
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Dates must use YYYY-MM-DD or ISO-8601 format") from exc


def filter_findings(rows: list[dict[str, Any]], date_from: str = "", date_to: str = "", risk: str = "all", surface: str = "all") -> list[dict[str, Any]]:
    start, end = parse_dt(date_from), parse_dt(date_to, True)
    if start and end and start > end: raise ValueError("Start date must be on or before end date")
    result = []
    for row in rows:
        created = parse_dt(row.get("created_at"))
        if start and (not created or created < start): continue
        if end and (not created or created > end): continue
        if risk != "all" and row.get("risk") != risk: continue
        if surface != "all" and row.get("surface") != surface: continue
        result.append(row)
    return result


def _identity(row: dict[str, Any], include_named_users: bool) -> str:
    if not include_named_users: return "Restricted"
    user = row.get("user") or {}
    return str(user.get("email") or user.get("id") or "Unknown")


def findings_summary(rows: list[dict[str, Any]], include_named_users: bool = False) -> dict[str, Any]:
    severities = {x: 0 for x in ("critical", "high", "medium", "low", "informational")}
    categories: dict[str, int] = {}; surfaces: dict[str, int] = {}
    for row in rows:
        severity = row.get("risk", "informational"); severities[severity] = severities.get(severity, 0) + 1
        surfaces[row.get("surface", "Unknown")] = surfaces.get(row.get("surface", "Unknown"), 0) + 1
        for factor in row.get("risk_factors", []):
            name = factor.get("id", "unknown"); categories[name] = categories.get(name, 0) + 1
    details = [{"id":r.get("id"),"created_at":r.get("created_at"),"severity":r.get("risk"),"score":r.get("risk_score"),
        "category":", ".join(x.get("id","") for x in r.get("risk_factors",[])),"status":r.get("status","new"),
        "surface":r.get("surface"),"title":r.get("title"),"identity":_identity(r,include_named_users),
        "rule_version":r.get("risk_rule_version"),"provenance":"Synthetic demo evidence" if str(r.get("id","")).find("demo") >= 0 else "Provider compliance API"} for r in rows]
    return {"total":len(rows),"severity":severities,"categories":dict(sorted(categories.items(),key=lambda x:x[1],reverse=True)),
        "surfaces":dict(sorted(surfaces.items(),key=lambda x:x[1],reverse=True)),"findings":details}


def findings_trends(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        created = parse_dt(row.get("created_at"));
        if not created: continue
        key = created.strftime("%Y-%m"); bucket = buckets.setdefault(key,{"period":key,"total":0,"critical":0,"high":0,"medium":0,"average_score":0,"_score":0})
        bucket["total"] += 1; severity=row.get("risk", "informational")
        if severity in ("critical","high","medium"): bucket[severity] += 1
        bucket["_score"] += int(row.get("risk_score") or 0)
    result=[]
    for key in sorted(buckets):
        bucket=buckets[key]; bucket["average_score"]=round(bucket.pop("_score")/bucket["total"],1); result.append(bucket)
    return result


def findings_csv(report: dict[str, Any], actor: str = "", version: str = "", filters: dict[str, str] | None = None) -> bytes:
    out=io.StringIO(); meta=csv.writer(out); meta.writerow(["JO AI Monitor Compliance Findings Report"]); meta.writerow(["Generated at",datetime.now(timezone.utc).isoformat()]); meta.writerow(["Generated by",actor]); meta.writerow(["Version",version]); meta.writerow(["Filters",json.dumps(filters or {},sort_keys=True)]); meta.writerow([])
    writer=csv.DictWriter(out,fieldnames=["id","created_at","severity","score","category","status","surface","title","identity","rule_version","provenance"])
    writer.writeheader(); writer.writerows(report["findings"]); return out.getvalue().encode("utf-8-sig")


def findings_pdf(report: dict[str, Any], actor: str, version: str, filters: dict[str, str]) -> bytes:
    stream=io.BytesIO(); styles=getSampleStyleSheet(); doc=SimpleDocTemplate(stream,pagesize=letter,rightMargin=.45*inch,leftMargin=.45*inch,topMargin=.5*inch,bottomMargin=.5*inch)
    story=[Paragraph("JO AI Monitor - Compliance Findings Report",styles["Title"]),Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {actor} - v{version}",styles["BodyText"]),
        Paragraph(f"Range: {filters.get('date_from') or 'All'} through {filters.get('date_to') or 'All'} | Severity: {filters.get('risk','all')} | Surface: {filters.get('surface','all')}",styles["BodyText"]),Spacer(1,10)]
    sev=report["severity"]; summary=[["Total","Critical","High","Medium"],[report["total"],sev.get("critical",0),sev.get("high",0),sev.get("medium",0)]]
    t=Table(summary,colWidths=[1.55*inch]*4); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172231")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#D8DEE6")),("PADDING",(0,0),(-1,-1),7)])); story += [t,Spacer(1,12)]
    rows=[["Severity","Score","Date","Surface","Finding","Identity"]]+[[x["severity"],x["score"],str(x["created_at"])[:10],x["surface"],Paragraph(str(x["title"]),styles["BodyText"]),x["identity"]] for x in report["findings"]]
    table=Table(rows,repeatRows=1,colWidths=[.65*inch,.4*inch,.7*inch,.9*inch,2.7*inch,1.1*inch]); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#315FDC")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.HexColor("#D8DEE6")),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)])); story.append(table)
    doc.build(story); return stream.getvalue()


def smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM)


def send_report(recipients: list[str], subject: str, payload: bytes, filename: str, media_type: str) -> None:
    if not smtp_configured(): raise RuntimeError("SMTP delivery is not configured")
    msg=EmailMessage(); msg["From"]=SMTP_FROM; msg["To"]=", ".join(recipients); msg["Subject"]=subject; msg.set_content("Your scheduled JO AI Monitor compliance report is attached.")
    maintype,subtype=media_type.split("/",1); msg.add_attachment(payload,maintype=maintype,subtype=subtype,filename=filename)
    with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp:
        if SMTP_TLS: smtp.starttls()
        if SMTP_USERNAME: smtp.login(SMTP_USERNAME,SMTP_PASSWORD)
        smtp.send_message(msg)


def list_schedules() -> list[dict[str, Any]]:
    init_reporting_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; rows=db.execute("SELECT * FROM report_schedules ORDER BY id DESC").fetchall()
    return [{**dict(x),"recipients":json.loads(x["recipients"]),"enabled":bool(x["enabled"]),"include_named_users":bool(x["include_named_users"])} for x in rows]


def create_schedule(name: str, recipients: list[str], frequency: str, report_format: str, include_named_users: bool, actor: str) -> dict[str, Any]:
    init_reporting_db()
    if frequency not in ("daily","weekly","monthly"): raise ValueError("Frequency must be daily, weekly, or monthly")
    if report_format not in ("pdf","csv","json"): raise ValueError("Format must be PDF, CSV, or JSON")
    recipients=[x.strip() for x in recipients if x.strip()]
    if not recipients: raise ValueError("At least one recipient is required")
    now=datetime.now(timezone.utc); delta={"daily":timedelta(days=1),"weekly":timedelta(days=7),"monthly":timedelta(days=30)}[frequency]
    with closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("INSERT INTO report_schedules(name,recipients,frequency,report_format,include_named_users,enabled,next_run_at,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)",
            (name.strip() or "Compliance report",json.dumps(recipients),frequency,report_format,int(include_named_users),1,(now+delta).isoformat(),now.isoformat(),actor)); db.commit(); schedule_id=cur.lastrowid
    return next(x for x in list_schedules() if x["id"]==schedule_id)


def update_schedule_run(schedule_id: int, status: str) -> None:
    schedule=next((x for x in list_schedules() if x["id"]==schedule_id),None)
    if not schedule: return
    now=datetime.now(timezone.utc); delta={"daily":timedelta(days=1),"weekly":timedelta(days=7),"monthly":timedelta(days=30)}[schedule["frequency"]]
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("UPDATE report_schedules SET last_run_at=?,last_status=?,next_run_at=? WHERE id=?",(now.isoformat(),status,(now+delta).isoformat(),schedule_id)); db.commit()


def delete_schedule(schedule_id: int) -> None:
    init_reporting_db()
    with closing(sqlite3.connect(DB_PATH)) as db: db.execute("DELETE FROM report_schedules WHERE id=?",(schedule_id,)); db.commit()
