import html
import io
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.governance import DB_PATH

STATUSES = ("new", "investigating", "confirmed", "benign", "accepted_risk", "closed")
PRIORITIES = ("critical", "high", "medium", "low")
CLOSED_STATUSES = {"benign", "accepted_risk", "closed"}


def init_case_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS investigation_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL, priority TEXT NOT NULL, assignee TEXT NOT NULL DEFAULT '', due_at TEXT,
            disposition TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, created_by TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS case_findings (
            case_id INTEGER NOT NULL, finding_id TEXT NOT NULL, snapshot_json TEXT NOT NULL,
            linked_at TEXT NOT NULL, linked_by TEXT NOT NULL, PRIMARY KEY(case_id,finding_id),
            FOREIGN KEY(case_id) REFERENCES investigation_cases(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, event_type TEXT NOT NULL,
            actor TEXT NOT NULL, created_at TEXT NOT NULL, old_value TEXT, new_value TEXT, reason TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(case_id) REFERENCES investigation_cases(id))""")
        db.commit()


def _now() -> str: return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str: return json.dumps(value,sort_keys=True,separators=(",",":"))


def _event(db: sqlite3.Connection, case_id: int, event_type: str, actor: str, old: Any = None, new: Any = None, reason: str = "") -> None:
    db.execute("INSERT INTO case_events(case_id,event_type,actor,created_at,old_value,new_value,reason) VALUES(?,?,?,?,?,?,?)",
        (case_id,event_type,actor,_now(),None if old is None else _json(old),None if new is None else _json(new),reason))


def _row(row: sqlite3.Row) -> dict[str, Any]:
    result=dict(row); result["tags"]=json.loads(result.get("tags") or "[]"); return result


def create_case(title: str, description: str, priority: str, assignee: str, due_at: str | None, tags: list[str], actor: str, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    init_case_db(); priority=priority.lower()
    if not title.strip(): raise ValueError("Case title is required")
    if priority not in PRIORITIES: raise ValueError("Priority must be critical, high, medium, or low")
    now=_now(); clean_tags=sorted({str(x).strip() for x in tags if str(x).strip()})
    with closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("INSERT INTO investigation_cases(title,description,status,priority,assignee,due_at,tags,created_at,updated_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (title.strip(),description.strip(),"new",priority,assignee.strip(),due_at or None,_json(clean_tags),now,now,actor)); case_id=cur.lastrowid
        _event(db,case_id,"case_created",actor,None,{"title":title.strip(),"priority":priority,"assignee":assignee.strip()})
        if finding: _link_finding(db,case_id,finding,actor)
        db.commit()
    return get_case(case_id)


def _link_finding(db: sqlite3.Connection, case_id: int, finding: dict[str, Any], actor: str) -> None:
    finding_id=str(finding.get("id") or "")
    if not finding_id: raise ValueError("Finding ID is required")
    cursor=db.execute("INSERT OR IGNORE INTO case_findings(case_id,finding_id,snapshot_json,linked_at,linked_by) VALUES(?,?,?,?,?)",
        (case_id,finding_id,_json(finding),_now(),actor))
    if cursor.rowcount: _event(db,case_id,"finding_linked",actor,None,{"finding_id":finding_id,"title":finding.get("title")})


def link_finding(case_id: int, finding: dict[str, Any], actor: str) -> dict[str, Any]:
    get_case(case_id); 
    with closing(sqlite3.connect(DB_PATH)) as db: _link_finding(db,case_id,finding,actor); db.execute("UPDATE investigation_cases SET updated_at=? WHERE id=?",(_now(),case_id)); db.commit()
    return get_case(case_id)


def list_cases(status: str = "all", assignee: str = "", q: str = "") -> list[dict[str, Any]]:
    init_case_db(); where=[]; params=[]
    if status != "all": where.append("c.status=?"); params.append(status)
    if assignee: where.append("c.assignee=?"); params.append(assignee)
    if q: where.append("(c.title LIKE ? OR c.description LIKE ? OR c.tags LIKE ?)"); params.extend([f"%{q}%"]*3)
    sql="SELECT c.*,COUNT(f.finding_id) finding_count FROM investigation_cases c LEFT JOIN case_findings f ON f.case_id=c.id"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY c.id ORDER BY CASE c.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,c.updated_at DESC"
    with closing(sqlite3.connect(DB_PATH)) as db: db.row_factory=sqlite3.Row; rows=db.execute(sql,params).fetchall()
    return [_row(x) for x in rows]


def get_case(case_id: int) -> dict[str, Any]:
    init_case_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM investigation_cases WHERE id=?",(case_id,)).fetchone()
        if not row: raise KeyError("Case not found")
        findings=db.execute("SELECT finding_id,snapshot_json,linked_at,linked_by FROM case_findings WHERE case_id=? ORDER BY linked_at",(case_id,)).fetchall()
        events=db.execute("SELECT id,event_type,actor,created_at,old_value,new_value,reason FROM case_events WHERE case_id=? ORDER BY id DESC",(case_id,)).fetchall()
    result=_row(row); result["findings"]=[{**json.loads(x["snapshot_json"]),"snapshot":{"linked_at":x["linked_at"],"linked_by":x["linked_by"]}} for x in findings]
    result["timeline"]=[{**dict(x),"old_value":json.loads(x["old_value"]) if x["old_value"] else None,"new_value":json.loads(x["new_value"]) if x["new_value"] else None} for x in events]
    return result


def update_case(case_id: int, changes: dict[str, Any], actor: str, reason: str = "") -> dict[str, Any]:
    current=get_case(case_id); allowed={"title","description","status","priority","assignee","due_at","disposition","tags"}; updates={k:v for k,v in changes.items() if k in allowed}
    if not updates: raise ValueError("No supported case fields were provided")
    if "status" in updates and updates["status"] not in STATUSES: raise ValueError("Unsupported case status")
    if "priority" in updates and updates["priority"] not in PRIORITIES: raise ValueError("Unsupported case priority")
    closing_status=updates.get("status",current["status"])
    disposition=str(updates.get("disposition",current["disposition"]) or "").strip()
    if closing_status in CLOSED_STATUSES and not disposition: raise ValueError("A disposition reason is required before closing or accepting a case")
    if "tags" in updates: updates["tags"]=_json(sorted({str(x).strip() for x in updates["tags"] if str(x).strip()}))
    fields=list(updates); values=[updates[x] for x in fields]; now=_now()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute(f"UPDATE investigation_cases SET {','.join(x+'=?' for x in fields)},updated_at=? WHERE id=?",values+[now,case_id])
        for field in fields:
            old=current[field]; new=json.loads(updates[field]) if field=="tags" else updates[field]
            if old != new: _event(db,case_id,f"{field}_changed",actor,old,new,reason)
        db.commit()
    return get_case(case_id)


def add_note(case_id: int, text: str, actor: str) -> dict[str, Any]:
    get_case(case_id); text=text.strip()
    if not text: raise ValueError("Note text is required")
    with closing(sqlite3.connect(DB_PATH)) as db: _event(db,case_id,"analyst_note",actor,None,{"text":text}); db.execute("UPDATE investigation_cases SET updated_at=? WHERE id=?",(_now(),case_id)); db.commit()
    return get_case(case_id)


def case_pdf(case: dict[str, Any], actor: str, version: str) -> bytes:
    stream=io.BytesIO(); styles=getSampleStyleSheet(); doc=SimpleDocTemplate(stream,pagesize=letter,rightMargin=.5*inch,leftMargin=.5*inch,topMargin=.5*inch,bottomMargin=.5*inch)
    story=[Paragraph(f"JO AI Monitor - Investigation Case #{case['id']}",styles["Title"]),Paragraph(html.escape(case["title"]),styles["Heading2"]),
        Paragraph(f"Generated {_now()} by {html.escape(actor)} - v{html.escape(version)}",styles["BodyText"]),Spacer(1,10)]
    meta=[["Status",case["status"],"Priority",case["priority"]],["Assignee",case["assignee"] or "Unassigned","Due",case["due_at"] or "None"],["Disposition",case["disposition"] or "Open","Created",case["created_at"]]]
    table=Table(meta,colWidths=[.85*inch,2.2*inch,.85*inch,2.6*inch]); table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.35,colors.HexColor("#D8DEE6")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EEF2F7")),("BACKGROUND",(2,0),(2,-1),colors.HexColor("#EEF2F7")),("PADDING",(0,0),(-1,-1),6)])); story += [table,Spacer(1,12),Paragraph("Description",styles["Heading2"]),Paragraph(html.escape(case["description"] or "No description"),styles["BodyText"]),Spacer(1,10),Paragraph("Preserved findings",styles["Heading2"])]
    findings=[["ID","Severity","Score","Finding","Surface"]]+[[x.get("id"),x.get("risk"),x.get("risk_score"),Paragraph(html.escape(str(x.get("title",""))),styles["BodyText"]),x.get("surface")] for x in case["findings"]]
    ft=Table(findings,repeatRows=1,colWidths=[1.25*inch,.6*inch,.4*inch,3*inch,1.25*inch]); ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#315FDC")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.HexColor("#D8DEE6")),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)])); story += [ft,Spacer(1,12),Paragraph("Case timeline",styles["Heading2"])]
    for event in reversed(case["timeline"]): story.append(Paragraph(f"{html.escape(event['created_at'])} - {html.escape(event['actor'])} - {html.escape(event['event_type'])}: {html.escape(event['reason'] or json.dumps(event['new_value'] or {}))}",styles["BodyText"]))
    doc.build(story); return stream.getvalue()
