import html
import hashlib
import io
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.governance import DB_PATH

STATUSES = ("new", "investigating", "confirmed", "benign", "accepted_risk", "closed")
PRIORITIES = ("critical", "high", "medium", "low")
CLOSED_STATUSES = {"benign", "accepted_risk", "closed"}
ESCALATIONS = ("none", "watch", "management", "incident_response", "legal")
ATTACHMENT_DIR = Path(os.getenv("ATTACHMENT_PATH", str(DB_PATH.parent / "attachments")))
MAX_ATTACHMENT_BYTES = max(1, int(os.getenv("MAX_ATTACHMENT_MB", "10"))) * 1024 * 1024
ALLOWED_ATTACHMENT_TYPES = {"application/pdf","text/plain","text/csv","application/json","image/png","image/jpeg"}


def _ensure_column(db: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    columns={x[1] for x in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if name not in columns: db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


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
        _ensure_column(db,"investigation_cases","category","TEXT NOT NULL DEFAULT 'security_review'")
        _ensure_column(db,"investigation_cases","escalation","TEXT NOT NULL DEFAULT 'none'")
        _ensure_column(db,"investigation_cases","legal_hold","INTEGER NOT NULL DEFAULT 0")
        _ensure_column(db,"investigation_cases","legal_hold_reason","TEXT NOT NULL DEFAULT ''")
        db.execute("""CREATE TABLE IF NOT EXISTS case_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, parent_id INTEGER,
            actor TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES investigation_cases(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS case_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, filename TEXT NOT NULL,
            media_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE,
            uploaded_at TEXT NOT NULL, uploaded_by TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES investigation_cases(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS saved_case_queues (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner TEXT NOT NULL,
            filters_json TEXT NOT NULL, shared INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""")
        db.commit()


def _now() -> str: return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str: return json.dumps(value,sort_keys=True,separators=(",",":"))


def _event(db: sqlite3.Connection, case_id: int, event_type: str, actor: str, old: Any = None, new: Any = None, reason: str = "") -> None:
    db.execute("INSERT INTO case_events(case_id,event_type,actor,created_at,old_value,new_value,reason) VALUES(?,?,?,?,?,?,?)",
        (case_id,event_type,actor,_now(),None if old is None else _json(old),None if new is None else _json(new),reason.strip() or event_type.replace("_"," ")))


def _row(row: sqlite3.Row) -> dict[str, Any]:
    result=dict(row); result["tags"]=json.loads(result.get("tags") or "[]"); return result


def create_case(title: str, description: str, priority: str, assignee: str, due_at: str | None, tags: list[str], actor: str, finding: dict[str, Any] | None = None, category: str = "security_review") -> dict[str, Any]:
    init_case_db(); priority=priority.lower()
    if not title.strip(): raise ValueError("Case title is required")
    if priority not in PRIORITIES: raise ValueError("Priority must be critical, high, medium, or low")
    now=_now(); clean_tags=sorted({str(x).strip() for x in tags if str(x).strip()})
    with closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("INSERT INTO investigation_cases(title,description,status,priority,assignee,due_at,tags,category,created_at,updated_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (title.strip(),description.strip(),"new",priority,assignee.strip(),due_at or None,_json(clean_tags),category.strip() or "security_review",now,now,actor)); case_id=cur.lastrowid
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


def list_cases(status: str = "all", assignee: str = "", q: str = "", priority: str = "all", category: str = "", escalation: str = "all") -> list[dict[str, Any]]:
    init_case_db(); where=[]; params=[]
    if status != "all": where.append("c.status=?"); params.append(status)
    if assignee: where.append("c.assignee=?"); params.append(assignee)
    if priority != "all": where.append("c.priority=?"); params.append(priority)
    if category: where.append("c.category=?"); params.append(category)
    if escalation != "all": where.append("c.escalation=?"); params.append(escalation)
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
        comments=db.execute("SELECT id,parent_id,actor,body,created_at FROM case_comments WHERE case_id=? ORDER BY id",(case_id,)).fetchall()
        attachments=db.execute("SELECT id,filename,media_type,size,sha256,uploaded_at,uploaded_by FROM case_attachments WHERE case_id=? ORDER BY id",(case_id,)).fetchall()
    result=_row(row); result["legal_hold"]=bool(result.get("legal_hold")); result["findings"]=[{**json.loads(x["snapshot_json"]),"snapshot":{"linked_at":x["linked_at"],"linked_by":x["linked_by"]}} for x in findings]
    result["timeline"]=[{**dict(x),"old_value":json.loads(x["old_value"]) if x["old_value"] else None,"new_value":json.loads(x["new_value"]) if x["new_value"] else None} for x in events]
    result["comments"]=[dict(x) for x in comments]; result["attachments"]=[dict(x) for x in attachments]
    return result


def update_case(case_id: int, changes: dict[str, Any], actor: str, reason: str = "") -> dict[str, Any]:
    current=get_case(case_id); allowed={"title","description","status","priority","assignee","due_at","disposition","tags","category","escalation"}; updates={k:v for k,v in changes.items() if k in allowed}
    if not updates: raise ValueError("No supported case fields were provided")
    if "status" in updates and updates["status"] not in STATUSES: raise ValueError("Unsupported case status")
    if "priority" in updates and updates["priority"] not in PRIORITIES: raise ValueError("Unsupported case priority")
    if "escalation" in updates and updates["escalation"] not in ESCALATIONS: raise ValueError("Unsupported escalation state")
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


def add_comment(case_id: int, body: str, actor: str, parent_id: int | None = None) -> dict[str, Any]:
    get_case(case_id); body=body.strip()
    if not body: raise ValueError("Comment text is required")
    with closing(sqlite3.connect(DB_PATH)) as db:
        if parent_id and not db.execute("SELECT 1 FROM case_comments WHERE id=? AND case_id=?",(parent_id,case_id)).fetchone(): raise ValueError("Parent comment was not found in this case")
        cur=db.execute("INSERT INTO case_comments(case_id,parent_id,actor,body,created_at) VALUES(?,?,?,?,?)",(case_id,parent_id,actor,body,_now()))
        _event(db,case_id,"comment_added",actor,None,{"comment_id":cur.lastrowid,"parent_id":parent_id}); db.execute("UPDATE investigation_cases SET updated_at=? WHERE id=?",(_now(),case_id)); db.commit()
    return get_case(case_id)


def save_attachment(case_id: int, filename: str, media_type: str, content: bytes, actor: str) -> dict[str, Any]:
    get_case(case_id)
    if not content: raise ValueError("Attachment is empty")
    if len(content)>MAX_ATTACHMENT_BYTES: raise ValueError(f"Attachment exceeds the {MAX_ATTACHMENT_BYTES//1024//1024} MB limit")
    if media_type not in ALLOWED_ATTACHMENT_TYPES: raise ValueError("Attachment type is not allowed")
    safe="".join(c if c.isalnum() or c in ".-_" else "_" for c in Path(filename).name)
    if safe in ("",".",".."): raise ValueError("Attachment filename is invalid")
    digest=hashlib.sha256(content).hexdigest(); storage=f"{case_id}-{digest}-{safe}"; ATTACHMENT_DIR.mkdir(parents=True,exist_ok=True); target=(ATTACHMENT_DIR/storage).resolve()
    if ATTACHMENT_DIR.resolve() not in target.parents: raise ValueError("Attachment path is invalid")
    if not target.exists(): target.write_bytes(content)
    with closing(sqlite3.connect(DB_PATH)) as db:
        if db.execute("SELECT 1 FROM case_attachments WHERE case_id=? AND sha256=?",(case_id,digest)).fetchone(): raise ValueError("This exact attachment is already linked to the case")
        cur=db.execute("INSERT INTO case_attachments(case_id,filename,media_type,size,sha256,storage_name,uploaded_at,uploaded_by) VALUES(?,?,?,?,?,?,?,?)",(case_id,safe,media_type,len(content),digest,storage,_now(),actor)); _event(db,case_id,"attachment_added",actor,None,{"attachment_id":cur.lastrowid,"filename":safe,"sha256":digest}); db.execute("UPDATE investigation_cases SET updated_at=? WHERE id=?",(_now(),case_id)); db.commit()
    return get_case(case_id)


def get_attachment(case_id: int, attachment_id: int) -> tuple[dict[str, Any], Path]:
    init_case_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM case_attachments WHERE id=? AND case_id=?",(attachment_id,case_id)).fetchone()
    if not row: raise KeyError("Attachment not found")
    path=(ATTACHMENT_DIR/row["storage_name"]).resolve()
    if ATTACHMENT_DIR.resolve() not in path.parents or not path.is_file(): raise KeyError("Attachment content not found")
    return dict(row),path


def set_legal_hold(case_id: int, enabled: bool, reason: str, actor: str) -> dict[str, Any]:
    current=get_case(case_id); reason=reason.strip()
    if enabled and not reason: raise ValueError("A legal-hold reason is required")
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("UPDATE investigation_cases SET legal_hold=?,legal_hold_reason=?,updated_at=? WHERE id=?",(int(enabled),reason if enabled else "",_now(),case_id)); _event(db,case_id,"legal_hold_enabled" if enabled else "legal_hold_released",actor,{"enabled":current["legal_hold"],"reason":current.get("legal_hold_reason","")},{"enabled":enabled,"reason":reason},reason); db.commit()
    return get_case(case_id)


def bulk_update(case_ids: list[int], changes: dict[str, Any], actor: str, reason: str) -> list[dict[str, Any]]:
    if not case_ids: raise ValueError("Select at least one case")
    if not reason.strip(): raise ValueError("A reason is required for bulk changes")
    ids=sorted({int(case_id) for case_id in case_ids}); current=[get_case(case_id) for case_id in ids]
    if changes.get("status") in CLOSED_STATUSES and not str(changes.get("disposition") or "").strip() and any(not x.get("disposition") for x in current): raise ValueError("Every selected case requires a disposition before bulk closure")
    return [update_case(case_id,changes,actor,reason) for case_id in ids]


def save_queue(name: str, owner: str, filters: dict[str, Any], shared: bool = False) -> dict[str, Any]:
    init_case_db(); name=name.strip()
    if not name: raise ValueError("Queue name is required")
    allowed={k:v for k,v in filters.items() if k in {"status","assignee","q","priority","category","escalation"}}
    with closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("INSERT INTO saved_case_queues(name,owner,filters_json,shared,created_at) VALUES(?,?,?,?,?)",(name,owner,_json(allowed),int(shared),_now())); db.commit(); queue_id=cur.lastrowid
    return {"id":queue_id,"name":name,"owner":owner,"filters":allowed,"shared":shared}


def list_queues(actor: str) -> list[dict[str, Any]]:
    init_case_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; rows=db.execute("SELECT * FROM saved_case_queues WHERE owner=? OR shared=1 ORDER BY id DESC",(actor,)).fetchall()
    return [{"id":x["id"],"name":x["name"],"owner":x["owner"],"filters":json.loads(x["filters_json"]),"shared":bool(x["shared"]),"created_at":x["created_at"]} for x in rows]


def delete_queue(queue_id: int, actor: str) -> None:
    init_case_db()
    with closing(sqlite3.connect(DB_PATH)) as db: db.execute("DELETE FROM saved_case_queues WHERE id=? AND owner=?",(queue_id,actor)); db.commit()


def case_pdf(case: dict[str, Any], actor: str, version: str) -> bytes:
    stream=io.BytesIO(); styles=getSampleStyleSheet(); doc=SimpleDocTemplate(stream,pagesize=letter,rightMargin=.5*inch,leftMargin=.5*inch,topMargin=.5*inch,bottomMargin=.5*inch)
    story=[Paragraph(f"JO AI Monitor - Investigation Case #{case['id']}",styles["Title"]),Paragraph(html.escape(case["title"]),styles["Heading2"]),
        Paragraph(f"Generated {_now()} by {html.escape(actor)} - v{html.escape(version)}",styles["BodyText"]),Spacer(1,10)]
    meta=[["Status",case["status"],"Priority",case["priority"]],["Assignee",case["assignee"] or "Unassigned","Due",case["due_at"] or "None"],["Category",case.get("category","security_review"),"Escalation",case.get("escalation","none")],["Legal hold","Active" if case.get("legal_hold") else "No","Hold reason",case.get("legal_hold_reason") or "None"],["Disposition",case["disposition"] or "Open","Created",case["created_at"]]]
    table=Table(meta,colWidths=[.85*inch,2.2*inch,.85*inch,2.6*inch]); table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.35,colors.HexColor("#D8DEE6")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EEF2F7")),("BACKGROUND",(2,0),(2,-1),colors.HexColor("#EEF2F7")),("PADDING",(0,0),(-1,-1),6)])); story += [table,Spacer(1,12),Paragraph("Description",styles["Heading2"]),Paragraph(html.escape(case["description"] or "No description"),styles["BodyText"]),Spacer(1,10),Paragraph("Preserved findings",styles["Heading2"])]
    findings=[["ID","Severity","Score","Finding","Surface"]]+[[x.get("id"),x.get("risk"),x.get("risk_score"),Paragraph(html.escape(str(x.get("title",""))),styles["BodyText"]),x.get("surface")] for x in case["findings"]]
    ft=Table(findings,repeatRows=1,colWidths=[1.25*inch,.6*inch,.4*inch,3*inch,1.25*inch]); ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#315FDC")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.HexColor("#D8DEE6")),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)])); story += [ft,Spacer(1,12),Paragraph("Case timeline",styles["Heading2"])]
    for event in reversed(case["timeline"]): story.append(Paragraph(f"{html.escape(event['created_at'])} - {html.escape(event['actor'])} - {html.escape(event['event_type'])}: {html.escape(event['reason'] or json.dumps(event['new_value'] or {}))}",styles["BodyText"]))
    story += [Spacer(1,10),Paragraph("Analyst comments",styles["Heading2"])]
    for comment in case.get("comments",[]): story.append(Paragraph(f"{html.escape(comment['created_at'])} - {html.escape(comment['actor'])}{' (reply)' if comment.get('parent_id') else ''}: {html.escape(comment['body'])}",styles["BodyText"]))
    story += [Spacer(1,10),Paragraph("Attachment manifest",styles["Heading2"])]
    attachment_rows=[["Filename","Type","Bytes","SHA-256","Uploaded by"]]+[[x["filename"],x["media_type"],x["size"],x["sha256"],x["uploaded_by"]] for x in case.get("attachments",[])]
    at=Table(attachment_rows,repeatRows=1,colWidths=[1.25*inch,1.1*inch,.55*inch,2.75*inch,1.1*inch]); at.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172231")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.HexColor("#D8DEE6")),("FONTSIZE",(0,0),(-1,-1),6),("PADDING",(0,0),(-1,-1),3)])); story.append(at)
    doc.build(story); return stream.getvalue()
