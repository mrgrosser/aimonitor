import json
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from app.governance import DB_PATH

_lock=threading.Lock()
STATUSES={"open","acknowledged","suppressed","resolved"}
ESCALATIONS={"none","management","incident_response","legal"}

def _now() -> str: return datetime.now(timezone.utc).isoformat()

def init_alert_db() -> None:
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, alert_type TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL, finding_id TEXT,
            status TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', escalation TEXT NOT NULL DEFAULT 'none',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, acknowledged_at TEXT,
            acknowledged_by TEXT, suppressed_until TEXT, reason TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}')""")
        db.execute("""CREATE TABLE IF NOT EXISTS alert_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, created_at TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL, changes_json TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS alert_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, connector TEXT NOT NULL,
            idempotency_key TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt_at TEXT, next_attempt_at TEXT, last_error TEXT NOT NULL DEFAULT '', delivered_at TEXT,
            UNIQUE(connector,idempotency_key))""")
        db.commit()

def _alert(row: sqlite3.Row) -> dict[str,Any]:
    result=dict(row); result["metadata"]=json.loads(result.pop("metadata_json")); return result

def create_alert(event_key: str, alert_type: str, severity: str, title: str, summary: str,
                 finding_id: str="", metadata: dict[str,Any] | None=None, actor: str="system") -> dict[str,Any]:
    init_alert_db(); event_key=event_key.strip()
    if not event_key or not title.strip(): raise ValueError("Event key and title are required")
    now=_now(); alert_id=f"alt_{uuid.uuid4().hex[:16]}"
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row
        existing=db.execute("SELECT * FROM alerts WHERE event_key=?",(event_key,)).fetchone()
        if existing: return _alert(existing)
        db.execute("""INSERT INTO alerts(id,event_key,alert_type,severity,title,summary,finding_id,status,created_at,updated_at,metadata_json)
            VALUES(?,?,?,?,?,?,?,'open',?,?,?)""",(alert_id,event_key,alert_type.strip(),severity.strip().lower(),title.strip(),summary.strip(),finding_id,now,now,json.dumps(metadata or {},sort_keys=True)))
        db.execute("INSERT INTO alert_timeline(alert_id,created_at,actor,action,reason,changes_json) VALUES(?,?,?,?,?,?)",
            (alert_id,now,actor,"created","Alert created",json.dumps({"status":"open"})))
        db.commit(); row=db.execute("SELECT * FROM alerts WHERE id=?",(alert_id,)).fetchone()
    return _alert(row)

def list_alerts(status: str="", owner: str="", limit: int=200) -> list[dict[str,Any]]:
    init_alert_db(); where=[]; params=[]
    if status: where.append("status=?"); params.append(status)
    if owner: where.append("owner=?"); params.append(owner)
    sql="SELECT * FROM alerts"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY created_at DESC LIMIT ?"; params.append(min(max(limit,1),1000))
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; return [_alert(row) for row in db.execute(sql,params).fetchall()]

def get_alert(alert_id: str) -> dict[str,Any]:
    init_alert_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM alerts WHERE id=?",(alert_id,)).fetchone()
    if not row: raise ValueError("Alert not found")
    return _alert(row)

def update_alert(alert_id: str, changes: dict[str,Any], actor: str, reason: str) -> dict[str,Any]:
    current=get_alert(alert_id); reason=reason.strip()
    if not reason: raise ValueError("A reason is required")
    status=str(changes.get("status",current["status"])); escalation=str(changes.get("escalation",current["escalation"]))
    if status not in STATUSES: raise ValueError("Invalid alert status")
    if escalation not in ESCALATIONS: raise ValueError("Invalid escalation")
    owner=str(changes.get("owner",current["owner"])).strip(); suppressed_until=str(changes.get("suppressed_until",current.get("suppressed_until") or "")).strip() or None
    if status=="suppressed" and not suppressed_until: raise ValueError("Suppressed alerts require an expiration")
    now=_now(); acknowledged_at=current.get("acknowledged_at"); acknowledged_by=current.get("acknowledged_by")
    if status=="acknowledged" and current["status"]!="acknowledged": acknowledged_at,acknowledged_by=now,actor
    delta={k:v for k,v in {"status":status,"owner":owner,"escalation":escalation,"suppressed_until":suppressed_until}.items() if v!=current.get(k)}
    if not delta: raise ValueError("No alert changes were provided")
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""UPDATE alerts SET status=?,owner=?,escalation=?,suppressed_until=?,acknowledged_at=?,acknowledged_by=?,reason=?,updated_at=? WHERE id=?""",
            (status,owner,escalation,suppressed_until,acknowledged_at,acknowledged_by,reason,now,alert_id))
        db.execute("INSERT INTO alert_timeline(alert_id,created_at,actor,action,reason,changes_json) VALUES(?,?,?,?,?,?)",
            (alert_id,now,actor,"updated",reason,json.dumps(delta,sort_keys=True))); db.commit()
    return get_alert(alert_id)

def alert_timeline(alert_id: str) -> list[dict[str,Any]]:
    get_alert(alert_id)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; rows=db.execute("SELECT * FROM alert_timeline WHERE alert_id=? ORDER BY id",(alert_id,)).fetchall()
    return [{**dict(row),"changes":json.loads(row["changes_json"])} for row in rows]

def queue_delivery(alert_id: str, connector: str) -> dict[str,Any]:
    get_alert(alert_id); connector=connector.strip().lower(); key=f"{alert_id}:{connector}"
    if connector not in {"email","teams","webhook"}: raise ValueError("Unsupported alert connector")
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("INSERT OR IGNORE INTO alert_deliveries(alert_id,connector,idempotency_key,status) VALUES(?,?,?,'pending')",(alert_id,connector,key)); db.commit()
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM alert_deliveries WHERE connector=? AND idempotency_key=?",(connector,key)).fetchone()
    return dict(row)
