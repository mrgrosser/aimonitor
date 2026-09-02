import json
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.governance import DB_PATH

RAPID7_WEBHOOK_URL=os.getenv("RAPID7_WEBHOOK_URL","").strip()
MAX_ATTEMPTS=max(1,min(int(os.getenv("RAPID7_MAX_ATTEMPTS","8")),20))
DEFAULT_CATEGORIES=["authentication","authorization","policy","case","alert","delivery","audit","system"]
DEFAULT_FIELDS=["event_id","timestamp","actor","action","object_type","object_id","source_ip","category"]
PROHIBITED={"prompt","response","transcript","attachment","evidence","messages","content","summary","query"}
_lock=threading.Lock()

def _now() -> str: return datetime.now(timezone.utc).isoformat()

def init_rapid7_db() -> None:
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS rapid7_config (
            id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,
            categories_json TEXT NOT NULL, fields_json TEXT NOT NULL, updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL, change_reason TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS rapid7_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
            category TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0, last_attempt_at TEXT, next_attempt_at TEXT,
            delivered_at TEXT, last_error TEXT NOT NULL DEFAULT '')""")
        if not db.execute("SELECT 1 FROM rapid7_config WHERE id=1").fetchone():
            db.execute("INSERT INTO rapid7_config VALUES(1,0,?,?,?,?,?)",(json.dumps(DEFAULT_CATEGORIES),json.dumps(DEFAULT_FIELDS),_now(),"system","Secure default: forwarding disabled"))
        db.commit()

def _config(row: sqlite3.Row) -> dict[str,Any]:
    result=dict(row); result["enabled"]=bool(result["enabled"]); result["categories"]=json.loads(result.pop("categories_json")); result["fields"]=json.loads(result.pop("fields_json")); result["destination_configured"]=bool(RAPID7_WEBHOOK_URL); return result

def get_config() -> dict[str,Any]:
    init_rapid7_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; return _config(db.execute("SELECT * FROM rapid7_config WHERE id=1").fetchone())

def update_config(enabled: bool, categories: list[str], fields: list[str], actor: str, reason: str) -> dict[str,Any]:
    reason=reason.strip(); categories=sorted({str(x).strip() for x in categories if str(x).strip()}); fields=sorted({str(x).strip() for x in fields if str(x).strip()})
    if not reason: raise ValueError("A configuration change reason is required")
    if not categories: raise ValueError("At least one event category is required")
    if not fields or "event_id" not in fields or "timestamp" not in fields: raise ValueError("Field allowlist must include event_id and timestamp")
    if any(any(term in field.casefold() for term in PROHIBITED) for field in fields): raise ValueError("Prompt, response, transcript, attachment, evidence, query, and content fields are prohibited")
    if enabled and not RAPID7_WEBHOOK_URL: raise ValueError("Rapid7 destination secret is not configured")
    init_rapid7_db()
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("UPDATE rapid7_config SET enabled=?,categories_json=?,fields_json=?,updated_at=?,updated_by=?,change_reason=? WHERE id=1",
            (int(enabled),json.dumps(categories),json.dumps(fields),_now(),actor,reason)); db.commit()
    return get_config()

def category_for(action: str, object_type: str="") -> str:
    value=f"{action} {object_type}".casefold()
    if "login" in value or "logout" in value or "session" in value: return "authentication"
    if "denied" in value or "authorization" in value: return "authorization"
    if "policy" in value: return "policy"
    if "case" in value or "investigation" in value: return "case"
    if "alert" in value: return "alert"
    if "delivery" in value or "connector" in value: return "delivery"
    if "system" in value or "worker" in value or "health" in value: return "system"
    return "audit"

def enqueue_audit_event(entry: dict[str,Any]) -> bool:
    config=get_config(); category=category_for(str(entry.get("action") or ""),str(entry.get("object_type") or ""))
    if not config["enabled"] or category not in config["categories"]: return False
    source={"event_id":str(entry.get("entry_hash") or uuid.uuid4()),"timestamp":entry.get("created_at"),"actor":entry.get("actor"),
        "action":entry.get("action"),"object_type":entry.get("object_type"),"object_id":entry.get("object_id"),"source_ip":entry.get("source_ip"),"category":category}
    payload={key:source.get(key) for key in config["fields"] if key in source}
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("INSERT OR IGNORE INTO rapid7_outbox(event_id,created_at,category,payload_json) VALUES(?,?,?,?)",
            (payload["event_id"],_now(),category,json.dumps(payload,separators=(",",":"),sort_keys=True))); db.commit()
    return bool(cur.rowcount)

def _post(payload: dict[str,Any]) -> None:
    parsed=urlparse(RAPID7_WEBHOOK_URL)
    if parsed.scheme!="https" or not parsed.netloc: raise RuntimeError("Rapid7 webhook must use HTTPS")
    body=json.dumps(payload,separators=(",",":"),sort_keys=True).encode(); request=Request(RAPID7_WEBHOOK_URL,data=body,method="POST",headers={"Content-Type":"application/json","User-Agent":"JO-AI-Monitor/0.9"})
    with urlopen(request,timeout=20) as response:
        if response.status>=300: raise RuntimeError(f"Rapid7 returned HTTP {response.status}")

def process_outbox(limit: int=100) -> dict[str,int]:
    init_rapid7_db(); now=datetime.now(timezone.utc); result={"delivered":0,"retrying":0,"failed":0}
    if not get_config()["enabled"]: return result
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; db.execute("BEGIN IMMEDIATE"); rows=db.execute("""SELECT * FROM rapid7_outbox
            WHERE status IN ('pending','retrying') AND (next_attempt_at IS NULL OR next_attempt_at<=?) AND attempts<? ORDER BY id LIMIT ?""",
            (now.isoformat(),MAX_ATTEMPTS,min(max(limit,1),500))).fetchall()
        if rows: db.executemany("UPDATE rapid7_outbox SET status='processing',last_attempt_at=? WHERE id=?",[(now.isoformat(),row["id"]) for row in rows])
        db.commit()
    for raw in rows:
        row=dict(raw); attempt=row["attempts"]+1
        try: _post(json.loads(row["payload_json"])); status="delivered"; error=""; next_attempt=None; delivered=_now(); result["delivered"]+=1
        except Exception as exc:
            final=attempt>=MAX_ATTEMPTS; status="failed" if final else "retrying"; error=str(exc)[:500]; delivered=None
            next_attempt=None if final else (now+timedelta(seconds=min(30*2**(attempt-1),3600))).isoformat(); result[status]+=1
        with _lock, closing(sqlite3.connect(DB_PATH)) as db:
            db.execute("UPDATE rapid7_outbox SET status=?,attempts=?,last_attempt_at=?,next_attempt_at=?,delivered_at=?,last_error=? WHERE id=?",
                (status,attempt,_now(),next_attempt,delivered,error,row["id"])); db.commit()
    return result

def health() -> dict[str,Any]:
    config=get_config()
    with closing(sqlite3.connect(DB_PATH)) as db:
        pending=db.execute("SELECT COUNT(*) FROM rapid7_outbox WHERE status IN ('pending','retrying','processing')").fetchone()[0]
        failed=db.execute("SELECT COUNT(*) FROM rapid7_outbox WHERE status='failed'").fetchone()[0]
        last=db.execute("SELECT delivered_at,last_error FROM rapid7_outbox ORDER BY id DESC LIMIT 1").fetchone()
    return {**config,"pending":pending,"failed":failed,"last_delivered_at":last[0] if last else None,"last_error":last[1] if last else ""}

def preview_event() -> dict[str,Any]:
    config=get_config(); sample={"event_id":"preview-event-id","timestamp":_now(),"actor":"preview-user","action":"rapid7_test","object_type":"configuration","object_id":"rapid7","source_ip":"127.0.0.1","category":"system"}
    return {key:sample[key] for key in config["fields"] if key in sample}

def send_test() -> None:
    if not RAPID7_WEBHOOK_URL: raise ValueError("Rapid7 destination secret is not configured")
    _post(preview_event())
