import json
import hashlib
import hmac
import os
import smtplib
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any
from urllib.request import Request, urlopen

from app.governance import DB_PATH

_lock=threading.Lock()
STATUSES={"open","acknowledged","suppressed","resolved"}
ESCALATIONS={"none","management","incident_response","legal"}
SMTP_HOST=os.getenv("SMTP_HOST","").strip(); SMTP_PORT=int(os.getenv("SMTP_PORT","587")); SMTP_FROM=os.getenv("SMTP_FROM","").strip()
SMTP_USERNAME=os.getenv("SMTP_USERNAME","").strip(); SMTP_PASSWORD=os.getenv("SMTP_PASSWORD",""); SMTP_TLS=os.getenv("SMTP_TLS","true").lower()=="true"
ALERT_EMAIL_TO=[x.strip() for x in os.getenv("ALERT_EMAIL_TO","").split(",") if x.strip()]
TEAMS_WEBHOOK_URL=os.getenv("TEAMS_WEBHOOK_URL","").strip(); ALERT_WEBHOOK_URL=os.getenv("ALERT_WEBHOOK_URL","").strip()
ALERT_WEBHOOK_SECRET=os.getenv("ALERT_WEBHOOK_SECRET","").encode(); ALERT_PUBLIC_URL=os.getenv("ALERT_PUBLIC_URL","").rstrip("/")
DELIVERY_MAX_ATTEMPTS=max(1,min(int(os.getenv("ALERT_DELIVERY_MAX_ATTEMPTS","5")),20))
PROCESSING_STALE_SECONDS=max(60,int(os.getenv("ALERT_PROCESSING_STALE_SECONDS","600")))

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

def list_deliveries(alert_id: str="", limit: int=200) -> list[dict[str,Any]]:
    init_alert_db(); sql="SELECT * FROM alert_deliveries"; params=[]
    if alert_id: sql+=" WHERE alert_id=?"; params.append(alert_id)
    sql+=" ORDER BY id DESC LIMIT ?"; params.append(min(max(limit,1),1000))
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; return [dict(row) for row in db.execute(sql,params).fetchall()]

def connector_health() -> list[dict[str,Any]]:
    configured={"email":bool(SMTP_HOST and SMTP_FROM and ALERT_EMAIL_TO),"teams":bool(TEAMS_WEBHOOK_URL),"webhook":bool(ALERT_WEBHOOK_URL and ALERT_WEBHOOK_SECRET)}
    init_alert_db(); result=[]
    with closing(sqlite3.connect(DB_PATH)) as db:
        for connector,enabled in configured.items():
            failed=db.execute("SELECT COUNT(*) FROM alert_deliveries WHERE connector=? AND status='failed'",(connector,)).fetchone()[0]
            pending=db.execute("SELECT COUNT(*) FROM alert_deliveries WHERE connector=? AND status IN ('pending','retrying')",(connector,)).fetchone()[0]
            row=db.execute("SELECT delivered_at,last_error FROM alert_deliveries WHERE connector=? ORDER BY id DESC LIMIT 1",(connector,)).fetchone()
            result.append({"id":connector,"configured":enabled,"pending":pending,"failed":failed,"last_delivered_at":row[0] if row else None,"last_error":row[1] if row else ""})
    return result

def _payload(alert: dict[str,Any], delivery: dict[str,Any]) -> dict[str,Any]:
    return {"schema":"jo-ai-monitor.alert.v1","event_id":delivery["idempotency_key"],"alert_id":alert["id"],
        "type":alert["alert_type"],"severity":alert["severity"],"title":alert["title"],"summary":alert["summary"],
        "status":alert["status"],"created_at":alert["created_at"],"url":f"{ALERT_PUBLIC_URL}/#cases" if ALERT_PUBLIC_URL else ""}

def _post_json(url: str, payload: dict[str,Any], headers: dict[str,str] | None=None) -> None:
    body=json.dumps(payload,separators=(",",":"),sort_keys=True).encode(); request=Request(url,data=body,method="POST",headers={"Content-Type":"application/json",**(headers or {})})
    with urlopen(request,timeout=20) as response:
        if response.status>=300: raise RuntimeError(f"HTTP {response.status}")

def _deliver(connector: str, alert: dict[str,Any], delivery: dict[str,Any]) -> None:
    payload=_payload(alert,delivery)
    if connector=="email":
        if not (SMTP_HOST and SMTP_FROM and ALERT_EMAIL_TO): raise RuntimeError("Email alert delivery is not configured")
        message=EmailMessage(); message["From"]=SMTP_FROM; message["To"]=", ".join(ALERT_EMAIL_TO); message["Subject"]=f"[{alert['severity'].upper()}] JO AI Monitor: {alert['title']}"
        message.set_content(f"{alert['summary']}\n\nAlert: {alert['id']}\nStatus: {alert['status']}\n{payload['url']}")
        with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=20) as smtp:
            if SMTP_TLS: smtp.starttls()
            if SMTP_USERNAME: smtp.login(SMTP_USERNAME,SMTP_PASSWORD)
            smtp.send_message(message)
    elif connector=="teams":
        if not TEAMS_WEBHOOK_URL: raise RuntimeError("Teams alert delivery is not configured")
        _post_json(TEAMS_WEBHOOK_URL,{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","weight":"Bolder","text":alert["title"]},{"type":"TextBlock","text":alert["summary"],"wrap":True},{"type":"FactSet","facts":[{"title":"Severity","value":alert["severity"]},{"title":"Alert","value":alert["id"]}]}]}}]},{"X-JO-Event-ID":delivery["idempotency_key"]})
    else:
        if not (ALERT_WEBHOOK_URL and ALERT_WEBHOOK_SECRET): raise RuntimeError("Signed webhook delivery is not configured")
        body=json.dumps(payload,separators=(",",":"),sort_keys=True).encode(); signature=hmac.new(ALERT_WEBHOOK_SECRET,body,hashlib.sha256).hexdigest()
        _post_json(ALERT_WEBHOOK_URL,payload,{"X-JO-Event-ID":delivery["idempotency_key"],"X-JO-Signature-256":f"sha256={signature}"})

def process_deliveries(limit: int=25) -> dict[str,int]:
    init_alert_db(); now=datetime.now(timezone.utc); counts={"delivered":0,"retrying":0,"failed":0}
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        # A row left in 'processing' by a crash or restart is reclaimable once it is stale.
        stale=(now-timedelta(seconds=PROCESSING_STALE_SECONDS)).isoformat()
        db.row_factory=sqlite3.Row; db.execute("BEGIN IMMEDIATE"); rows=db.execute("""SELECT * FROM alert_deliveries WHERE attempts<?
            AND (status IN ('pending','retrying') AND (next_attempt_at IS NULL OR next_attempt_at<=?)
                 OR status='processing' AND last_attempt_at<=?) ORDER BY id LIMIT ?""",(DELIVERY_MAX_ATTEMPTS,now.isoformat(),stale,min(max(limit,1),100))).fetchall()
        if rows: db.executemany("UPDATE alert_deliveries SET status='processing',last_attempt_at=? WHERE id=?",[(now.isoformat(),row["id"]) for row in rows])
        db.commit()
    for raw in rows:
        delivery=dict(raw); attempt=delivery["attempts"]+1
        try:
            _deliver(delivery["connector"],get_alert(delivery["alert_id"]),delivery); status="delivered"; error=""; delivered_at=_now(); next_attempt=None; counts["delivered"]+=1
        except Exception as exc:
            final=attempt>=DELIVERY_MAX_ATTEMPTS; status="failed" if final else "retrying"; error=str(exc)[:500]; delivered_at=None
            next_attempt=None if final else (now+timedelta(seconds=min(30*(2**(attempt-1)),3600))).isoformat(); counts[status]+=1
        with _lock, closing(sqlite3.connect(DB_PATH)) as db:
            db.execute("UPDATE alert_deliveries SET status=?,attempts=?,last_attempt_at=?,next_attempt_at=?,last_error=?,delivered_at=? WHERE id=?",
                (status,attempt,_now(),next_attempt,error,delivered_at,delivery["id"])); db.commit()
    return counts
