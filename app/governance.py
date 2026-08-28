import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("DATABASE_PATH", "data/jo-ai-monitor.db"))
FINDING_THRESHOLD = max(0, min(int(os.getenv("RISK_FINDING_THRESHOLD", "40")), 100))
_lock = threading.Lock()

RULES = [
    ("unauthorized_access", 45, r"\b(hack|unauthorized|bypass|break into|gain access|root access|privilege escalat\w*)\b"),
    ("evasion", 20, r"\b(without (?:the )?(?:admin|owner|security).{0,20}(?:knowing|noticing)|hide (?:my|the) (?:tracks|activity)|evade detection|cover (?:my|the) tracks)\b"),
    ("credential_exposure", 25, r"\b(passwords?|api[- ]?keys?|access tokens?|private keys?|aws credentials?|secrets?)\b"),
    ("production_target", 15, r"\b(prod(?:uction)?|live server|customer environment)\b"),
    ("data_exfiltration", 25, r"\b(exfiltrat\w*|steal|bundle them|upload.{0,20}(?:external|personal)|send.{0,20}(?:outside|personal))\b"),
    ("regulated_or_personal_data", 20, r"\b(ssn|social security|credit card|patient|medical record|phi|pii|personal data)\b"),
    ("confidential_information", 40, r"\b(confidential|trade secret|proprietary|customer records?|source code)\b"),
    ("malware_or_exploit", 30, r"\b(ransomware|malware|keylogger|reverse shell|zero[- ]day|exploit code|payload)\b"),
    ("destructive_action", 25, r"\b(delete all|wipe|destroy|encrypt all|drop database|disable logging)\b"),
]

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, object_type TEXT,
            object_id TEXT, source_ip TEXT, user_agent TEXT, details TEXT,
            previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE)""")
        db.execute("""CREATE TABLE IF NOT EXISTS suppressed_evidence (
            evidence_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, provider TEXT,
            user_id TEXT, surface TEXT, risk_score INTEGER NOT NULL,
            reason TEXT NOT NULL, rule_version TEXT NOT NULL)""")

def audit(actor: str, action: str, object_type: str = "", object_id: str = "",
          source_ip: str = "", user_agent: str = "", details: dict[str, Any] | None = None) -> None:
    init_db(); created=datetime.now(timezone.utc).isoformat(); detail=json.dumps(details or {},sort_keys=True,separators=(",",":"))
    with _lock, sqlite3.connect(DB_PATH) as db:
        row=db.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone(); previous=row[0] if row else "GENESIS"
        canonical="|".join((created,actor,action,object_type,object_id,source_ip,user_agent,detail,previous))
        digest=hashlib.sha256(canonical.encode()).hexdigest()
        db.execute("INSERT INTO audit_log(created_at,actor,action,object_type,object_id,source_ip,user_agent,details,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (created,actor,action,object_type,object_id,source_ip,user_agent,detail,previous,digest))

def read_audit(limit: int = 200, actor: str = "", action: str = "") -> list[dict[str,Any]]:
    init_db(); where=[]; params=[]
    if actor: where.append("actor=?"); params.append(actor)
    if action: where.append("action=?"); params.append(action)
    sql="SELECT id,created_at,actor,action,object_type,object_id,source_ip,user_agent,details,previous_hash,entry_hash FROM audit_log"
    if where: sql+=" WHERE "+" AND ".join(where)
    sql+=" ORDER BY id DESC LIMIT ?"; params.append(min(max(limit,1),1000))
    with sqlite3.connect(DB_PATH) as db:
        rows=db.execute(sql,params).fetchall()
    keys=("id","created_at","actor","action","object_type","object_id","source_ip","user_agent","details","previous_hash","entry_hash")
    return [{**dict(zip(keys,r)),"details":json.loads(r[8])} for r in rows]

def verify_chain() -> bool:
    init_db()
    with sqlite3.connect(DB_PATH) as db: rows=db.execute("SELECT created_at,actor,action,object_type,object_id,source_ip,user_agent,details,previous_hash,entry_hash FROM audit_log ORDER BY id").fetchall()
    previous="GENESIS"
    for r in rows:
        if r[8]!=previous: return False
        canonical="|".join(str(x or "") for x in (*r[:8],r[8])); digest=hashlib.sha256(canonical.encode()).hexdigest()
        if digest!=r[9]: return False
        previous=r[9]
    return True

def score_evidence(item: dict[str,Any]) -> dict[str,Any]:
    from app.policy_management import active_policy
    policy=active_policy(); rules=policy["rules"]; bands=policy["severity_bands"]
    parts=[item.get("title",""),item.get("summary","")]
    for msg in item.get("messages",[]) or []: parts.append(str(msg.get("text") or msg.get("content") or ""))
    for ctx in item.get("contexts",[]) or []: parts.extend((str(ctx.get("displayName","")),str(ctx.get("contextType",""))))
    text=" ".join(parts).lower(); factors=[]; score=0
    for rule in rules:
        if rule.get("enabled",True) and re.search(rule["pattern"],text,re.I):
            score+=int(rule["points"]); factors.append({"id":rule["id"],"points":int(rule["points"])})
    score=min(score,100); severity="critical" if score>=bands["critical"] else "high" if score>=bands["high"] else "medium" if score>=bands["medium"] else "low" if score>=bands["low"] else "informational"
    item.update(risk=severity,risk_score=score,risk_factors=factors,risk_rule_version=policy["version"],promoted=score>=policy["finding_threshold"])
    return item

def record_suppressed(item: dict[str,Any], provider: str) -> None:
    init_db(); user=item.get("user") or {}; reason="below_finding_threshold"
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT OR REPLACE INTO suppressed_evidence(evidence_id,observed_at,provider,user_id,surface,risk_score,reason,rule_version) VALUES(?,?,?,?,?,?,?,?)",
            (item.get("id"),datetime.now(timezone.utc).isoformat(),provider,user.get("id") or user.get("email"),item.get("surface"),item.get("risk_score",0),reason,item.get("risk_rule_version","unknown")))

def suppressed_count() -> int:
    init_db()
    with sqlite3.connect(DB_PATH) as db: return db.execute("SELECT COUNT(*) FROM suppressed_evidence").fetchone()[0]
