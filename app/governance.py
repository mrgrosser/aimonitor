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
    try:
        from app.rapid7_export import enqueue_audit_event
        enqueue_audit_event({"entry_hash":digest,"created_at":created,"actor":actor,"action":action,"object_type":object_type,"object_id":object_id,"source_ip":source_ip})
    except Exception:
        pass

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
    controls=policy.get("controls") or {}; user=item.get("user") or {}; groups=[str(x).casefold() for x in (user.get("groups") or item.get("groups") or [])]
    app_request=bool(re.search(str(controls.get("app_generation_pattern") or r"$^"),text,re.I))
    it_values={str(x).casefold() for x in controls.get("it_group_values",[])}
    is_it=bool(it_values.intersection(groups)) or str(user.get("department") or item.get("business_unit") or "").casefold() in it_values
    approved=bool(item.get("approval_id") or item.get("approved_workflow"))
    if app_request and controls.get("only_it_can_generate_apps",True) and not is_it:
        score+=60; factors.append({"id":"unauthorized_app_generation","points":60})
    if app_request and controls.get("app_generation_requires_approval",True) and not approved:
        score+=40; factors.append({"id":"app_generation_without_approval","points":40})
    now=datetime.now(timezone.utc); exception=None
    for candidate in policy.get("exceptions") or []:
        expires=candidate.get("expires_at")
        if expires:
            expires_at=datetime.fromisoformat(expires.replace("Z","+00:00"))
            if expires_at.tzinfo is None: expires_at=expires_at.replace(tzinfo=timezone.utc)
            if expires_at<=now: continue
        value=str(candidate.get("value") or "").casefold(); kind=candidate.get("type")
        matched=(kind=="user" and value in {str(user.get("id") or "").casefold(),str(user.get("email") or "").casefold()})
        matched=matched or (kind=="group" and value in groups) or (kind=="surface" and value==str(item.get("surface") or "").casefold())
        matched=matched or (kind=="workflow" and value==str(item.get("workflow") or "").casefold())
        if matched: exception=candidate; break
    threshold=policy["finding_threshold"]
    context={"provider":item.get("provider"),"surface":item.get("surface"),"business_unit":item.get("business_unit") or user.get("department"),"category":item.get("category")}
    matching=[]
    for scope in policy.get("scope_overrides") or []:
        if all(not scope.get(key) or str(scope[key]).casefold()==str(context.get(key) or "").casefold() for key in context): matching.append(scope)
    if matching: threshold=max(int(scope["finding_threshold"]) for scope in matching)
    score=min(score,100); severity="critical" if score>=bands["critical"] else "high" if score>=bands["high"] else "medium" if score>=bands["medium"] else "low" if score>=bands["low"] else "informational"
    item.update(risk=severity,risk_score=score,risk_factors=factors,risk_rule_version=policy["version"],risk_threshold=threshold,
        risk_scope_ids=[scope["id"] for scope in matching],policy_exception_id=exception.get("id") if exception else None,
        promoted=score>=threshold and exception is None)
    return item

def record_suppressed(item: dict[str,Any], provider: str) -> None:
    init_db(); user=item.get("user") or {}; reason="below_finding_threshold"
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT OR REPLACE INTO suppressed_evidence(evidence_id,observed_at,provider,user_id,surface,risk_score,reason,rule_version) VALUES(?,?,?,?,?,?,?,?)",
            (item.get("id"),datetime.now(timezone.utc).isoformat(),provider,user.get("id") or user.get("email"),item.get("surface"),item.get("risk_score",0),reason,item.get("risk_rule_version","unknown")))

def suppressed_count() -> int:
    init_db()
    with sqlite3.connect(DB_PATH) as db: return db.execute("SELECT COUNT(*) FROM suppressed_evidence").fetchone()[0]
