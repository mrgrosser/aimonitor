import json
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from app.governance import DB_PATH, FINDING_THRESHOLD, RULES

_lock = threading.Lock()
_cache: dict[str, Any] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_policy() -> dict[str, Any]:
    return {
        "version":"rules-2026.08.2","name":"JO AI Monitor baseline","description":"Initial deterministic detection policy.",
        "finding_threshold":FINDING_THRESHOLD,"severity_bands":{"critical":80,"high":60,"medium":40,"low":20},
        "rules":[{"id":name,"points":points,"pattern":pattern,"enabled":True} for name,points,pattern in RULES],
        "scope_overrides":[], "exceptions":[],
        "controls":{"only_it_can_generate_apps":True,"app_generation_requires_approval":True,
            "it_group_values":["IT","Information Technology"],
            "app_generation_pattern":r"\b(build|create|generate|scaffold|vibe[- ]?code)\b.{0,80}\b(app|application|website|service|script|code)\b"},
    }


def init_policy_db() -> None:
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS detection_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            description TEXT NOT NULL, status TEXT NOT NULL, finding_threshold INTEGER NOT NULL,
            severity_bands_json TEXT NOT NULL, rules_json TEXT NOT NULL, created_at TEXT NOT NULL,
            created_by TEXT NOT NULL, approved_at TEXT, approved_by TEXT, activated_at TEXT,
            activated_by TEXT, previous_active_id INTEGER, change_reason TEXT NOT NULL DEFAULT '',
            scope_overrides_json TEXT NOT NULL DEFAULT '[]', exceptions_json TEXT NOT NULL DEFAULT '[]',
            controls_json TEXT NOT NULL DEFAULT '{}')""")
        columns={row[1] for row in db.execute("PRAGMA table_info(detection_policies)").fetchall()}
        for name,default in (("scope_overrides_json","'[]'"),("exceptions_json","'[]'"),("controls_json","'{}'")):
            if name not in columns: db.execute(f"ALTER TABLE detection_policies ADD COLUMN {name} TEXT NOT NULL DEFAULT {default}")
        if not db.execute("SELECT 1 FROM detection_policies LIMIT 1").fetchone():
            policy=_default_policy(); now=_now()
            db.execute("""INSERT INTO detection_policies(version,name,description,status,finding_threshold,
                severity_bands_json,rules_json,created_at,created_by,approved_at,approved_by,activated_at,activated_by,change_reason,
                scope_overrides_json,exceptions_json,controls_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(policy["version"],policy["name"],policy["description"],"active",
                policy["finding_threshold"],json.dumps(policy["severity_bands"],sort_keys=True),json.dumps(policy["rules"],sort_keys=True),
                now,"system",now,"system",now,"system","Seeded current production-equivalent baseline",
                json.dumps(policy["scope_overrides"]),json.dumps(policy["exceptions"]),json.dumps(policy["controls"],sort_keys=True)))
        db.commit()


def _row(row: sqlite3.Row) -> dict[str, Any]:
    result=dict(row); defaults=_default_policy()
    result["rules"]=json.loads(result.pop("rules_json")); result["severity_bands"]=json.loads(result.pop("severity_bands_json"))
    for key in ("scope_overrides","exceptions","controls"):
        result[key]=json.loads(result.pop(f"{key}_json","") or json.dumps(defaults[key]))
    if not result["controls"]: result["controls"]=defaults["controls"]
    return result


def list_policies() -> list[dict[str, Any]]:
    init_policy_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; rows=db.execute("SELECT * FROM detection_policies ORDER BY id DESC").fetchall()
    return [_row(x) for x in rows]


def get_policy(policy_id: int) -> dict[str, Any]:
    init_policy_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM detection_policies WHERE id=?",(policy_id,)).fetchone()
    if not row: raise ValueError("Policy not found")
    return _row(row)


def active_policy() -> dict[str, Any]:
    global _cache
    if _cache is not None: return _cache
    init_policy_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory=sqlite3.Row; row=db.execute("SELECT * FROM detection_policies WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
    _cache=_row(row) if row else _default_policy()
    return _cache


def _validate(payload: dict[str, Any]) -> dict[str, Any]:
    threshold=max(0,min(int(payload.get("finding_threshold",40)),100)); rules=payload.get("rules") or []
    if not rules: raise ValueError("At least one detection rule is required")
    seen=set(); normalized=[]
    for rule in rules:
        rule_id=str(rule.get("id") or "").strip()
        if not rule_id or rule_id in seen: raise ValueError("Rule IDs must be present and unique")
        seen.add(rule_id); pattern=str(rule.get("pattern") or "")
        try: re.compile(pattern,re.I)
        except re.error as exc: raise ValueError(f"Invalid regular expression for {rule_id}: {exc}") from exc
        normalized.append({"id":rule_id,"points":max(0,min(int(rule.get("points",0)),100)),"pattern":pattern,"enabled":bool(rule.get("enabled",True))})
    bands={k:int(v) for k,v in (payload.get("severity_bands") or {"critical":80,"high":60,"medium":40,"low":20}).items()}
    if not (100>=bands.get("critical",80)>bands.get("high",60)>bands.get("medium",40)>bands.get("low",20)>=0):
        raise ValueError("Severity bands must descend from critical to low")
    scopes=[]
    for index,scope in enumerate(payload.get("scope_overrides") or []):
        match={k:str(scope.get(k) or "").strip() for k in ("provider","surface","business_unit","category")}
        if not any(match.values()): raise ValueError("Each scope override requires at least one matcher")
        scopes.append({"id":str(scope.get("id") or f"scope-{index+1}"),**match,
            "finding_threshold":max(0,min(int(scope.get("finding_threshold",threshold)),100))})
    exceptions=[]
    for index,exception in enumerate(payload.get("exceptions") or []):
        kind=str(exception.get("type") or "").strip(); value=str(exception.get("value") or "").strip()
        if kind not in {"user","group","surface","workflow"} or not value: raise ValueError("Exceptions require a user, group, surface, or workflow value")
        expires=str(exception.get("expires_at") or "").strip()
        if expires:
            try: datetime.fromisoformat(expires.replace("Z","+00:00"))
            except ValueError as exc: raise ValueError("Exception expiration must be ISO-8601") from exc
        reason=str(exception.get("reason") or "").strip(); approver=str(exception.get("approved_by") or "").strip()
        if not reason or not approver: raise ValueError("Exceptions require a reason and approving identity")
        exceptions.append({"id":str(exception.get("id") or f"exception-{index+1}"),"type":kind,"value":value,
            "expires_at":expires,"reason":reason,"approved_by":approver})
    controls={**_default_policy()["controls"],**(payload.get("controls") or {})}
    try: re.compile(str(controls["app_generation_pattern"]),re.I)
    except re.error as exc: raise ValueError(f"Invalid app-generation pattern: {exc}") from exc
    controls["it_group_values"]=[str(x).strip() for x in controls.get("it_group_values",[]) if str(x).strip()]
    return {"finding_threshold":threshold,"rules":normalized,"severity_bands":bands,"scope_overrides":scopes,"exceptions":exceptions,"controls":controls}


def create_draft(version: str, name: str, description: str, actor: str) -> dict[str, Any]:
    base=active_policy(); version=version.strip(); name=name.strip()
    if not version or not name: raise ValueError("Version and name are required")
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        try:
            cur=db.execute("""INSERT INTO detection_policies(version,name,description,status,finding_threshold,severity_bands_json,
                rules_json,created_at,created_by,previous_active_id,change_reason,scope_overrides_json,exceptions_json,controls_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (version,name,description.strip(),"draft",base["finding_threshold"],json.dumps(base["severity_bands"],sort_keys=True),
                json.dumps(base["rules"],sort_keys=True),_now(),actor,base.get("id"),"Drafted from active policy",
                json.dumps(base["scope_overrides"]),json.dumps(base["exceptions"]),json.dumps(base["controls"],sort_keys=True))); db.commit()
        except sqlite3.IntegrityError as exc: raise ValueError("Policy version already exists") from exc
    return get_policy(cur.lastrowid)


def update_draft(policy_id: int, payload: dict[str, Any], actor: str, reason: str) -> dict[str, Any]:
    current=get_policy(policy_id)
    if current["status"]!="draft": raise ValueError("Only draft policies can be edited")
    valid=_validate(payload)
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""UPDATE detection_policies SET name=?,description=?,finding_threshold=?,severity_bands_json=?,rules_json=?,
            scope_overrides_json=?,exceptions_json=?,controls_json=?,approved_at=NULL,approved_by=NULL,change_reason=? WHERE id=?""",(str(payload.get("name") or current["name"]).strip(),
            str(payload.get("description",current["description"])).strip(),valid["finding_threshold"],json.dumps(valid["severity_bands"],sort_keys=True),
            json.dumps(valid["rules"],sort_keys=True),json.dumps(valid["scope_overrides"]),json.dumps(valid["exceptions"]),json.dumps(valid["controls"],sort_keys=True),reason.strip(),policy_id)); db.commit()
    return get_policy(policy_id)


def approve_policy(policy_id: int, actor: str, reason: str) -> dict[str, Any]:
    policy=get_policy(policy_id)
    if policy["status"]!="draft": raise ValueError("Only draft policies can be approved")
    if actor==policy["created_by"]: raise ValueError("Policy approval requires a different person than the draft creator")
    if not reason.strip(): raise ValueError("Approval reason is required")
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("UPDATE detection_policies SET status='approved',approved_at=?,approved_by=?,change_reason=? WHERE id=?",(_now(),actor,reason.strip(),policy_id)); db.commit()
    return get_policy(policy_id)


def activate_policy(policy_id: int, actor: str, reason: str) -> dict[str, Any]:
    global _cache
    policy=get_policy(policy_id)
    if policy["status"] not in {"approved","retired"}: raise ValueError("Policy must be approved before activation")
    if policy.get("approved_by")==actor: raise ValueError("Policy activation requires a different person than the approver")
    if not reason.strip(): raise ValueError("Activation reason is required")
    with _lock, closing(sqlite3.connect(DB_PATH)) as db:
        active=db.execute("SELECT id FROM detection_policies WHERE status='active' LIMIT 1").fetchone(); previous=active[0] if active else None
        db.execute("UPDATE detection_policies SET status='retired' WHERE status='active'")
        db.execute("UPDATE detection_policies SET status='active',activated_at=?,activated_by=?,previous_active_id=?,change_reason=? WHERE id=?",(_now(),actor,previous,reason.strip(),policy_id)); db.commit(); _cache=None
    return get_policy(policy_id)


def rollback_policy(actor: str, reason: str) -> dict[str, Any]:
    current=active_policy(); target=current.get("previous_active_id")
    if not target: raise ValueError("No previous active policy is available")
    return activate_policy(int(target),actor,reason)
