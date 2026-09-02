import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any

from app.governance import DB_PATH

# Promoted evidence is retained for this many days; 0 disables pruning. Case snapshots and
# legal holds live in their own tables and are never touched by pruning.
RETENTION_DAYS = max(0, int(os.getenv("FINDING_RETENTION_DAYS", "180")))


def _now() -> str: return datetime.now(timezone.utc).isoformat()


def init_finding_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, provider TEXT NOT NULL, surface TEXT, user_id TEXT, user_email TEXT,
            title TEXT, created_at TEXT, updated_at TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
            risk TEXT NOT NULL, risk_score INTEGER NOT NULL, policy_version TEXT NOT NULL,
            promoted INTEGER NOT NULL DEFAULT 1, evidence_json TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at)")
        db.commit()


def upsert_finding(item: dict[str, Any], provider: str) -> bool:
    """Store a scored, promoted finding. Returns True when the finding is new."""
    init_finding_db(); user=item.get("user") or {}; now=_now()
    with closing(sqlite3.connect(DB_PATH)) as db:
        row=db.execute("SELECT first_seen_at FROM findings WHERE id=?",(item.get("id"),)).fetchone()
        db.execute("""INSERT OR REPLACE INTO findings(id,provider,surface,user_id,user_email,title,created_at,updated_at,
            first_seen_at,last_seen_at,risk,risk_score,policy_version,promoted,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
            (item.get("id"),provider,item.get("surface"),user.get("id"),user.get("email"),item.get("title"),
             item.get("created_at"),item.get("updated_at"),row[0] if row else now,now,item.get("risk"),
             int(item.get("risk_score") or 0),item.get("risk_rule_version") or "unknown",json.dumps(item,separators=(",",":"))))
        db.commit()
    return row is None


def delete_finding(finding_id: str) -> None:
    init_finding_db()
    with closing(sqlite3.connect(DB_PATH)) as db: db.execute("DELETE FROM findings WHERE id=?",(finding_id,)); db.commit()


def get_finding(finding_id: str) -> dict[str, Any] | None:
    init_finding_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        row=db.execute("SELECT evidence_json FROM findings WHERE id=?",(finding_id,)).fetchone()
    return json.loads(row[0]) if row else None


def list_findings() -> list[dict[str, Any]]:
    init_finding_db()
    with closing(sqlite3.connect(DB_PATH)) as db:
        rows=db.execute("SELECT evidence_json FROM findings WHERE promoted=1 ORDER BY created_at DESC").fetchall()
    return [json.loads(x[0]) for x in rows]


def known_versions() -> dict[str, tuple[str, str]]:
    """Provider item id -> (provider updated_at, policy version) across stored findings and
    suppressed metadata, so the sync only rehydrates new or changed evidence."""
    init_finding_db(); result: dict[str, tuple[str, str]] = {}
    with closing(sqlite3.connect(DB_PATH)) as db:
        for id_,updated,version in db.execute("SELECT id,updated_at,policy_version FROM findings"): result[id_]=(updated or "",version)
        try:
            for id_,updated,version in db.execute("SELECT evidence_id,updated_at,rule_version FROM suppressed_evidence"): result.setdefault(id_,(updated or "",version))
        except sqlite3.OperationalError: pass
    return result


def touch_seen(ids: list[str]) -> None:
    if not ids: return
    init_finding_db(); now=_now()
    with closing(sqlite3.connect(DB_PATH)) as db:
        for start in range(0,len(ids),500):
            chunk=ids[start:start+500]
            db.execute(f"UPDATE findings SET last_seen_at=? WHERE id IN ({','.join('?'*len(chunk))})",[now,*chunk])
        db.commit()


def prune_findings(retention_days: int | None = None) -> int:
    days=RETENTION_DAYS if retention_days is None else retention_days
    if not days: return 0
    init_finding_db(); cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as db:
        cur=db.execute("DELETE FROM findings WHERE first_seen_at<?",(cutoff,)); db.commit()
    return cur.rowcount


def rescore_findings() -> dict[str, int]:
    """Re-evaluate every stored finding against the active policy. Findings that fall below
    the threshold move to suppressed metadata and their retained evidence is deleted."""
    from app.governance import record_suppressed, score_evidence
    counts={"rescored":0,"suppressed":0}
    for item in list_findings():
        provider="m365" if item.get("kind")=="copilot" else "anthropic"
        score_evidence(item)
        if item["promoted"]: upsert_finding(item,provider); counts["rescored"]+=1
        else: record_suppressed(item,provider); delete_finding(str(item.get("id"))); counts["suppressed"]+=1
    return counts
