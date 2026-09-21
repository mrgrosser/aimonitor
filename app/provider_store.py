"""Durable last-successful provider views, independent of browser sessions."""
import json
from app import database as db_backend
from contextlib import contextmanager, closing
from datetime import datetime, timezone
from app import governance


@db_backend.initialize_once
def init_provider_db():
    with closing(db_backend.connect(governance.DB_PATH)) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS provider_views (
            name TEXT PRIMARY KEY, payload TEXT NOT NULL, collected_at TEXT, error TEXT)""")
        db.commit()


@contextmanager
def database():
    init_provider_db()
    with closing(db_backend.connect(governance.DB_PATH)) as db:
        yield db
        db.commit()


def read(name):
    with database() as db:
        row = db.execute("SELECT payload,collected_at,error FROM provider_views WHERE name=?", (name,)).fetchone()
    if not row:
        return {"data": [], "sync": {"state": "pending", "last_success_at": None}}
    payload, collected, error = row
    return {**{"data": [], **json.loads(payload)}, "sync": {
        "state": "failed" if error else "ok", "last_success_at": collected, "error": error}}


def save(name, payload):
    with database() as db:
        db.execute("""INSERT INTO provider_views VALUES (?,?,?,NULL)
            ON CONFLICT (name) DO UPDATE SET
                payload=excluded.payload,collected_at=excluded.collected_at,error=excluded.error""",
                   (name, json.dumps(payload), datetime.now(timezone.utc).isoformat()))


def fail(name):
    with database() as db:
        db.execute("""INSERT INTO provider_views VALUES (?, '{}', NULL, ?)

            ON CONFLICT(name) DO UPDATE SET
                error=excluded.error""",
            (name, "Provider refresh failed; showing last saved data. Check provider credentials and connectivity."))
