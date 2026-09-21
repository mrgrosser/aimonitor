"""PostgreSQL connection pooling; SQLite is limited to offline demo/tests.

Application SQL uses portable ON CONFLICT/RETURNING and qmark parameters.
Only parameter style and generated identity syntax differ between backends.
"""
import atexit
from contextlib import closing, contextmanager
from contextvars import ContextVar
from functools import wraps
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import threading

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

Row = sqlite3.Row
Error = (sqlite3.Error, psycopg.Error)
IntegrityError = (sqlite3.IntegrityError, psycopg.IntegrityError)
OperationalError = (sqlite3.OperationalError, psycopg.OperationalError)
_pool = None
_pool_key = None
_pool_lock = threading.RLock()
_schema_lock = threading.RLock()
_initialized = set()
_seed_defaults = ContextVar('seed_defaults', default=True)

def seed_defaults(): return _seed_defaults.get()

@contextmanager
def seeding(enabled):
    token = _seed_defaults.set(enabled)
    try: yield
    finally: _seed_defaults.reset(token)



def connection_info():
    url = os.getenv('DATABASE_URL', '').strip()
    if url:
        if not url.startswith(('postgresql://', 'postgres://')):
            raise RuntimeError('DATABASE_URL must be a PostgreSQL connection URL')
        return url
    if os.getenv('PGHOST'):
        return make_conninfo(host=os.environ['PGHOST'], port=os.getenv('PGPORT', '5432'),
            dbname=os.getenv('PGDATABASE', 'jo_ai_monitor'), user=os.getenv('PGUSER', 'jo_ai_monitor'),
            password=os.getenv('PGPASSWORD', ''), sslmode=os.getenv('PGSSLMODE', 'prefer'))
    if os.getenv('DEMO_MODE', 'true').lower() != 'true':
        raise RuntimeError('Live mode requires PostgreSQL: configure DATABASE_URL or PGHOST/PGDATABASE/PGUSER/PGPASSWORD')
    return ''


def is_postgres():
    return bool(connection_info())


def pool():
    global _pool, _pool_key
    key = connection_info()
    with _pool_lock:
        if _pool is None or key != _pool_key:
            if _pool: _pool.close()
            _pool = ConnectionPool(key, min_size=1,
                max_size=max(4, int(os.getenv('DATABASE_POOL_SIZE', '12'))),
                timeout=30, max_waiting=64, open=True,
                kwargs={'connect_timeout': 10, 'application_name': 'jo-ai-monitor'},
                check=ConnectionPool.check_connection)
            _pool_key = key
        return _pool


def close_pool():
    global _pool, _pool_key
    with _pool_lock:
        if _pool: _pool.close()
        _pool = _pool_key = None
        _initialized.clear()


atexit.register(close_pool)


def initialize_once(function):
    """Run schema setup once per PostgreSQL process, never on its hot paths.

    A database advisory lock also serializes initialization across processes.
    SQLite retains its legacy upgrade behavior for migration fixtures.
    """
    @wraps(function)
    def run(*args, **kwargs):
        key = connection_info()
        if not key: return function(*args, **kwargs)
        identity = (key, function.__module__, function.__name__)
        with _schema_lock:
            if identity in _initialized: return
            with closing(connect()) as guard:
                guard.raw.execute('SELECT pg_advisory_lock(74193001)')
                try:
                    result = function(*args, **kwargs)
                    _initialized.add(identity)
                    return result
                finally:
                    guard.raw.execute('SELECT pg_advisory_unlock(74193001)')
    return run


class Record:
    def __init__(self, names, values):
        self.names, self.values = names, values
    def keys(self): return self.names
    def __getitem__(self, key):
        return self.values[self.names.index(key)] if isinstance(key, str) else self.values[key]
    def __iter__(self): return iter(self.values)
    def __len__(self): return len(self.values)


class Result:
    def __init__(self, cursor, named=False, returning=False):
        self.cursor = cursor
        self.names = [col[0] for col in cursor.description] if cursor.description else []
        self.named = named
        # Consume RETURNING before commit (required by SQLite), and allow callers
        # to read inserted IDs after returning the connection to the pool.
        self.buffer = list(cursor.fetchall()) if returning else None
        self.rowcount = cursor.rowcount
    def _row(self, value):
        return Record(self.names, value) if value is not None and self.named else value
    def fetchone(self):
        row = (self.buffer.pop(0) if self.buffer else None) if self.buffer is not None else self.cursor.fetchone()
        return self._row(row)
    def fetchall(self):
        if self.buffer is None: return [self._row(row) for row in self.cursor.fetchall()]
        rows, self.buffer = self.buffer, []
        return [self._row(row) for row in rows]
    def __iter__(self):
        while (row := self.fetchone()) is not None: yield row


def postgres_sql(statement):
    # Replace placeholders only outside SQL quoted literals/identifiers. Escaped
    # quotes are consumed together; literal percent signs must be escaped for psycopg.
    tokens = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", statement)
    return ''.join(token.replace('%', '%%') if index % 2 else token.replace('%', '%%').replace('?', '%s')
                   for index, token in enumerate(tokens))


class Connection:
    def __init__(self, raw, owner=None):
        self.raw, self.owner = raw, owner
        self.row_factory = None
        self.closed = False
    @property
    def postgres(self): return self.owner is not None
    def execute(self, statement, parameters=()):
        if self.postgres:
            cursor = self.raw.execute(postgres_sql(statement), parameters)
        else:
            statement = statement.replace('INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
            self.raw.row_factory = self.row_factory
            cursor = self.raw.execute(statement, parameters)
        return Result(cursor, self.postgres and self.row_factory is Row,
                      bool(re.search(r'\bRETURNING\b', statement, re.I)))
    def executemany(self, statement, parameters):
        if self.postgres:
            cursor = self.raw.cursor()
            cursor.executemany(postgres_sql(statement), parameters)
        else: cursor = self.raw.executemany(statement, parameters)
        return Result(cursor)
    def columns(self, table):
        if self.postgres:
            return {row[0] for row in self.raw.execute(
                'SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s', (table,))}
        if not re.fullmatch(r'[a-z_]+', table): raise ValueError('Invalid table name')
        return {row[1] for row in self.raw.execute(f'PRAGMA table_info({table})')}
    def lock(self, name):
        if self.postgres:
            key = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], 'big', signed=True)
            self.raw.execute('SELECT pg_advisory_xact_lock(%s)', (key,))
        elif not self.raw.in_transaction:
            self.raw.execute('BEGIN IMMEDIATE')
    def commit(self): self.raw.commit()
    def rollback(self): self.raw.rollback()
    def close(self):
        if self.closed: return
        self.closed = True
        if self.owner:
            try: self.raw.rollback()
            finally: self.owner.putconn(self.raw)
        else: self.raw.close()
    def __enter__(self): return self
    def __exit__(self, kind, value, traceback):
        if kind: self.rollback()
        else: self.commit()


def connect(path=None, timeout=30):
    if connection_info():
        owner = pool()
        return Connection(owner.getconn(), owner)
    path = Path(path or os.getenv('DATABASE_PATH', 'data/jo-ai-monitor.db'))
    path.parent.mkdir(parents=True, exist_ok=True)
    return Connection(sqlite3.connect(path, timeout=timeout))


def require_legacy_migration():
    """Do not let an upgrade silently start with empty PostgreSQL data."""
    source = os.getenv('SQLITE_MIGRATION_SOURCE', '')
    if not source or not is_postgres(): return
    path = Path(source)
    if not path.is_file() or not path.stat().st_size: return
    with closing(connect()) as db:
        exists = db.raw.execute("SELECT to_regclass('sqlite_migrations')").fetchone()[0]
        if exists and db.raw.execute('SELECT 1 FROM sqlite_migrations LIMIT 1').fetchone(): return
    raise RuntimeError('Existing SQLite data requires migration before startup. Run python -m tools.migrate_sqlite_to_postgres --source '+source)
