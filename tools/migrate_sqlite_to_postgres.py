"""Copy an offline SQLite database into an EMPTY PostgreSQL application database.

Reads the source through a consistent read-only transaction, copies all tables in
foreign-key order, verifies every copied value, and commits the data atomically.
Attachments remain on the existing /data volume and are not moved by this tool.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import psycopg
from psycopg import sql
from app import database, schema

METADATA_TABLES = {'schema_migrations', 'sqlite_migrations'}


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def digest_rows(rows):
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        digest.update(json.dumps(list(row), ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        digest.update(b'\n')
        count += 1
    return count, digest.hexdigest()


def source_tables(source):
    tables = [row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    for table in tables:
        if not table.replace('_', '').isalnum(): raise ValueError('Unsupported source table name')
    return tables


def verify_source(source):
    if [row[0] for row in source.execute('PRAGMA integrity_check')] != ['ok']:
        raise ValueError('SQLite integrity check failed; source was not modified')
    if source.execute('PRAGMA foreign_key_check').fetchone():
        raise ValueError('SQLite has foreign-key violations; resolve them before migration')
    if 'audit_log' in source_tables(source):
        previous = 'GENESIS'
        for row in source.execute('SELECT created_at,actor,action,object_type,object_id,source_ip,user_agent,details,previous_hash,entry_hash FROM audit_log ORDER BY id'):
            expected = hashlib.sha256('|'.join(str(value or '') for value in row[:9]).encode()).hexdigest()
            if row[8] != previous or row[9] != expected:
                raise ValueError('SQLite audit chain verification failed')
            previous = row[9]


def table_order(target, tables):
    dependencies = {table: set() for table in tables}
    for child, parent in target.execute("""SELECT child.relname,parent.relname
        FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
        JOIN pg_class parent ON parent.oid=c.confrelid
        JOIN pg_namespace n ON child.relnamespace=n.oid
        WHERE c.contype='f' AND n.nspname=current_schema()"""):
        if child in dependencies and parent in dependencies and child != parent:
            dependencies[child].add(parent)
    result = []
    while dependencies:
        ready = sorted(table for table, parents in dependencies.items() if not parents)
        if not ready: raise ValueError('Cyclic source dependencies require a dedicated migration')
        for table in ready:
            result.append(table)
            del dependencies[table]
        for parents in dependencies.values(): parents.difference_update(ready)
    return result


def migrate(source_path, check_only=False):
    path = Path(source_path).resolve(strict=True)
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as source:
        source.execute('PRAGMA query_only=ON')
        source.execute('BEGIN')
        verify_source(source)
        tables = source_tables(source)
        if not tables: raise ValueError('Source contains no application tables')
        if check_only:
            return {'verified': True, 'tables': {name: source.execute('SELECT COUNT(*) FROM '+quote(name)).fetchone()[0] for name in tables}}
        if not database.is_postgres(): raise ValueError('Configure PostgreSQL before migrating')
        schema.initialize(seed=False)
        with psycopg.connect(database.connection_info()) as target:
            target.execute('SELECT pg_advisory_xact_lock(74193002)')
            target_tables = {r[0] for r in target.execute("SELECT tablename FROM pg_tables WHERE schemaname=current_schema()")}
            unknown = set(tables) - (target_tables - METADATA_TABLES)
            if unknown: raise ValueError('Unrecognized source tables: '+', '.join(sorted(unknown)))
            # Refuse even seeded data. Run migration before starting the application.
            for table in sorted(target_tables - {'schema_migrations'}):
                if target.execute(sql.SQL('SELECT 1 FROM {} LIMIT 1').format(sql.Identifier(table))).fetchone():
                    raise ValueError('Destination is not empty; refusing to overwrite existing PostgreSQL data')
            counts = {}
            manifest = hashlib.sha256()
            for table in table_order(target, tables):
                info = list(source.execute('PRAGMA table_info('+quote(table)+')'))
                columns = [row[1] for row in info]
                keys = [row[1] for row in sorted(info, key=lambda row: row[5]) if row[5]]
                if not keys: raise ValueError('Source table has no primary key: '+table)
                target_columns = {row[0] for row in target.execute('SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s',(table,))}
                if set(columns) - target_columns: raise ValueError('Unsupported columns in '+table)
                names = ','.join(quote(name) for name in columns)
                text_keys = {row[1] for row in info if 'TEXT' in row[2].upper() or 'CHAR' in row[2].upper()}
                order = ','.join(quote(name)+(' COLLATE BINARY' if name in text_keys else '') for name in keys)
                statement = 'SELECT '+names+' FROM '+quote(table)+' ORDER BY '+order
                with target.cursor() as cursor:
                    with cursor.copy(sql.SQL('COPY {} ({}) FROM STDIN').format(sql.Identifier(table), sql.SQL(',').join(map(sql.Identifier, columns)))) as copy:
                        for row in source.execute(statement): copy.write_row(row)
                source_count, source_hash = digest_rows(source.execute(statement))
                target_statement = sql.SQL('SELECT {} FROM {} ORDER BY {}').format(
                    sql.SQL(',').join(map(sql.Identifier, columns)), sql.Identifier(table), sql.SQL(',').join(sql.SQL('{} COLLATE "C"').format(sql.Identifier(name)) if name in text_keys else sql.Identifier(name) for name in keys))
                # A named cursor streams the verification rather than loading the table.
                with target.cursor(name='verify_'+table) as cursor:
                    cursor.execute(target_statement)
                    target_count, target_hash = digest_rows(cursor)
                if (source_count, source_hash) != (target_count, target_hash):
                    raise ValueError('Data verification failed for '+table)
                counts[table] = source_count
                manifest.update((table+':'+source_hash+'\n').encode())
                for column in target.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s AND is_identity='YES'",(table,)).fetchall():
                    sequence = target.execute('SELECT pg_get_serial_sequence(%s,%s)',(table,column[0])).fetchone()[0]
                    maximum = target.execute(sql.SQL('SELECT MAX({}) FROM {}').format(sql.Identifier(column[0]),sql.Identifier(table))).fetchone()[0]
                    target.execute('SELECT setval(%s,%s,%s)',(sequence, maximum or 1, maximum is not None))
            target.execute('CREATE TABLE IF NOT EXISTS sqlite_migrations (source_sha256 TEXT PRIMARY KEY, completed_at TEXT NOT NULL, row_counts_json TEXT NOT NULL)')
            fingerprint = manifest.hexdigest()
            target.execute('INSERT INTO sqlite_migrations VALUES (%s,%s,%s)',(fingerprint,datetime.now(timezone.utc).isoformat(),json.dumps(counts,sort_keys=True)))
            # psycopg commits only after every table and value has been verified.
        return {'verified': True, 'source_sha256': fingerprint, 'tables': counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='Path to existing SQLite database (read-only)')
    parser.add_argument('--check-only', action='store_true', help='Verify source integrity and print counts without writing PostgreSQL')
    args = parser.parse_args()
    try:
        print(json.dumps(migrate(args.source,args.check_only),indent=2,sort_keys=True))
    except (ValueError, OSError, sqlite3.Error, psycopg.Error) as exc:
        # Driver exception text can include connection details or source values.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        parser.exit(1, 'Migration failed: '+message+'\n')
    finally:
        database.close_pool()


if __name__ == '__main__': main()
