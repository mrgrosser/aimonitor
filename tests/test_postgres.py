"""Real PostgreSQL integration tests. Set TEST_POSTGRES_URL to a test server.

Every test uses a unique schema, never the server's existing application tables.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import uuid

import psycopg
from psycopg import sql
from app import database, schema, governance, policy_management, finding_store, provider_store


@contextmanager
def isolated_postgres(initialize=True):
    base = os.environ['TEST_POSTGRES_URL']
    name = 'test_' + uuid.uuid4().hex
    with psycopg.connect(base, autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(name)))
    url = base + ('&' if '?' in base else '?') + urlencode({'options': '-csearch_path='+name})
    database.close_pool()
    policy_management._cache = None
    try:
        with patch.dict(os.environ, {'DATABASE_URL': url, 'DEMO_MODE': 'true'}):
            if initialize: schema.initialize()
            yield url
    finally:
        database.close_pool()
        policy_management._cache = None
        with psycopg.connect(base, autocommit=True) as admin:
            admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(name)))


@unittest.skipUnless(os.getenv('TEST_POSTGRES_URL'), 'PostgreSQL integration URL required')
class PostgreSQLTests(unittest.TestCase):
    def setUp(self):
        context = isolated_postgres()
        self.url = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def test_existing_case_alert_reporting_and_policy_workflows(self):
        # Run the established behavioral tests on PostgreSQL as well as SQLite.
        modules = ('test_case_management', 'test_alert_management', 'test_rapid7_export',
                   'test_usage_reporting', 'test_finding_reporting', 'test_copilot_history')
        for name in modules:
            module = importlib.import_module('tests.'+name)
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            for group in suite:
                for test in group:
                    with self.subTest(test=str(test)), isolated_postgres():
                        result = unittest.TestResult()
                        test.run(result)
                        self.assertEqual(result.errors+result.failures, [])

    def test_policy_lifecycle_and_duplicate_versions(self):
        draft=policy_management.create_draft('pg-policy','PostgreSQL policy','scope','author')
        with self.assertRaisesRegex(ValueError,'already exists'):
            policy_management.create_draft('pg-policy','Duplicate','scope','author')
        approved=policy_management.approve_policy(draft['id'],'reviewer','Reviewed')
        self.assertEqual(approved['status'],'approved')
        active=policy_management.activate_policy(draft['id'],'admin','Approved rollout')
        self.assertEqual(active['status'],'active')
        self.assertEqual(policy_management.active_policy()['version'],'pg-policy')

    def test_data_and_session_survive_application_process_restart(self):
        from app import main
        provider_store.save('activities',{'data':[{'id':'survives-restart'}]})
        environment={**os.environ,'SESSION_SECRET':main.SECRET.decode(),
                     'TEST_SESSION_TOKEN':main.make_token('restart-user',{'Compliance.Admin'})}
        code="from unittest.mock import patch\nfrom fastapi.testclient import TestClient\nfrom app import main\nwith patch.object(main,'DEMO',False):\n client=TestClient(main.app)\n client.cookies.set('cm_session',__import__('os').environ['TEST_SESSION_TOKEN'])\n assert client.get('/api/activities').json()['data']==[{'id':'survives-restart'}]\n assert client.get('/api/auth/me').json()['user']=='restart-user'\n assert client.get('/ready').json()['database']=='postgresql'\n"
        for _ in range(2):
            process=subprocess.run([sys.executable,'-c',code],env=environment,capture_output=True,text=True,timeout=60)
            self.assertEqual(process.returncode,0,process.stderr)

    def test_findings_upsert_retention_and_rollback(self):
        row = {'id':'pg-finding','provider':'anthropic','kind':'chat','risk':'high','risk_score':70,
               'risk_rule_version':policy_management.active_policy()['version'],
               'risk_pipeline_version':governance.PIPELINE_VERSION,'promoted':True,
               'created_at':'2026-09-01','updated_at':'2026-09-02','messages':[]}
        self.assertTrue(finding_store.upsert_finding(row,'anthropic'))
        row['risk_score']=75
        self.assertFalse(finding_store.upsert_finding(row,'anthropic'))
        self.assertEqual(finding_store.get_finding('pg-finding')['risk_score'],75)
        self.assertEqual(len(finding_store.known_versions()),1)
        with closing(database.connect()) as db:
            db.execute("UPDATE findings SET first_seen_at='2000-01-01'")
            db.commit()
        self.assertEqual(finding_store.prune_findings(1),1)
        self.assertFalse(finding_store.upsert_finding(row,'anthropic'))
        with closing(database.connect()) as db:
            db.execute("INSERT INTO expired_findings VALUES ('uncommitted','now')")
        self.assertNotIn('uncommitted',finding_store.expired_finding_ids())

    def test_schema_setup_is_not_repeated_on_reads(self):
        statements=[]
        execute=database.Connection.execute
        def record(db,statement,*args,**kwargs):
            statements.append(statement)
            return execute(db,statement,*args,**kwargs)
        with patch.object(database.Connection,'execute',record):
            for _ in range(4):
                finding_store.list_findings()
                provider_store.read('activities')
                governance.read_audit()
        self.assertFalse(any('CREATE TABLE' in statement or 'ALTER TABLE' in statement for statement in statements))

    def test_parallel_audit_writers_preserve_chain(self):
        command='from app.governance import audit; [audit("worker", "parallel") for _ in range(12)]'
        workers=[subprocess.Popen([sys.executable,'-c',command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                   creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0) for _ in range(3)]
        for worker in workers:
            out,err=worker.communicate(timeout=60)
            self.assertEqual(worker.returncode,0,err.decode())
        self.assertEqual(len(governance.read_audit()),36)
        self.assertTrue(governance.verify_chain())

    def test_snapshot_upserts_and_pool_survive_failed_transaction(self):
        with closing(database.connect()) as db:
            with self.assertRaises(psycopg.Error): db.execute('SELECT missing_column FROM provider_views')
        provider_store.save('activities',{'data':[{'id':'one'}]})
        provider_store.fail('activities')
        self.assertEqual(provider_store.read('activities')['data'],[{'id':'one'}])
        provider_store.save('activities',{'data':[{'id':'two'}]})
        self.assertEqual(provider_store.read('activities')['sync']['state'],'ok')
        with closing(database.connect()) as db:
            value=db.execute("SELECT '?' AS literal, ? AS parameter, '50%' AS percent",('a?b%',)).fetchone()
        self.assertEqual(value,('?', 'a?b%', '50%'))

    def test_http_readiness_and_saved_data_without_provider(self):
        from fastapi.testclient import TestClient
        import app.main as main
        with patch.object(main,'DEMO',False), patch.object(main,'anthropic_get') as fetch:
            provider_store.save('activities',{'data':[{'id':'saved'}]})
            client=TestClient(main.app)
            client.cookies.set('cm_session',main.make_token('admin',{'Compliance.Admin'}))
            self.assertEqual(client.get('/ready').json()['database'],'postgresql')
            self.assertEqual(client.get('/api/activities').json()['data'],[{'id':'saved'}])
            self.assertEqual(client.get('/api/auth/me').status_code,200)
            fetch.assert_not_called()

    def test_migration_rolls_back_on_verification_failure_and_retries(self):
        import sqlite3
        from tools import migrate_sqlite_to_postgres as migration
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE provider_views (name TEXT PRIMARY KEY,payload TEXT NOT NULL,collected_at TEXT,error TEXT)')
                db.executemany('INSERT INTO provider_views VALUES (?,?,?,?)',[(name,'{"data":[]}','now',None) for name in ('z','A','a','Z','Unicode-\u00e9')])
                db.commit()
            with isolated_postgres(initialize=False), patch.dict(os.environ, {'SQLITE_MIGRATION_SOURCE':str(source)}):
                with self.assertRaisesRegex(RuntimeError,'requires migration'): database.require_legacy_migration()
                original=migration.digest_rows
                calls=[]
                def mismatched(rows):
                    result=original(rows);calls.append(1)
                    return (result[0],'mismatch') if len(calls)==2 else result
                with patch.object(migration,'digest_rows',mismatched):
                    with self.assertRaisesRegex(ValueError,'verification failed'):migration.migrate(source)
                with closing(database.connect()) as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM provider_views').fetchone()[0],0)
                self.assertTrue(migration.migrate(source)['verified'])
                database.require_legacy_migration()

    def test_sqlite_migration_preserves_values_ids_and_audit_chain(self):
        from tools.migrate_sqlite_to_postgres import migrate
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source.db'
            env={**os.environ,'DATABASE_URL':'','PGHOST':'','DEMO_MODE':'true',
                 'DATABASE_PATH':str(source),'ATTACHMENT_PATH':str(Path(folder)/'attachments')}
            code='''from app.schema import initialize
initialize()
from app import governance,case_management,provider_store
from app.database import connect
from contextlib import closing
governance.audit('migration-user','original-audit')
c=case_management.create_case('Preserved case','scope','high','',None,[],'analyst',{'id':'evidence','title':'Saved original'})
case_management.add_comment(c['id'],'original comment','analyst')
provider_store.save('activities',{'data':[{'id':'old-event'}]})
with closing(connect()) as db:
 db.execute("INSERT INTO claude_analytics VALUES (?,?,?)",('2026-08','{\\"cost_unit\\":\\"USD\\",\\"summary\\":{\\"claude_requests\\":42}}','2026-09-01'))
 db.commit()
'''
            completed=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,text=True,timeout=60)
            self.assertEqual(completed.returncode,0,completed.stderr)
            before=source.read_bytes()
            with isolated_postgres(initialize=False):
                report=migrate(source)
                self.assertTrue(report['verified'])
                self.assertEqual(report['tables']['investigation_cases'],1)
                self.assertTrue(governance.verify_chain())
                from app import case_management,claude_analytics
                self.assertEqual(case_management.get_case(1)['comments'][0]['body'],'original comment')
                self.assertEqual(claude_analytics.saved('2026-08')['summary']['claude_requests'],42)
                c=case_management.create_case('Next case','scope','low','',None,[],'analyst')
                self.assertGreater(c['id'],1)
                with self.assertRaisesRegex(ValueError,'not empty'):migrate(source)
            self.assertEqual(source.read_bytes(),before)


if __name__ == '__main__': unittest.main()
