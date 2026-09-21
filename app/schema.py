"""Versioned PostgreSQL schema setup shared by application startup and migration."""
from contextlib import closing
from app import database


def initialize(seed=True):
    from app import (governance, usage_reporting, finding_reporting, case_management,
                     policy_management, alert_management, rapid7_export, finding_store,
                     claude_analytics, copilot_analytics, purview_analytics, usage_directory,
                     provider_store)
    with database.seeding(seed):
        for function in (governance.init_db, usage_reporting.init_usage_db,
                         finding_reporting.init_reporting_db, case_management.init_case_db,
                         policy_management.init_policy_db, alert_management.init_alert_db,
                         rapid7_export.init_rapid7_db, finding_store.init_finding_db,
                         claude_analytics.init_analytics_db, copilot_analytics.init_analytics_db,
                         purview_analytics.init_analytics_db, usage_directory.init_directory_db,
                         provider_store.init_provider_db):
            function()
    if database.is_postgres():
        with closing(database.connect()) as db:
            db.lock('schema-migrations')
            db.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
            if not db.execute('SELECT 1 FROM schema_migrations WHERE version=1').fetchone():
                for statement in (
                    'CREATE INDEX IF NOT EXISTS idx_findings_promoted_created ON findings(promoted,created_at DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_findings_retention ON findings(first_seen_at)',
                    'CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON audit_log(actor,id DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_audit_action_id ON audit_log(action,id DESC)',
                    'CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id,id)',
                    'CREATE INDEX IF NOT EXISTS idx_case_comments_case ON case_comments(case_id,id)',
                    'CREATE INDEX IF NOT EXISTS idx_case_attachments_case ON case_attachments(case_id,id)',
                    'CREATE INDEX IF NOT EXISTS idx_cases_status_updated ON investigation_cases(status,updated_at)',
                    'CREATE INDEX IF NOT EXISTS idx_alert_timeline_alert ON alert_timeline(alert_id,id)',
                    'CREATE INDEX IF NOT EXISTS idx_delivery_pending ON alert_deliveries(status,next_attempt_at)',
                    'CREATE INDEX IF NOT EXISTS idx_rapid7_pending ON rapid7_outbox(status,next_attempt_at)',
                ): db.execute(statement)
                db.execute("INSERT INTO schema_migrations VALUES (1, CAST(CURRENT_TIMESTAMP AS TEXT))")
            db.commit()
