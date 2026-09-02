import asyncio
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

# app.main initializes every database at import, so the temp paths must be in place
# (both in the environment and on the already-imported modules) before it loads.
TMP = Path(tempfile.mkdtemp())
DB = TMP / "main-auth.db"
os.environ["DATABASE_PATH"] = str(DB)
os.environ["ATTACHMENT_PATH"] = str(TMP / "attachments")

import app.governance as governance
import app.policy_management as policy_management
import app.case_management as case_management
import app.alert_management as alert_management
import app.rapid7_export as rapid7_export
import app.usage_reporting as usage_reporting
import app.finding_reporting as finding_reporting
import app.finding_store as finding_store
for module in (governance, policy_management, case_management, alert_management, rapid7_export, usage_reporting, finding_reporting, finding_store):
    module.DB_PATH = DB
policy_management._cache = None
case_management.ATTACHMENT_DIR = TMP / "attachments"

from fastapi.testclient import TestClient
import app.main as main

client = TestClient(main.app)
REPO_ROOT = Path(__file__).resolve().parents[1]


def _repoint_databases():
    """Other test modules move these module-level DB paths; pin them back to ours."""
    for module in (governance, policy_management, case_management, alert_management, rapid7_export, usage_reporting, finding_reporting, finding_store):
        module.DB_PATH = DB
    policy_management._cache = None


class LocalLoginThrottleTests(unittest.TestCase):
    def setUp(self):
        main._login_failures.clear()
        client.cookies.clear()
        _repoint_databases()

    def test_lockout_after_repeated_failures(self):
        for _ in range(main.LOGIN_MAX_FAILURES):
            self.assertEqual(client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code, 401)
        self.assertEqual(client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code, 429)
        self.assertEqual(client.post("/api/auth/login", json={"username": main.USERNAME, "password": main.PASSWORD}).status_code, 429)

    def test_success_clears_failure_history(self):
        for _ in range(main.LOGIN_MAX_FAILURES - 1):
            client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        self.assertEqual(client.post("/api/auth/login", json={"username": main.USERNAME, "password": main.PASSWORD}).status_code, 200)
        self.assertEqual(client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code, 401)

    def test_different_usernames_do_not_share_lockout(self):
        for _ in range(main.LOGIN_MAX_FAILURES):
            client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        self.assertEqual(client.post("/api/auth/login", json={"username": "other", "password": "wrong"}).status_code, 401)


class SessionTokenTests(unittest.TestCase):
    def setUp(self):
        client.cookies.clear()
        _repoint_databases()

    def test_valid_token_grants_identity(self):
        token = main.make_token("admin", {"Compliance.Admin"}, "local")
        response = client.get("/api/auth/me", cookies={"cm_session": token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"], "admin")

    def test_tampered_signature_is_rejected(self):
        payload, signature = main.make_token("admin", {"Compliance.Admin"}, "local").rsplit(".", 1)
        forged = f"{payload}.{'0' * len(signature)}"
        self.assertEqual(client.get("/api/auth/me", cookies={"cm_session": forged}).status_code, 401)

    def test_tampered_payload_is_rejected(self):
        payload, signature = main.make_token("viewer", set(), "entra").rsplit(".", 1)
        elevated = base64.urlsafe_b64encode(json.dumps({"u": "viewer", "roles": ["Compliance.Admin"], "method": "entra", "exp": int(time.time()) + 600}).encode()).decode().rstrip("=")
        self.assertEqual(client.get("/api/auth/me", cookies={"cm_session": f"{elevated}.{signature}"}).status_code, 401)

    def test_expired_token_is_rejected(self):
        payload = base64.urlsafe_b64encode(json.dumps({"u": "admin", "roles": ["Compliance.Admin"], "method": "local", "exp": int(time.time()) - 10}).encode()).decode().rstrip("=")
        signature = hmac.new(main.SECRET, payload.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(client.get("/api/auth/me", cookies={"cm_session": f"{payload}.{signature}"}).status_code, 401)

    def test_missing_token_is_rejected(self):
        self.assertEqual(client.get("/api/auth/me").status_code, 401)


class PagePermissionTests(unittest.TestCase):
    def setUp(self):
        client.cookies.clear()
        _repoint_databases()

    def _cookies(self, roles, method="entra"):
        return {"cm_session": main.make_token("user@example.com", set(roles), method)}

    def test_reports_only_role_is_scoped_to_reports(self):
        cookies = self._cookies({"Compliance.ReportsOnly"})
        self.assertEqual(client.get("/api/report-schedules", cookies=cookies).status_code, 200)
        self.assertEqual(client.get("/api/policies", cookies=cookies).status_code, 403)
        self.assertEqual(client.get("/api/audit", cookies=cookies).status_code, 403)
        self.assertEqual(client.get("/api/usage", cookies=cookies).status_code, 403)
        self.assertEqual(client.get("/api/investigations", cookies=cookies).status_code, 403)

    def test_auditor_reaches_audit_but_not_settings(self):
        cookies = self._cookies({"Compliance.Auditor"})
        self.assertEqual(client.get("/api/audit", cookies=cookies).status_code, 200)
        self.assertEqual(client.get("/api/policies", cookies=cookies).status_code, 403)

    def test_entra_user_without_roles_reaches_nothing_mapped(self):
        cookies = self._cookies(set())
        for path in ("/api/audit", "/api/policies", "/api/usage", "/api/report-schedules", "/api/investigations"):
            self.assertEqual(client.get(path, cookies=cookies).status_code, 403, path)

    def test_local_method_retains_full_access(self):
        cookies = {"cm_session": main.make_token("admin", {"Compliance.Admin"}, "local")}
        self.assertEqual(client.get("/api/policies", cookies=cookies).status_code, 200)
        self.assertEqual(client.get("/api/audit", cookies=cookies).status_code, 200)


class FindingSyncTests(unittest.TestCase):
    def setUp(self):
        client.cookies.clear()
        _repoint_databases()
        connection = sqlite3.connect(DB)
        try:
            connection.execute("DELETE FROM findings")
            connection.execute("DELETE FROM suppressed_evidence")
            connection.commit()
        finally:
            connection.close()

    def test_fetch_all_follows_pagination(self):
        pages = [{"data": [{"id": "a"}, {"id": "b"}], "has_more": True, "last_id": "b"},
                 {"data": [{"id": "c"}], "has_more": False}]
        with patch.object(main, "anthropic_get", AsyncMock(side_effect=pages)) as fake:
            items = asyncio.run(main._fetch_all("/v1/compliance/apps/chats"))
        self.assertEqual([x["id"] for x in items], ["a", "b", "c"])
        self.assertEqual(fake.call_args_list[1].args[1], [("limit", "100"), ("after_id", "b")])

    def test_sync_stores_promoted_suppresses_rest_and_skips_unchanged(self):
        risky = {"id": "claude_chat_risky", "name": "Root access", "created_at": "2026-09-01T00:00:00Z",
                 "updated_at": "2026-09-01T00:00:00Z", "user": {"id": "u1", "email_address": "p@example.com"}}
        boring = {"id": "claude_chat_boring", "name": "Lunch plan", "created_at": "2026-09-01T00:00:00Z",
                  "updated_at": "2026-09-01T00:00:00Z", "user": {"id": "u2", "email_address": "q@example.com"}}
        async def fake_get(path, params=None):
            if path == "/v1/compliance/apps/chats": return {"data": [risky, boring], "has_more": False}
            if path.endswith("/claude_chat_risky/messages"):
                return {"messages": [{"role": "human", "text": "hack root access on the production server without the admin noticing"}]}
            if path.endswith("/claude_chat_boring/messages"):
                return {"messages": [{"role": "human", "text": "plan a team lunch"}]}
            return {"data": [], "has_more": False}
        with patch.object(main, "anthropic_get", fake_get), patch.object(main, "M365_ENABLED", False):
            first = asyncio.run(main.sync_provider_findings())
        self.assertEqual((first["promoted"], first["suppressed"]), (1, 1))
        self.assertEqual([x["id"] for x in finding_store.list_findings()], ["claude_chat_risky"])
        with patch.object(main, "anthropic_get", fake_get), patch.object(main, "M365_ENABLED", False):
            second = asyncio.run(main.sync_provider_findings())
        self.assertEqual(second["scored"], 0)

    def test_stored_finding_is_served_without_provider_calls(self):
        item = {"id": "claude_chat_stored", "kind": "chat", "surface": "Claude.ai", "title": "Stored", "summary": "",
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
                "user": {"id": "u1", "email": "p@example.com"},
                "messages": [{"role": "human", "text": "hack root access on production"}]}
        governance.score_evidence(item)
        finding_store.upsert_finding(item, "anthropic")
        cookies = {"cm_session": main.make_token("admin", {"Compliance.Admin"}, "local")}
        with patch.object(main, "DEMO", False), patch.object(main, "anthropic_get", AsyncMock(side_effect=AssertionError("provider should not be called"))):
            response = client.get("/api/cases/claude_chat_stored", cookies=cookies)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["risk"], "high")


class LiveModeGuardTests(unittest.TestCase):
    def _boot(self, name, extra_env):
        env = {**os.environ, "DEMO_MODE": "false", "ANTHROPIC_COMPLIANCE_ACCESS_KEY": "test-key",
               "DATABASE_PATH": str(TMP / f"guard-{name}.db"), "ATTACHMENT_PATH": str(TMP / "guard-attachments"), **extra_env}
        return subprocess.run([sys.executable, "-c", "import app.main"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)

    def test_live_mode_refuses_placeholder_secret(self):
        result = self._boot("secret", {"SESSION_SECRET": "development-only-secret-change-me", "APP_PASSWORD": "a-genuinely-different-password"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to start in live mode", result.stderr)

    def test_live_mode_refuses_short_secret(self):
        result = self._boot("short", {"SESSION_SECRET": "too-short", "APP_PASSWORD": "a-genuinely-different-password"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SESSION_SECRET", result.stderr)

    def test_live_mode_refuses_default_password(self):
        result = self._boot("password", {"SESSION_SECRET": "s" * 40, "APP_PASSWORD": "change-me-now"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APP_PASSWORD", result.stderr)

    def test_live_mode_boots_with_strong_config(self):
        result = self._boot("ok", {"SESSION_SECRET": "s" * 40, "APP_PASSWORD": "a-genuinely-different-password"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_demo_mode_still_boots_with_defaults(self):
        env = {**os.environ, "DEMO_MODE": "true", "DATABASE_PATH": str(TMP / "guard-demo.db"), "ATTACHMENT_PATH": str(TMP / "guard-attachments")}
        result = subprocess.run([sys.executable, "-c", "import app.main"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
