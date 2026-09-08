import asyncio
import copy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import closing
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


    def test_usage_reader_cannot_import_or_replace(self):
        cookies = self._cookies({"Compliance.UsageReader"})
        with patch.object(main, "parse_usage_file") as parse, patch.object(main, "save_usage_period") as save:
            for path in ("/api/usage/import/preview", "/api/usage/import", "/api/usage/import?replace=true"):
                response = client.post(path, cookies=cookies, files={"file": ("test.csv", b"test", "text/csv")})
                self.assertEqual(response.status_code, 403)
            parse.assert_not_called(); save.assert_not_called()
        self.assertFalse(client.get("/api/auth/me", cookies=cookies).json()["usage_import"])

    def test_authorized_importer_and_admin_can_import(self):
        with patch.object(main, "USAGE_IMPORT_ROLES", {"Usage.Importer"}):
            for roles, method in (({"Compliance.Admin"}, "entra"), ({"Compliance.UsageReader", "Usage.Importer"}, "entra"), (set(), "local")):
                cookies = self._cookies(roles, method)
                with patch.object(main, "parse_usage_file", return_value=({"period":"Test"}, "hash")), patch.object(main, "save_usage_period") as save, patch.object(main, "generate_usage_alerts"):
                    response = client.post("/api/usage/import?replace=true", cookies=cookies, files={"file": ("test.csv", b"test", "text/csv")})
                    self.assertEqual(response.status_code, 200); save.assert_called_once()
                self.assertTrue(client.get("/api/auth/me", cookies=cookies).json()["usage_import"])


class FindingSyncTests(unittest.TestCase):
    def setUp(self):
        key_patch = patch.object(main, "API_KEY", "test-key")
        key_patch.start(); self.addCleanup(key_patch.stop)
        client.cookies.clear()
        _repoint_databases()
        connection = sqlite3.connect(DB)
        try:
            connection.execute("DELETE FROM expired_findings")
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


    def _sync_item(self):
        return {"id":"claude_chat_retry", "kind":"chat", "surface":"Claude.ai", "title":"Question", "summary":"",
                "created_at":"2026-09-01T00:00:00Z", "updated_at":"2026-09-01T00:00:00Z", "user":{"id":"u1"}}

    def test_failed_hydration_is_retried_without_suppressing(self):
        from fastapi import HTTPException
        import httpx
        for error in (HTTPException(429, "Rate limited"), HTTPException(503, "Unavailable"), httpx.ReadTimeout("Timeout")):
            item = self._sync_item(); item["id"] += type(error).__name__ + str(getattr(error,"status_code",0))
            fetch = AsyncMock(side_effect=[error, {"messages":[{"role":"human","text":"hack production"}]}])
            with patch.object(main,"_live_index",AsyncMock(side_effect=lambda:([copy.deepcopy(item)],[],[]))), patch.object(main,"M365_ENABLED",False), patch.object(main,"anthropic_get",fetch):
                first=asyncio.run(main.sync_provider_findings())
                self.assertEqual(first["scored"],0); self.assertNotIn(item["id"],finding_store.known_versions())
                second=asyncio.run(main.sync_provider_findings())
                self.assertEqual(second["promoted"],1); self.assertEqual(fetch.await_count,2)

    def test_failed_refresh_preserves_existing_evidence(self):
        from fastapi import HTTPException
        item=self._sync_item(); item["messages"]=[{"role":"human","text":"hack production"}]
        governance.score_evidence(item); finding_store.upsert_finding(item,"anthropic")
        changed={**item,"updated_at":"2026-09-02T00:00:00Z"}
        with patch.object(main,"_live_index",AsyncMock(return_value=([changed],[],[]))), patch.object(main,"M365_ENABLED",False), patch.object(main,"anthropic_get",AsyncMock(side_effect=HTTPException(500,"Unavailable"))):
            asyncio.run(main.sync_provider_findings())
        self.assertEqual(finding_store.get_finding(item["id"]),item)

    def test_expired_exception_reevaluates_unchanged_evidence(self):
        item=self._sync_item(); item["title"]="hack production"; item["messages"]=[{"role":"human","text":"hack production"}]
        policy=copy.deepcopy(main.active_policy())
        policy["exceptions"]=[{"id":"pilot","type":"user","value":"u1","expires_at":"2099-01-01T00:00:00Z"}]
        with patch.object(policy_management,"active_policy",return_value=policy), patch.object(main,"active_policy",return_value=policy), patch.object(main,"_live_index",AsyncMock(side_effect=lambda:([copy.deepcopy(item)],[],[]))), patch.object(main,"M365_ENABLED",False), patch.object(main,"hydrate_live",AsyncMock(side_effect=lambda rows:rows)):
            self.assertEqual(asyncio.run(main.sync_provider_findings())["suppressed"],1)
            self.assertEqual(asyncio.run(main.sync_provider_findings())["scored"],0)
            # Advance the clock past the exception in both scoring and synchronization.
            class Future(datetime):
                @classmethod
                def now(cls, tz=None): return datetime(2100,1,1,tzinfo=timezone.utc)
            with patch.object(governance,"datetime",Future), patch.object(finding_store,"datetime",Future):
                self.assertEqual(asyncio.run(main.sync_provider_findings())["promoted"],1)

    def test_retention_blocks_reimport_after_policy_or_provider_change(self):
        item=self._sync_item(); item["title"]="hack production"; item["messages"]=[{"role":"human","text":"hack production"}]
        governance.score_evidence(item); finding_store.upsert_finding(item,"anthropic")
        with closing(sqlite3.connect(DB)) as db, db:
            db.execute("UPDATE findings SET first_seen_at=?",((datetime.now(timezone.utc)-timedelta(days=200)).isoformat(),))
        item["updated_at"]="2026-09-03T00:00:00Z"
        with patch.object(main,"_live_index",AsyncMock(return_value=([item],[],[]))), patch.object(main,"M365_ENABLED",False), patch.object(main,"hydrate_live",AsyncMock(return_value=[])) as hydrate, patch.object(finding_store,"RETENTION_DAYS",180):
            self.assertEqual(asyncio.run(main.sync_provider_findings())["pruned"],1)
            with patch.object(main,"active_policy",return_value={"version":"new-policy"}):
                self.assertEqual(asyncio.run(main.sync_provider_findings())["scored"],0)
            self.assertTrue(all(call.args[0]==[] for call in hydrate.call_args_list))
        self.assertIsNone(finding_store.get_finding(item["id"]))

    def test_live_normalization_applies_provider_scope(self):
        policy=copy.deepcopy(main.active_policy())
        policy["scope_overrides"]=[{"id":"claude","provider":"anthropic","finding_threshold":100}]
        with patch.object(main,"_fetch_all",AsyncMock(side_effect=[[{"id":"chat","title":"hack production"}],[],[]])), patch.object(policy_management,"active_policy",return_value=policy):
            chats,_,_=asyncio.run(main._live_index())
            scored=governance.score_evidence(chats[0])
        self.assertEqual(scored["provider"],"anthropic"); self.assertEqual(scored["risk_threshold"],100)
        self.assertEqual(scored["risk_scope_ids"],["claude"]); self.assertFalse(scored["promoted"])

    def test_copilot_pairs_messages_across_pages(self):
        pages=[{"value":[{"id":"p","requestId":"req","interactionType":"userPrompt","createdDateTime":"2026-09-01T00:00:00Z","body":{"content":"hack production"}}],"@odata.nextLink":"https://graph.microsoft.com/next"},
               {"value":[{"id":"r","requestId":"req","interactionType":"aiResponse","createdDateTime":"2026-09-01T00:01:00Z","body":{"content":"No"}}]}]
        with patch.object(main,"m365_users",AsyncMock(return_value=[{"id":"u","email":"u@example.com"}])), patch.object(main,"graph_get",AsyncMock(side_effect=pages)) as fetch:
            rows=asyncio.run(main.m365_cases())
        self.assertEqual(fetch.await_count,2); self.assertEqual(fetch.call_args.args[0],"https://graph.microsoft.com/next")
        self.assertEqual(len(rows),1); self.assertEqual(len(rows[0]["messages"]),2); self.assertEqual(rows[0]["provider"],"m365")

    def test_copilot_user_failure_preserves_successful_users(self):
        from fastapi import HTTPException
        failures=[]
        async def get(url):
            if "/bad/" in url: raise HTTPException(403,"Forbidden")
            return {"value":[{"id":"p","interactionType":"userPrompt","body":{"contentType":"html","content":"<br>Use &lt;name&gt;<script>bad()</script>"}}]}
        with patch.object(main,"m365_users",AsyncMock(return_value=[{"id":"bad"},{"id":"good"}])), patch.object(main,"graph_get",AsyncMock(side_effect=get)):
            rows=asyncio.run(main.m365_cases(failures=failures))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["title"],"Use <name>")
        self.assertIn("<br>",rows[0]["messages"][0]["raw_body"]["content"])
        self.assertEqual(failures[0]["status"],403)
        self.assertEqual(failures[0]["user_id"],"bad")

    def test_copilot_unlimited_discovery_follows_all_pages(self):
        pages=[{"value":[{"id":"one"}],"@odata.nextLink":"https://graph.microsoft.com/next"},{"value":[{"id":"two"}]}]
        with patch.object(main,"M365_USERS",[]),patch.object(main,"M365_MAX_USERS",0),patch.object(main,"graph_get",AsyncMock(side_effect=pages)):
            self.assertEqual(len(asyncio.run(main.m365_users())),2)

    def test_copilot_plain_text_keeps_angle_brackets(self):
        self.assertEqual(main.copilot_text({"contentType":"text","content":"a < b && c > d"}),"a < b && c > d")

    def test_copilot_partial_page_failure_does_not_store_partial_evidence(self):
        from fastapi import HTTPException
        with patch.object(main,"m365_users",AsyncMock(return_value=[{"id":"u"}])), patch.object(main,"graph_get",AsyncMock(side_effect=[{"value":[{"id":"p"}],"@odata.nextLink":"https://graph.microsoft.com/next"},HTTPException(503,"Unavailable")])):
            with self.assertRaises(HTTPException): asyncio.run(main.m365_cases())


    def test_session_index_uses_next_page_cursor(self):
        for kind in ("local","remote"):
            with patch.object(main,"anthropic_get",AsyncMock(side_effect=[{"data":[{"id":"one"}],"next_page":"opaque"},{"data":[{"id":"two"}],"next_page":None}])) as fetch:
                rows=asyncio.run(main._fetch_all(f"/v1/compliance/apps/sessions/{kind}"))
            self.assertEqual(len(rows),2); self.assertEqual(fetch.call_args.args[1],[("limit","100"),("page","opaque")])

    def test_structured_transcripts_follow_pages_and_preserve_blocks(self):
        for kind,id_,cursor_key in (("chat","claude_chat_long","last_id"),("session","clls_long","next_page"),("session","cse_long","next_page")):
            block={"type":"text","text":"hack production"}
            first={"data":[{"role":"user","content":[block]}],cursor_key:"opaque","has_more":True}
            last={"data":[{"role":"assistant","content":[{"type":"tool_use","input":{"command":"disable logging"}}]}],"has_more":False}
            with patch.object(main,"anthropic_get",AsyncMock(side_effect=[first,last])) as fetch:
                rows=asyncio.run(main.hydrate_live([{**self._sync_item(),"kind":kind,"id":id_}]))
            self.assertEqual(len(rows[0]["messages"]),2)
            self.assertEqual(rows[0]["messages"][0]["text"],"hack production")
            self.assertEqual(rows[0]["messages"][0]["role"],"human")
            self.assertEqual(rows[0]["messages"][0]["content"],[block])
            self.assertIn("disable logging", rows[0]["messages"][1]["text"])

    def test_pagination_cap_and_repeated_cursor_fail_visibly(self):
        from fastapi import HTTPException
        with patch.object(main,"FINDINGS_SYNC_MAX_ITEMS",1),patch.object(main,"anthropic_get",AsyncMock(return_value={"data":[{"id":"one"},{"id":"two"}]})):
            with self.assertRaises(HTTPException): asyncio.run(main._fetch_all("/chats"))
        with patch.object(main,"anthropic_get",AsyncMock(return_value={"data":[{"id":"one"}],"has_more":True,"last_id":"stuck"})):
            with self.assertRaises(HTTPException): asyncio.run(main._fetch_all("/chats"))

    def test_sync_failure_and_partial_results_are_visible(self):
        from fastapi import HTTPException
        with patch.object(main,"_sync_provider_findings",AsyncMock(side_effect=HTTPException(403,"secret upstream message"))):
            with self.assertRaises(HTTPException): asyncio.run(main.sync_provider_findings())
        self.assertEqual(main._finding_sync_status["state"],"failed")
        self.assertNotIn("secret",main._finding_sync_status["error"])
        with patch.object(main,"_sync_provider_findings",AsyncMock(return_value={"failed":2})):
            asyncio.run(main.sync_provider_findings())
        self.assertEqual(main._finding_sync_status["state"],"partial")
        with patch.object(main,"_sync_provider_findings",AsyncMock(return_value={"failed":0})):
            asyncio.run(main.sync_provider_findings())
        self.assertEqual(main._finding_sync_status["state"],"ok")
        self.assertIsNotNone(main._finding_sync_status["last_success_at"])

    def test_graph_user_discovery_pages_to_configured_limit(self):
        with patch.object(main,"M365_USERS",[]),patch.object(main,"M365_MAX_USERS",2),patch.object(main,"graph_get",AsyncMock(side_effect=[{"value":[{"id":"one"}],"@odata.nextLink":"https://graph.microsoft.com/next"},{"value":[{"id":"two"},{"id":"three"}]}])):
            self.assertEqual([u["id"] for u in asyncio.run(main.m365_users())],["one","two"])

    def test_graph_rejects_foreign_next_link_before_obtaining_token(self):
        from fastapi import HTTPException
        with patch.object(main,"graph_token",AsyncMock()) as token:
            with self.assertRaises(HTTPException): asyncio.run(main.graph_get("https://example.com/collect"))
        token.assert_not_called()


    def test_unretained_evidence_cannot_be_rehydrated_through_detail_api(self):
        cookies={"cm_session":main.make_token("admin",{"Compliance.Admin"},"local")}
        with patch.object(main,"DEMO",False),patch.object(main,"anthropic_get",AsyncMock()) as anthropic,patch.object(main,"m365_cases",AsyncMock()) as copilot:
            for evidence_id in ("claude_chat_deleted","m365:someone:deleted"):
                response=client.get(f"/api/cases/{evidence_id}",cookies=cookies)
                self.assertEqual(response.status_code,404)
            anthropic.assert_not_called();copilot.assert_not_called()


class LiveModeGuardTests(unittest.TestCase):
    def _boot(self, name, extra_env):
        env = {**os.environ, "DEMO_MODE": "false", "COOKIE_SECURE":"true", "ANTHROPIC_COMPLIANCE_ACCESS_KEY": "test-key",
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


    def test_live_without_provider_refuses_demo_fallback(self):
        result=self._boot("no-provider",{"ANTHROPIC_COMPLIANCE_ACCESS_KEY":"", "M365_COPILOT_TENANT_ID":"", "M365_COPILOT_CLIENT_ID":"", "M365_COPILOT_CLIENT_SECRET":"", "SESSION_SECRET":"s"*40,"APP_PASSWORD":"strong-password"})
        self.assertNotEqual(result.returncode,0);self.assertIn("at least one live evidence provider",result.stderr)

    def test_live_requires_secure_cookies_and_a_login_method(self):
        for name,values,message in (("cookies",{"COOKIE_SECURE":"false"},"COOKIE_SECURE"),("auth",{"LOCAL_AUTH_ENABLED":"false","ENTRA_CLIENT_SECRET":""},"Configure Entra")):
            result=self._boot(name,{"SESSION_SECRET":"s"*40,"APP_PASSWORD":"strong-password",**values})
            self.assertNotEqual(result.returncode,0); self.assertIn(message,result.stderr)

    def test_copilot_only_live_configuration_boots(self):
        result=self._boot("copilot",{"ANTHROPIC_COMPLIANCE_ACCESS_KEY":"", "M365_COPILOT_TENANT_ID":"tenant", "M365_COPILOT_CLIENT_ID":"client", "M365_COPILOT_CLIENT_SECRET":"secret", "SESSION_SECRET":"s"*40,"APP_PASSWORD":"strong-password"})
        self.assertEqual(result.returncode,0,result.stderr)


class ReleaseAuthTests(unittest.TestCase):
    def setUp(self):
        client.cookies.clear();_repoint_databases()

    def test_reports_only_executive_downloads_redact_all_sections(self):
        import io
        from openpyxl import load_workbook
        token=main.make_token("ceo@example.com",{"Compliance.ReportsOnly"},"entra")
        data={"period":"August 2026","summary":{},"top_users":[],"executive_sections":[{"name":"Detail","rows":[["person@example.com"]]}]}
        with patch.object(main,"resolve_usage",return_value=data):
            response=client.get("/api/reports/executive",cookies={"cm_session":token})
            self.assertEqual(response.status_code,200)
            self.assertNotIn("person@example.com",response.text)
            self.assertFalse(response.json()["user_detail_included"])
            response=client.get("/api/reports/executive?format=xlsx",cookies={"cm_session":token})
            self.assertEqual(response.status_code,200)
            workbook=load_workbook(io.BytesIO(response.content))
            self.assertTrue(workbook["Detail"]["A1"].value.startswith("User "))
            self.assertEqual(client.get("/api/cases",cookies={"cm_session":token}).status_code,403)
            self.assertEqual(client.post("/api/usage/import",cookies={"cm_session":token}).status_code,403)
            self.assertEqual(client.post("/api/report-schedules",cookies={"cm_session":token},json={}).status_code,403)
            self.assertEqual(client.delete("/api/report-schedules/1",cookies={"cm_session":token}).status_code,403)

    def test_entra_callback_enforces_tenant_roles_and_secure_cookie(self):
        from types import SimpleNamespace
        claims={"tid":"tenant","roles":["Compliance.Reviewer"],"preferred_username":"reviewer@example.com"}
        entra=SimpleNamespace(authorize_access_token=AsyncMock(return_value={"userinfo":claims}))
        with patch.object(main,"ENTRA_ENABLED",True),patch.object(main,"ENTRA_TENANT","tenant"),patch.object(main,"ENTRA_ROLES",{"Compliance.Reviewer"}),patch.object(main,"ENTRA_GROUPS",set()),patch.object(main,"COOKIE_SECURE",True),patch.object(main,"oauth",SimpleNamespace(entra=entra)):
            response=client.get("/api/auth/entra/callback",follow_redirects=False)
            self.assertEqual(response.status_code,302)
            self.assertIn("Secure",response.headers["set-cookie"]);self.assertIn("HttpOnly",response.headers["set-cookie"])
            claims["tid"]="foreign"
            response=client.get("/api/auth/entra/callback",follow_redirects=False)
            self.assertIn("tenant_not_allowed",response.headers["location"])
            self.assertNotIn("set-cookie",response.headers)
            claims["tid"]="tenant";claims["roles"]=[]
            response=client.get("/api/auth/entra/callback",follow_redirects=False)
            self.assertIn("access_not_assigned",response.headers["location"])

    def test_startup_shutdown_and_sensitive_response_cache(self):
        with patch.object(main,"DEMO",True),patch.object(main,"run_due_report_schedules",AsyncMock()):
            with TestClient(main.app) as active:
                self.assertEqual(active.get("/health").json()["version"],"0.10.4")
                self.assertEqual(active.get("/api/auth/config").headers["cache-control"],"no-store, no-cache, must-revalidate, max-age=0")
                self.assertEqual(active.get("/api/cases").headers["cache-control"],"no-store")


if __name__ == "__main__":
    unittest.main()
