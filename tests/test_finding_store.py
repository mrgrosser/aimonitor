import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import finding_store, governance, policy_management


class FindingStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        db = Path(self.temp.name) / "findings.db"
        # Other test modules share these module globals; restore them afterward.
        self._previous = (finding_store.DB_PATH, governance.DB_PATH, policy_management.DB_PATH)
        finding_store.DB_PATH = db
        governance.DB_PATH = db
        policy_management.DB_PATH = db
        policy_management._cache = None
        finding_store.init_finding_db()
        governance.init_db()
        policy_management.init_policy_db()
        self.item = {"id": "claude_chat_1", "kind": "chat", "surface": "Claude.ai", "title": "Root access", "summary": "",
                     "created_at": "2026-09-01T12:00:00Z", "updated_at": "2026-09-01T12:05:00Z",
                     "user": {"id": "u1", "email": "person@example.com"},
                     "messages": [{"role": "human", "text": "How do I hack root access on the production server without the admin noticing?"}]}

    def tearDown(self):
        finding_store.DB_PATH, governance.DB_PATH, policy_management.DB_PATH = self._previous
        policy_management._cache = None
        self.temp.cleanup()

    def test_upsert_get_and_list_roundtrip(self):
        governance.score_evidence(self.item)
        self.assertTrue(finding_store.upsert_finding(self.item, "anthropic"))
        self.assertFalse(finding_store.upsert_finding(self.item, "anthropic"))
        stored = finding_store.get_finding("claude_chat_1")
        self.assertEqual(stored["risk"], "critical")
        self.assertEqual([x["id"] for x in finding_store.list_findings()], ["claude_chat_1"])
        self.assertEqual(finding_store.known_versions()["claude_chat_1"], ("2026-09-01T12:05:00Z", stored["risk_rule_version"]))

    def test_known_versions_covers_suppressed_metadata(self):
        self.item["risk_score"] = 5
        self.item["risk_rule_version"] = "rules-2026.08.2"
        governance.record_suppressed(self.item, "anthropic")
        self.assertEqual(finding_store.known_versions()["claude_chat_1"], ("2026-09-01T12:05:00Z", "rules-2026.08.2"))

    def test_prune_respects_retention_window(self):
        governance.score_evidence(self.item)
        finding_store.upsert_finding(self.item, "anthropic")
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        connection = sqlite3.connect(finding_store.DB_PATH)
        try:
            connection.execute("UPDATE findings SET first_seen_at=?", (old,))
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(finding_store.prune_findings(365), 0)
        self.assertEqual(finding_store.prune_findings(0), 0)
        self.assertEqual(finding_store.prune_findings(180), 1)
        self.assertEqual(finding_store.list_findings(), [])

    def test_rescore_moves_below_threshold_findings_to_suppressed(self):
        governance.score_evidence(self.item)
        finding_store.upsert_finding(self.item, "anthropic")
        draft = policy_management.create_draft("rules-test-strict", "Strict", "Unit test", "author")
        draft["finding_threshold"] = 95
        policy_management.update_draft(draft["id"], draft, "author", "Raise threshold above this finding")
        policy_management.approve_policy(draft["id"], "reviewer", "Reviewed")
        policy_management.activate_policy(draft["id"], "deployer", "Deploy strict policy")
        result = finding_store.rescore_findings()
        self.assertEqual(result["suppressed"], 1)
        self.assertEqual(finding_store.list_findings(), [])
        self.assertEqual(governance.suppressed_count(), 1)

    def test_rescore_keeps_findings_that_still_qualify(self):
        governance.score_evidence(self.item)
        finding_store.upsert_finding(self.item, "anthropic")
        result = finding_store.rescore_findings()
        self.assertEqual(result, {"rescored": 1, "suppressed": 0})
        self.assertEqual(len(finding_store.list_findings()), 1)


if __name__ == "__main__":
    unittest.main()
