import tempfile
import unittest
import sqlite3
from pathlib import Path

from app import governance, policy_management
from app.governance import score_evidence


class GovernanceScoringTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); db=Path(self.temp.name)/"governance.db"
        governance.DB_PATH=db; policy_management.DB_PATH=db; policy_management._cache=None; policy_management.init_policy_db()

    def tearDown(self):
        self.temp.cleanup()

    def test_root_access_example_is_explainable_critical(self):
        item = {"title":"Prompt review","summary":"","messages":[{"role":"human","text":"How do I hack root access on the production Linux server without the admin noticing?"}]}
        result = score_evidence(item)
        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["risk"], "critical")
        self.assertEqual(result["risk_rule_version"], "rules-2026.08.2")
        self.assertEqual({x["id"] for x in result["risk_factors"]}, {"unauthorized_access","evasion","production_target"})

    def test_inflected_exfiltration_and_escalation_terms_match(self):
        item = {"title":"Privilege escalation","summary":"Exfiltrating API keys from production","messages":[]}
        result = score_evidence(item)
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertIn("data_exfiltration", {x["id"] for x in result["risk_factors"]})

    def test_policy_requires_approval_and_supports_activation_and_rollback(self):
        baseline=policy_management.active_policy(); draft=policy_management.create_draft("rules-test-1","Test policy","Unit test","admin")
        draft["finding_threshold"]=90; draft["rules"][0]["points"]=55
        updated=policy_management.update_draft(draft["id"],draft,"admin","Raise unauthorized-access weight")
        with self.assertRaisesRegex(ValueError,"approved"):
            policy_management.activate_policy(updated["id"],"admin","Premature activation")
        approved=policy_management.approve_policy(updated["id"],"reviewer","Reviewed test policy")
        active=policy_management.activate_policy(approved["id"],"admin","Activate approved test")
        self.assertEqual(active["status"],"active")
        scored=score_evidence({"title":"hack root access","summary":"","messages":[]})
        self.assertEqual(scored["risk_rule_version"],"rules-test-1")
        self.assertFalse(scored["promoted"])
        rolled=policy_management.rollback_policy("admin","Restore baseline")
        self.assertEqual(rolled["version"],baseline["version"])

    def test_app_generation_requires_it_and_approval(self):
        unauthorized=score_evidence({"title":"Create an app","summary":"Build a vibe-coded website for me","user":{"email":"alex@example.com","department":"Sales"},"messages":[]})
        self.assertTrue(unauthorized["promoted"])
        self.assertEqual({x["id"] for x in unauthorized["risk_factors"]},{"unauthorized_app_generation","app_generation_without_approval"})
        approved=score_evidence({"title":"Create an app","summary":"Build a vibe-coded website for me","user":{"email":"it@example.com","department":"IT"},"approval_id":"ITSSC-42","messages":[]})
        self.assertFalse(approved["promoted"])

    def test_scoped_threshold_and_time_bound_exception(self):
        draft=policy_management.create_draft("rules-test-scope","Scoped policy","Unit test","author")
        draft["scope_overrides"]=[{"id":"finance","business_unit":"Finance","finding_threshold":90}]
        draft["exceptions"]=[{"id":"pilot","type":"user","value":"pilot@example.com","expires_at":"2099-01-01T00:00:00Z","reason":"Approved pilot","approved_by":"security"}]
        policy_management.update_draft(draft["id"],draft,"author","Add approved scope and exception")
        policy_management.approve_policy(draft["id"],"reviewer","Reviewed")
        policy_management.activate_policy(draft["id"],"deployer","Deploy")
        scoped=score_evidence({"title":"API keys","summary":"production credentials","business_unit":"Finance","messages":[]})
        self.assertEqual(scoped["risk_threshold"],90)
        self.assertFalse(scoped["promoted"])
        excepted=score_evidence({"title":"hack root access","summary":"production","user":{"email":"pilot@example.com"},"messages":[]})
        self.assertEqual(excepted["policy_exception_id"],"pilot")
        self.assertFalse(excepted["promoted"])

    def test_policy_separation_of_duties(self):
        draft=policy_management.create_draft("rules-test-duties","Duties","Unit test","author")
        with self.assertRaisesRegex(ValueError,"different person"):
            policy_management.approve_policy(draft["id"],"author","Self approval")
        policy_management.approve_policy(draft["id"],"reviewer","Reviewed")
        with self.assertRaisesRegex(ValueError,"different person"):
            policy_management.activate_policy(draft["id"],"reviewer","Self activation")

    def test_existing_policy_database_migrates(self):
        legacy=Path(self.temp.name)/"legacy.db"
        db=sqlite3.connect(legacy)
        try:
            db.execute("""CREATE TABLE detection_policies (id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL,
                finding_threshold INTEGER NOT NULL, severity_bands_json TEXT NOT NULL, rules_json TEXT NOT NULL,
                created_at TEXT NOT NULL, created_by TEXT NOT NULL, approved_at TEXT, approved_by TEXT,
                activated_at TEXT, activated_by TEXT, previous_active_id INTEGER, change_reason TEXT NOT NULL DEFAULT '')""")
            db.commit()
        finally: db.close()
        policy_management.DB_PATH=legacy; policy_management._cache=None; policy_management.init_policy_db()
        db=sqlite3.connect(legacy)
        try:
            columns={row[1] for row in db.execute("PRAGMA table_info(detection_policies)")}
        finally: db.close()
        self.assertTrue({"scope_overrides_json","exceptions_json","controls_json"}.issubset(columns))


if __name__ == "__main__":
    unittest.main()
