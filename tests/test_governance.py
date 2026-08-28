import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
