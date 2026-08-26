import unittest

from app.governance import score_evidence


class GovernanceScoringTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
