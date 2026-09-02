import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app import governance_analytics as analytics

class GovernanceAnalyticsTests(unittest.TestCase):
    def test_repeat_findings_are_correlated_without_clear_identity(self):
        now=datetime(2026,9,3,tzinfo=timezone.utc); rows=[]
        for index in range(3): rows.append({"id":f"f{index}","created_at":(now-timedelta(days=index)).isoformat(),"surface":"Claude.ai","user":{"email":"person@example.com"},"risk_factors":[{"id":"credential_exposure"}]})
        result=analytics.correlate_findings(rows,now)
        self.assertEqual(len(result),1); self.assertEqual(result[0]["metadata"]["event_count"],3)
        self.assertNotIn("person@example.com",str(result))

    def test_budget_license_and_model_economics_alerts(self):
        data={"period":"August 2026","summary":{"claude_usage_spend":90,"claude_usage_budget":100},
            "licensing":{"claude_seats_purchased":20,"claude_seats_unassigned":4,"estimated_monthly_run_rate":500},
            "claude_models":[{"name":"Premium","requests":10,"spend":70},{"name":"Standard","requests":90,"spend":30}]}
        kinds={x["alert_type"] for x in analytics.usage_alerts(data)}
        self.assertEqual(kinds,{"budget","unused_license","model_economics"})

    def test_run_rate_alert_is_explicitly_configured(self):
        data={"period":"August 2026","summary":{},"licensing":{"estimated_monthly_run_rate":600},"claude_models":[]}
        with patch.object(analytics,"RUN_RATE_LIMIT",500): result=analytics.usage_alerts(data)
        self.assertEqual(result[0]["alert_type"],"cost")

if __name__=="__main__": unittest.main()
