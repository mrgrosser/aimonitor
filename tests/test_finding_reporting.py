import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.finding_reporting import filter_findings, findings_csv, findings_pdf, findings_summary, findings_trends


class FindingReportingTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"id":"one","created_at":"2026-05-03T12:00:00Z","risk":"critical","risk_score":80,"risk_factors":[{"id":"unauthorized_access","points":45}],"risk_rule_version":"rules-2026.08.2","status":"open","surface":"Claude.ai","title":"Root access","user":{"email":"person@example.com"}},
            {"id":"two","created_at":"2026-06-15T12:00:00Z","risk":"high","risk_score":70,"risk_factors":[{"id":"credential_exposure","points":25}],"risk_rule_version":"rules-2026.08.2","status":"review","surface":"Claude Code","title":"Credentials","user":{"email":"other@example.com"}},
        ]

    def test_custom_date_and_severity_filters(self):
        result = filter_findings(self.rows,"2026-06-01","2026-06-30","high","all")
        self.assertEqual([x["id"] for x in result],["two"])
        with self.assertRaises(ValueError): filter_findings(self.rows,"2026-07-01","2026-06-01")

    def test_named_users_are_restricted_by_default(self):
        restricted=findings_summary(self.rows)
        named=findings_summary(self.rows,True)
        self.assertEqual(restricted["findings"][0]["identity"],"Restricted")
        self.assertEqual(named["findings"][0]["identity"],"person@example.com")
        self.assertIn(b"Restricted",findings_csv(restricted))

    def test_monthly_trends_and_pdf(self):
        trends=findings_trends(self.rows)
        self.assertEqual([x["period"] for x in trends],["2026-05","2026-06"])
        report=findings_summary(self.rows)
        pdf=findings_pdf(report,"tester","0.7.2",{"date_from":"","date_to":"","risk":"all","surface":"all"})
        self.assertTrue(pdf.startswith(b"%PDF"))


if __name__ == "__main__": unittest.main()
