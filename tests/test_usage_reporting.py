import tempfile
import unittest
from pathlib import Path

import app.usage_reporting as reporting


CSV_SAMPLE = b"""category,name,period,value,text,requests,interactions,spend,users,provider,volume,surfaces,active_days
summary,copilot_interactions,August 2026,1200,,,,,,,,,
summary,claude_requests,August 2026,900,,,,,,,,,
summary,claude_usage_spend,August 2026,45.50,,,,,,,,,
licensing,estimated_monthly_run_rate,August 2026,445.50,,,,,,,,,
claude_product,Chat,August 2026,,,900,,45.50,,,,,
claude_model,Claude Sonnet 5,August 2026,,,900,,45.50,,,,,
copilot_app,Outlook,August 2026,,,,1200,,40,,,,
top_user,user@example.com,August 2026,,,,,12,,Claude Enterprise,400,2,10
caveat,Usage is not a performance measure,August 2026,,,,,,,,,,
"""


class UsageReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        reporting.DB_PATH = Path(self.temp.name) / "usage.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_csv_import_storage_and_duplicate_protection(self):
        data, digest = reporting.parse_usage_file(CSV_SAMPLE, "august.csv")
        self.assertEqual(data["period"], "August 2026")
        self.assertEqual(data["summary"]["claude_requests"], 900)
        self.assertTrue(data["top_users"][0]["user"].startswith("User "))
        self.assertNotIn("user@example.com", str(data))
        self.assertEqual(data["validation"]["warnings"], [])
        reporting.save_usage_period(data, "august.csv", digest, "tester")
        self.assertEqual(reporting.get_usage_period("August 2026")["summary"]["copilot_interactions"], 1200)
        with self.assertRaisesRegex(ValueError, "already exists"):
            reporting.save_usage_period(data, "august.csv", digest, "tester")

    def test_report_formats(self):
        data, _ = reporting.parse_usage_file(CSV_SAMPLE, "august.csv")
        self.assertTrue(reporting.usage_pdf(data, "tester", "v0.7.0").startswith(b"%PDF"))
        self.assertIn(b"Claude product", reporting.usage_csv(data))
        self.assertIn("Print / Save PDF", reporting.usage_html(data, "tester", "v0.7.0"))

    def test_rejects_malformed_and_unsupported_files(self):
        with self.assertRaisesRegex(ValueError, "Unable to parse"):
            reporting.parse_usage_file(b"not an xlsx", "broken.xlsx")
        with self.assertRaisesRegex(ValueError, "Only .xlsx and .csv"):
            reporting.parse_usage_file(b"content", "usage.txt")


if __name__ == "__main__":
    unittest.main()
