import tempfile
import unittest
from pathlib import Path

from app import alert_management as alerts

class AlertManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); alerts.DB_PATH=Path(self.temp.name)/"alerts.db"; alerts.init_alert_db()
    def tearDown(self): self.temp.cleanup()

    def test_alert_lifecycle_and_timeline(self):
        alert=alerts.create_alert("finding:one","policy","high","Approval missing","Minimal summary","finding-1",actor="system")
        alert=alerts.update_alert(alert["id"],{"owner":"analyst","status":"acknowledged"},"analyst","Accepted for review")
        self.assertEqual(alert["owner"],"analyst"); self.assertEqual(alert["acknowledged_by"],"analyst")
        alert=alerts.update_alert(alert["id"],{"escalation":"incident_response"},"analyst","Confirmed security scope")
        self.assertEqual(alert["escalation"],"incident_response"); self.assertEqual(len(alerts.alert_timeline(alert["id"])),3)

    def test_duplicate_event_and_delivery_are_idempotent(self):
        first=alerts.create_alert("finding:one","policy","high","First","Summary")
        second=alerts.create_alert("finding:one","policy","critical","Duplicate","Summary")
        self.assertEqual(first["id"],second["id"])
        one=alerts.queue_delivery(first["id"],"teams"); two=alerts.queue_delivery(first["id"],"teams")
        self.assertEqual(one["id"],two["id"])

    def test_suppression_requires_expiration_and_reason(self):
        alert=alerts.create_alert("finding:two","policy","medium","Review","Summary")
        with self.assertRaisesRegex(ValueError,"expiration"): alerts.update_alert(alert["id"],{"status":"suppressed"},"analyst","Pilot")
        with self.assertRaisesRegex(ValueError,"reason"): alerts.update_alert(alert["id"],{"owner":"analyst"},"analyst","")
        suppressed=alerts.update_alert(alert["id"],{"status":"suppressed","suppressed_until":"2099-01-01T00:00:00Z"},"analyst","Approved exception")
        self.assertEqual(suppressed["status"],"suppressed")

if __name__=="__main__": unittest.main()
