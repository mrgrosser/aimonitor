import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

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

    def test_delivery_success_and_retry_are_checkpointed(self):
        alert=alerts.create_alert("finding:delivery","policy","high","Deliver","Minimal summary")
        alerts.queue_delivery(alert["id"],"webhook")
        with patch.object(alerts,"_deliver") as deliver:
            self.assertEqual(alerts.process_deliveries(),{"delivered":1,"retrying":0,"failed":0}); deliver.assert_called_once()
        row=alerts.list_deliveries(alert["id"])[0]; self.assertEqual(row["status"],"delivered"); self.assertEqual(row["attempts"],1)
        second=alerts.create_alert("finding:retry","policy","medium","Retry","Minimal summary"); alerts.queue_delivery(second["id"],"teams")
        with patch.object(alerts,"_deliver",side_effect=RuntimeError("temporary failure")):
            result=alerts.process_deliveries()
        self.assertEqual(result["retrying"],1); row=alerts.list_deliveries(second["id"])[0]; self.assertEqual(row["status"],"retrying"); self.assertTrue(row["next_attempt_at"])

    def test_connector_health_never_exposes_secrets(self):
        health=alerts.connector_health(); self.assertEqual({x["id"] for x in health},{"email","teams","webhook"})
        self.assertNotIn("url",str(health).lower()); self.assertNotIn("secret",str(health).lower())

    def test_generic_webhook_is_hmac_signed(self):
        alert=alerts.create_alert("finding:signed","policy","high","Signed","Minimal summary")
        delivery=alerts.queue_delivery(alert["id"],"webhook")
        with patch.object(alerts,"ALERT_WEBHOOK_URL","https://collector.example/alerts"), patch.object(alerts,"ALERT_WEBHOOK_SECRET",b"test-secret"), patch.object(alerts,"_post_json") as post:
            alerts._deliver("webhook",alert,delivery)
        url,payload,headers=post.call_args.args
        body=alerts.json.dumps(payload,separators=(",",":"),sort_keys=True).encode()
        expected=alerts.hmac.new(b"test-secret",body,alerts.hashlib.sha256).hexdigest()
        self.assertEqual(url,"https://collector.example/alerts"); self.assertEqual(headers["X-JO-Signature-256"],f"sha256={expected}")

    def test_terminal_delivery_failure_stops_retrying(self):
        alert=alerts.create_alert("finding:terminal","policy","high","Terminal","Minimal summary"); alerts.queue_delivery(alert["id"],"email")
        with patch.object(alerts,"DELIVERY_MAX_ATTEMPTS",1), patch.object(alerts,"_deliver",side_effect=RuntimeError("permanent failure")):
            result=alerts.process_deliveries()
        self.assertEqual(result["failed"],1); self.assertEqual(alerts.list_deliveries(alert["id"])[0]["status"],"failed")

    def test_stuck_processing_rows_are_reclaimed_after_staleness(self):
        alert=alerts.create_alert("finding:stuck","policy","high","Stuck","Minimal summary"); delivery=alerts.queue_delivery(alert["id"],"webhook")
        stale=(datetime.now(timezone.utc)-timedelta(seconds=alerts.PROCESSING_STALE_SECONDS+60)).isoformat()
        with alerts.closing(alerts.sqlite3.connect(alerts.DB_PATH)) as db:
            db.execute("UPDATE alert_deliveries SET status='processing',last_attempt_at=? WHERE id=?",(stale,delivery["id"])); db.commit()
        with patch.object(alerts,"_deliver") as deliver:
            result=alerts.process_deliveries()
        deliver.assert_called_once(); self.assertEqual(result["delivered"],1)
        self.assertEqual(alerts.list_deliveries(alert["id"])[0]["status"],"delivered")

    def test_fresh_processing_rows_are_not_reclaimed(self):
        alert=alerts.create_alert("finding:inflight","policy","high","Inflight","Minimal summary"); delivery=alerts.queue_delivery(alert["id"],"email")
        with alerts.closing(alerts.sqlite3.connect(alerts.DB_PATH)) as db:
            db.execute("UPDATE alert_deliveries SET status='processing',last_attempt_at=? WHERE id=?",(alerts._now(),delivery["id"])); db.commit()
        with patch.object(alerts,"_deliver") as deliver:
            result=alerts.process_deliveries()
        deliver.assert_not_called(); self.assertEqual(result,{"delivered":0,"retrying":0,"failed":0})
        self.assertEqual(alerts.list_deliveries(alert["id"])[0]["status"],"processing")

if __name__=="__main__": unittest.main()
