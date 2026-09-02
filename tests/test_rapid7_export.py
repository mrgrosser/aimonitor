import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import rapid7_export as rapid7

class Rapid7ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); rapid7.DB_PATH=Path(self.temp.name)/"rapid7.db"; rapid7.init_rapid7_db()
    def tearDown(self): self.temp.cleanup()

    def enable(self):
        with patch.object(rapid7,"RAPID7_WEBHOOK_URL","https://example.invalid/hook"):
            return rapid7.update_config(True,["authentication","audit"],rapid7.DEFAULT_FIELDS,"admin","Approved pilot")

    def test_secure_default_and_field_prohibition(self):
        self.assertFalse(rapid7.get_config()["enabled"])
        with self.assertRaisesRegex(ValueError,"prohibited"): rapid7.update_config(False,["audit"],["event_id","timestamp","prompt"],"admin","Bad field")

    def test_audit_event_uses_allowlist_and_deduplicates(self):
        self.enable()
        entry={"entry_hash":"hash-1","created_at":"2026-09-03T12:00:00Z","actor":"admin","action":"login_succeeded","object_type":"session","object_id":"","source_ip":"10.0.0.1","details":{"prompt":"never export"}}
        self.assertTrue(rapid7.enqueue_audit_event(entry)); self.assertFalse(rapid7.enqueue_audit_event(entry))
        db=rapid7.sqlite3.connect(rapid7.DB_PATH)
        try: payload=rapid7.json.loads(db.execute("SELECT payload_json FROM rapid7_outbox").fetchone()[0])
        finally: db.close()
        self.assertNotIn("details",payload); self.assertNotIn("prompt",str(payload)); self.assertEqual(payload["category"],"authentication")

    def test_delivery_retry_and_health(self):
        self.enable(); rapid7.enqueue_audit_event({"entry_hash":"hash-2","created_at":"2026-09-03T12:00:00Z","actor":"admin","action":"audit_viewed","object_type":"audit","source_ip":""})
        with patch.object(rapid7,"_post",side_effect=RuntimeError("temporary")): result=rapid7.process_outbox()
        self.assertEqual(result["retrying"],1); self.assertEqual(rapid7.health()["pending"],1)

if __name__=="__main__": unittest.main()
