import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app import governance, provider_store


class ProviderStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patcher = patch.object(governance, "DB_PATH", Path(self.temp.name) / "monitor.db")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_saved_data_survives_connections_and_failed_refresh(self):
        provider_store.save("activities", {"data": [{"id": "one"}]})
        before = provider_store.read("activities")
        provider_store.fail("activities")
        after = provider_store.read("activities")
        self.assertEqual(after["data"], before["data"])
        self.assertEqual(after["sync"]["last_success_at"], before["sync"]["last_success_at"])
        self.assertEqual(after["sync"]["state"], "failed")
        provider_store.save("activities", {"data": [{"id": "two"}]})
        self.assertEqual(provider_store.read("activities")["sync"]["state"], "ok")

    def test_first_failure_and_empty_store_are_explicit(self):
        self.assertEqual(provider_store.read("organizations")["sync"]["state"], "pending")
        provider_store.fail("organizations")
        self.assertEqual(provider_store.read("organizations")["data"], [])
        self.assertEqual(provider_store.read("organizations")["sync"]["state"], "failed")
