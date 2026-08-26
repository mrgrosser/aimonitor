import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import case_management as cases


class CaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.db=Path(self.temp.name)/"cases.db"; self.patch=patch.object(cases,"DB_PATH",self.db); self.patch.start(); cases.init_case_db()
        self.finding={"id":"finding-1","title":"Root access","risk":"critical","risk_score":80,"surface":"Claude.ai","user":{"email":"person@example.com"},"risk_factors":[{"id":"unauthorized_access","points":45}]}

    def tearDown(self): self.patch.stop(); self.temp.cleanup()

    def test_case_workflow_preserves_evidence_and_timeline(self):
        case=cases.create_case("Root access review","Investigate scope","critical","analyst@example.com",None,["access"],"creator",self.finding)
        self.assertEqual(len(case["findings"]),1)
        case=cases.update_case(case["id"],{"status":"investigating","priority":"high"},"analyst","Triage complete")
        case=cases.add_note(case["id"],"Validated the source evidence.","analyst")
        self.assertEqual(case["status"],"investigating")
        self.assertTrue(any(x["event_type"]=="analyst_note" for x in case["timeline"]))
        self.assertEqual(case["findings"][0]["id"],"finding-1")

    def test_closure_requires_disposition(self):
        case=cases.create_case("Review","Scope","medium","",None,[],"creator")
        with self.assertRaises(ValueError): cases.update_case(case["id"],{"status":"closed"},"analyst")
        closed=cases.update_case(case["id"],{"status":"closed","disposition":"Confirmed and remediated"},"analyst","Review completed")
        self.assertEqual(closed["status"],"closed")

    def test_case_pdf_and_queue(self):
        case=cases.create_case("Evidence package","Scope","high","owner",None,[],"creator",self.finding)
        payload=cases.case_pdf(case,"auditor","0.8.0")
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertEqual(cases.list_cases()[0]["finding_count"],1)


if __name__ == "__main__": unittest.main()
