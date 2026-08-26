import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import case_management as cases


class CaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.db=Path(self.temp.name)/"cases.db"; self.patch=patch.object(cases,"DB_PATH",self.db); self.attach_patch=patch.object(cases,"ATTACHMENT_DIR",Path(self.temp.name)/"attachments"); self.patch.start(); self.attach_patch.start(); cases.init_case_db()
        self.finding={"id":"finding-1","title":"Root access","risk":"critical","risk_score":80,"surface":"Claude.ai","user":{"email":"person@example.com"},"risk_factors":[{"id":"unauthorized_access","points":45}]}

    def tearDown(self): self.attach_patch.stop(); self.patch.stop(); self.temp.cleanup()

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

    def test_comments_attachments_holds_bulk_and_saved_queues(self):
        first=cases.create_case("First","Scope","high","",None,[],"creator",self.finding)
        second=cases.create_case("Second","Scope","medium","",None,[],"creator")
        first=cases.add_comment(first["id"],"Initial review","analyst")
        reply_to=first["comments"][0]["id"]
        first=cases.add_comment(first["id"],"Follow-up","reviewer",reply_to)
        first=cases.save_attachment(first["id"],"evidence.txt","text/plain",b"preserved evidence","analyst")
        metadata,path=cases.get_attachment(first["id"],first["attachments"][0]["id"])
        self.assertEqual(path.read_bytes(),b"preserved evidence")
        self.assertEqual(len(first["comments"]),2)
        held=cases.set_legal_hold(first["id"],True,"Pending legal review","admin")
        self.assertTrue(held["legal_hold"])
        updated=cases.bulk_update([first["id"],second["id"]],{"priority":"critical"},"analyst","Campaign escalation")
        self.assertTrue(all(x["priority"]=="critical" for x in updated))
        queue=cases.save_queue("My critical queue","analyst",{"priority":"critical","unsupported":"ignored"})
        self.assertEqual(queue["filters"],{"priority":"critical"})
        self.assertEqual(len(cases.list_queues("analyst")),1)
        cases.delete_queue(queue["id"],"analyst")
        self.assertEqual(cases.list_queues("analyst"),[])


if __name__ == "__main__": unittest.main()
