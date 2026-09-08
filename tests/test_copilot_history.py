import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import closing
from app import copilot_analytics as c

class HistoryTests(unittest.TestCase):
    def test_cached_backfill_snapshot_retention_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(c.usage_reporting,'DB_PATH',str(Path(tmp)/'usage.db')):
            def report(refresh, rows):
                return {'period':'Copilot - last 180 days','report_refresh_date':refresh,'collected_at':refresh+'T00:00:00+00:00','copilot_user_trend':[{'Date':d,'Active users':n} for d,n in rows]}
            old=report('2026-09-01',[('2026-08-01',3),('2026-08-02',0)])
            with closing(c.database()) as db:
                db.execute('INSERT INTO copilot_analytics VALUES (?,?)',(old['period'],json.dumps(old)));db.commit()
            monthly=c.saved('Copilot - month 2026-08')
            self.assertEqual(len(monthly['copilot_user_trend']),2)
            self.assertIn('2 of 31',monthly['caveats'][0])
            self.assertNotIn('copilot_active_users',monthly['summary'])
            with closing(c.database()) as db:
                db.execute('INSERT INTO copilot_snapshots VALUES (?,?,?)',(old['period'],old['report_refresh_date'],json.dumps(old)))
                new=report('2026-09-02',[('2026-08-01',4),('2026-09-01',9)])
                db.execute('UPDATE copilot_analytics SET payload=?',(json.dumps(new),));db.commit()
            rows=c.saved('Copilot - month 2026-08')['copilot_user_trend']
            self.assertEqual([r['Active users'] for r in rows],[4,0])
            self.assertIsNone(c.saved('Copilot - month 2026-07'))
            self.assertIn({'period':'Copilot - month 2026-08'},c.periods())
