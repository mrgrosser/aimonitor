from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from tools.verify_sqlite_restore import verify

class RestoreTests(unittest.TestCase):
    def test_read_only_check_and_missing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'restore.db'
            with self.assertRaises(FileNotFoundError):verify(path)
            self.assertFalse(path.exists())
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE example (id INTEGER)')
                db.execute('INSERT INTO example VALUES (1)')
                db.commit()
            before=path.read_bytes()
            result=verify(path)
            self.assertTrue(result['integrity_ok'])
            self.assertEqual(result['table_counts'],{'example':1})
            self.assertEqual(before,path.read_bytes())
