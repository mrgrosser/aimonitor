import sqlite3
from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from tools.backup_sqlite import backup


class SQLiteCutoverBackupTests(unittest.TestCase):
    def test_backup_includes_committed_wal_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source.db'
            destination=Path(folder)/'backup.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY,body TEXT)')
                db.execute("INSERT INTO evidence VALUES (1,'retained')")
                db.commit()
                backup(source,destination)
                with closing(sqlite3.connect(destination)) as saved:
                    self.assertEqual(saved.execute('SELECT * FROM evidence').fetchall(),[(1,'retained')])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],1)

    def test_backup_refuses_to_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source.db'
            destination=Path(folder)/'backup.db'
            with closing(sqlite3.connect(source)) as db:
                db.execute('CREATE TABLE evidence (id INTEGER)')
                db.commit()
            destination.write_bytes(b'existing backup')
            with self.assertRaises(FileExistsError):backup(source,destination)
            self.assertEqual(destination.read_bytes(),b'existing backup')
