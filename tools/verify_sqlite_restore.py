"""Read-only integrity check for a restored SQLite database; does not start the app."""
from contextlib import closing
import argparse
import json
import sqlite3
from pathlib import Path


def verify(path):
    path=Path(path).resolve(strict=True)
    if not path.is_file():raise ValueError('Expected a database file')
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
        integrity=[r[0] for r in db.execute('PRAGMA integrity_check')]
        foreign_keys=list(db.execute('PRAGMA foreign_key_check'))
        tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        counts={name:db.execute('SELECT COUNT(*) FROM "'+name.replace('"','""')+'"').fetchone()[0] for name in tables}
    return {'integrity_ok':integrity==['ok'],'foreign_key_errors':len(foreign_keys),'table_counts':counts}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database',help='Path to restored database, not the production volume')
    args=parser.parse_args()
    result=verify(args.database)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['integrity_ok'] and not result['foreign_key_errors'] else 1)
