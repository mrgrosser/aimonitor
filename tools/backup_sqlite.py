"""Create a consistent SQLite backup before the PostgreSQL cutover."""
import argparse
from contextlib import closing
from pathlib import Path
import sqlite3


def backup(source, destination):
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    # Exclusive creation prevents accidental replacement of an earlier backup.
    with destination.open('xb'):
        pass
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as reader:
        with closing(sqlite3.connect(destination)) as writer:
            reader.backup(writer)
            if writer.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Backup integrity check failed')
    return destination


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--destination',required=True)
    args=parser.parse_args()
    print(backup(args.source,args.destination))
