from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_core.config import DB_PATH
from security_core.database import connect, init_db
from security_core.repository import backfill_worker_log_geo, preview_worker_log_geo_backfill


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def backup_database() -> Path:
    backup_path = DB_PATH.with_name(f"{DB_PATH.name}.bak-{timestamp_slug()}")
    with connect() as source:
        with sqlite3.connect(backup_path) as target:
            source.backup(target)
    return backup_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recompute local Worker log geolocation fields from stored raw logs.")
    parser.add_argument("--apply", action="store_true", help="Write corrected geolocation fields into the local SQLite DB.")
    parser.add_argument("--no-backup", action="store_true", help="Skip the SQLite backup before writing.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    init_db()
    preview = preview_worker_log_geo_backfill()
    print(f"[INFO] DB: {DB_PATH}")
    print(
        "[INFO] Preview: accessLogs={accessLogs} accessLogUpdates={accessLogUpdates} "
        "eventUpdates={eventUpdates} chengduCorrections={chengduCorrections}".format(**preview)
    )

    if not args.apply:
        print("[INFO] Dry run only. Re-run with --apply to update the local DB.")
        return 0

    if not args.no_backup:
        backup_path = backup_database()
        print(f"[OK] Backup created: {backup_path}")

    result = backfill_worker_log_geo()
    print(
        "[OK] Backfill complete: accessLogs={accessLogs} events={events} aggregates={aggregates}".format(
            **result
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
