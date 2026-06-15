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
from security_core.ip2location import DEFAULT_SOURCE_DIR, EXPECTED_CSV_FILES, discover_sources, import_ip2location_lite_sources
from security_core.repository import backfill_ip_geo, preview_ip_geo_backfill


def timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def backup_database() -> Path:
    backup_path = DB_PATH.with_name(f"{DB_PATH.name}.bak-ip2location-{timestamp_slug()}")
    with connect() as source:
        with sqlite3.connect(backup_path) as target:
            source.backup(target)
    return backup_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import IP2Location LITE DB11 IPv4/IPv6 CSV data and backfill local geo fields.")
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help=f"CSV/ZIP file or directory. Defaults to {DEFAULT_SOURCE_DIR}.",
    )
    parser.add_argument("--apply", action="store_true", help="Write imported ranges and backfilled geo fields into SQLite.")
    parser.add_argument("--allow-partial", action="store_true", help="Allow importing only IPv4 or only IPv6 DB11 data.")
    parser.add_argument("--skip-backfill", action="store_true", help="Only import IP2Location ranges; do not update event/log rows.")
    parser.add_argument("--no-backup", action="store_true", help="Skip the SQLite backup before writing.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    init_db()
    source_paths = [Path(value) for value in args.source] if args.source else [DEFAULT_SOURCE_DIR]
    sources = discover_sources(source_paths)
    found = {source.csv_name for source in sources}
    missing = [name for name in EXPECTED_CSV_FILES if name not in found]

    print(f"[INFO] DB: {DB_PATH}")
    print(f"[INFO] Source paths: {', '.join(str(path) for path in source_paths)}")
    for source in sources:
        member = f"#{source.zip_member}" if source.zip_member else ""
        print(f"[INFO] Found {source.csv_name}: {source.path}{member}")

    if missing and not args.allow_partial:
        print("[ERROR] Missing required IP2Location DB11 files:")
        for name in missing:
            print(f"  - {name} or {name}.ZIP")
        print("[INFO] Put the official downloaded files in the source directory, or pass --source with the exact file path.")
        return 2
    if not sources:
        print("[ERROR] No IP2Location DB11 CSV or ZIP files were found.")
        return 2

    if not args.apply:
        print("[INFO] Dry run only. Re-run with --apply to import and backfill.")
        return 0

    if not args.no_backup:
        backup_path = backup_database()
        print(f"[OK] Backup created: {backup_path}")

    counts = import_ip2location_lite_sources(sources)
    print(
        "[OK] Imported ranges: ipv4={ipv4} ipv6={ipv6}".format(
            ipv4=counts.get("IP2LOCATION-LITE-DB11.CSV", 0),
            ipv6=counts.get("IP2LOCATION-LITE-DB11.IPV6.CSV", 0),
        )
    )

    if args.skip_backfill:
        return 0

    preview = preview_ip_geo_backfill()
    print(
        "[INFO] Backfill preview: accessLogUpdates={accessLogUpdates} rawEventUpdates={rawEventUpdates} "
        "rawEventMatches={rawEventMatches}".format(**preview)
    )
    result = backfill_ip_geo()
    print(
        "[OK] Geo backfill complete: accessLogs={accessLogs} events={events} aggregates={aggregates} "
        "rawEventGeoUpdates={rawEventGeoUpdates}".format(**result)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
