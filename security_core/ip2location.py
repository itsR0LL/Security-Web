from __future__ import annotations

import csv
import ipaddress
import sqlite3
import zipfile
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import DATA_DIR
from .database import db_session, utc_now


PROVIDER = "ip2location_lite"
EDITION = "DB11"
DEFAULT_SOURCE_DIR = DATA_DIR / "ip2location"
IP_KEY_WIDTH = 39
IPV4_CSV_NAME = "IP2LOCATION-LITE-DB11.CSV"
IPV6_CSV_NAME = "IP2LOCATION-LITE-DB11.IPV6.CSV"
CSV_ENCODING = "latin-1"
EXPECTED_CSV_FILES = {
    IPV4_CSV_NAME: 4,
    IPV6_CSV_NAME: 6,
}


@dataclass(frozen=True)
class ImportSource:
    path: Path
    csv_name: str
    ip_version: int
    zip_member: str | None = None


def _text(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text == "-" else text


def ip_key(value: Any) -> str:
    address = ipaddress.ip_address(_text(value))
    return str(int(address)).zfill(IP_KEY_WIDTH)


def _decimal_ip_key(value: str, *, ip_version: int, line_number: int, csv_name: str) -> str:
    try:
        number = int(value)
    except ValueError as error:
        raise ValueError(f"{csv_name}:{line_number} has a non-integer IP boundary: {value!r}") from error
    max_value = (2**32 - 1) if ip_version == 4 else (2**128 - 1)
    if number < 0 or number > max_value:
        raise ValueError(f"{csv_name}:{line_number} IP boundary is outside IPv{ip_version} range: {value!r}")
    return str(number).zfill(IP_KEY_WIDTH)


def _float(value: str, *, csv_name: str, line_number: int, field_name: str) -> float:
    text = _text(value)
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError as error:
        raise ValueError(f"{csv_name}:{line_number} has invalid {field_name}: {value!r}") from error


def _expected_csv_name(path: Path) -> tuple[str, int] | None:
    name = path.name.upper()
    expected_by_upper_name = {csv_name.upper(): (csv_name, ip_version) for csv_name, ip_version in EXPECTED_CSV_FILES.items()}
    if name in expected_by_upper_name:
        return expected_by_upper_name[name]
    if name.endswith(".ZIP"):
        csv_name = name[:-4]
        if csv_name in expected_by_upper_name:
            return expected_by_upper_name[csv_name]
    return None


def _zip_member_for_csv(path: Path, csv_name: str) -> str:
    expected_name = csv_name.upper()
    with zipfile.ZipFile(path) as archive:
        for member in archive.namelist():
            if Path(member).name.upper() == expected_name:
                return member
    raise FileNotFoundError(f"{path} does not contain {csv_name}")


def discover_sources(paths: Iterable[Path] | None = None) -> list[ImportSource]:
    raw_paths = list(paths or [DEFAULT_SOURCE_DIR])
    sources: list[ImportSource] = []
    for raw_path in raw_paths:
        path = Path(raw_path)
        if path.is_dir():
            children = sorted(child for child in path.iterdir() if child.is_file())
        else:
            children = [path]
        for child in children:
            expected = _expected_csv_name(child)
            if expected is None:
                continue
            csv_name, ip_version = expected
            zip_member = _zip_member_for_csv(child, csv_name) if child.name.upper().endswith(".ZIP") else None
            sources.append(ImportSource(path=child, csv_name=csv_name, ip_version=ip_version, zip_member=zip_member))
    return sources


def _open_source(source: ImportSource) -> Iterator[list[str]]:
    if source.zip_member:
        with zipfile.ZipFile(source.path) as archive:
            with archive.open(source.zip_member) as binary_file:
                text_file = TextIOWrapper(binary_file, encoding=CSV_ENCODING, newline="")
                yield from csv.reader(line.replace("\x00", "") for line in text_file)
    else:
        with source.path.open("r", encoding=CSV_ENCODING, newline="") as text_file:
            yield from csv.reader(line.replace("\x00", "") for line in text_file)


def _import_rows(connection: sqlite3.Connection, source: ImportSource, imported_at: str, batch_size: int) -> int:
    rows: list[tuple[Any, ...]] = []
    count = 0
    for line_number, row in enumerate(_open_source(source), start=1):
        if len(row) < 10:
            raise ValueError(f"{source.csv_name}:{line_number} has {len(row)} fields; DB11 requires 10 fields")
        item = (
            PROVIDER,
            EDITION,
            source.ip_version,
            _decimal_ip_key(row[0], ip_version=source.ip_version, line_number=line_number, csv_name=source.csv_name),
            _decimal_ip_key(row[1], ip_version=source.ip_version, line_number=line_number, csv_name=source.csv_name),
            _text(row[2]).upper(),
            _text(row[3]),
            _text(row[4]),
            _text(row[5]),
            _float(row[6], csv_name=source.csv_name, line_number=line_number, field_name="latitude"),
            _float(row[7], csv_name=source.csv_name, line_number=line_number, field_name="longitude"),
            _text(row[8]),
            _text(row[9]),
            imported_at,
        )
        rows.append(item)
        if len(rows) >= batch_size:
            connection.executemany(
                """
                INSERT INTO ip2location_ranges (
                    provider, edition, ip_version, ip_from_key, ip_to_key,
                    country_code, country_name, region_name, city_name,
                    latitude, longitude, zip_code, time_zone, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            count += len(rows)
            rows.clear()
    if rows:
        connection.executemany(
            """
            INSERT INTO ip2location_ranges (
                provider, edition, ip_version, ip_from_key, ip_to_key,
                country_code, country_name, region_name, city_name,
                latitude, longitude, zip_code, time_zone, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        count += len(rows)
    return count


def import_ip2location_lite_sources(sources: list[ImportSource], *, batch_size: int = 5000) -> dict[str, int]:
    imported_at = utc_now()
    counts = {IPV4_CSV_NAME: 0, IPV6_CSV_NAME: 0}
    with db_session() as connection:
        connection.execute("DELETE FROM ip2location_ranges WHERE provider = ? AND edition = ?", (PROVIDER, EDITION))
        for source in sources:
            counts[source.csv_name] += _import_rows(connection, source, imported_at, batch_size)
    return counts


def lookup_ip_location(client_ip: Any, connection: sqlite3.Connection) -> dict[str, Any] | None:
    text = _text(client_ip)
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    key = str(int(address)).zfill(IP_KEY_WIDTH)
    row = connection.execute(
        """
        SELECT *
        FROM ip2location_ranges
        WHERE provider = ?
          AND edition = ?
          AND ip_version = ?
          AND ip_from_key <= ?
        ORDER BY ip_from_key DESC
        LIMIT 1
        """,
        (PROVIDER, EDITION, address.version, key),
    ).fetchone()
    if not row or str(row["ip_to_key"]) < key:
        return None
    if not str(row["country_code"] or "").strip():
        return None
    return {
        "source": PROVIDER,
        "edition": EDITION,
        "countryCode": row["country_code"],
        "countryName": row["country_name"],
        "regionName": row["region_name"],
        "cityName": row["city_name"],
        "latitude": row["latitude"],
        "longitude": row["longitude"],
        "zipCode": row["zip_code"],
        "timeZone": row["time_zone"],
    }
