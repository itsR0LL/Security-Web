from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import (
    AGGREGATE_RETENTION_LABEL,
    DATA_DIR,
    DB_PATH,
    DEFAULT_HIGH_RISK_THRESHOLD,
    DEFAULT_MONITORED_HOST,
    DEFAULT_RAW_RETENTION_DAYS,
    DEFAULT_REFRESH_INTERVAL_HOURS,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_data_dir() -> None:
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    ensure_data_dir()
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS raw_events (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        event_id TEXT,
        occurred_at TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT '',
        region TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '',
        latitude REAL NOT NULL DEFAULT 0,
        longitude REAL NOT NULL DEFAULT 0,
        location_precision TEXT NOT NULL DEFAULT 'estimated',
        asn TEXT NOT NULL DEFAULT '',
        method TEXT NOT NULL DEFAULT 'GET',
        host TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '/',
        query TEXT,
        status_code INTEGER NOT NULL DEFAULT 0,
        user_agent TEXT NOT NULL DEFAULT '',
        referer TEXT,
        ray_id TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL DEFAULT 'allow',
        rule_id TEXT NOT NULL DEFAULT '',
        rule_name TEXT NOT NULL DEFAULT '',
        event_type TEXT NOT NULL DEFAULT '',
        risk_level TEXT NOT NULL DEFAULT 'info',
        confidence REAL NOT NULL DEFAULT 0,
        summary TEXT NOT NULL DEFAULT '',
        rule_matches_json TEXT NOT NULL DEFAULT '[]',
        raw_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_raw_events_occurred_at ON raw_events (occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_risk ON raw_events (risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_type ON raw_events (event_type)",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_ip ON raw_events (client_ip)",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_country ON raw_events (country)",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_action ON raw_events (action)",
    """
    CREATE TABLE IF NOT EXISTS event_aggregates (
        id TEXT PRIMARY KEY,
        bucket_type TEXT NOT NULL,
        bucket_start TEXT NOT NULL,
        dimension TEXT NOT NULL,
        dimension_value TEXT NOT NULL,
        total_count INTEGER NOT NULL DEFAULT 0,
        threat_count INTEGER NOT NULL DEFAULT 0,
        blocked_count INTEGER NOT NULL DEFAULT 0,
        challenge_count INTEGER NOT NULL DEFAULT 0,
        bandwidth_bytes INTEGER NOT NULL DEFAULT 0,
        cached_bytes INTEGER NOT NULL DEFAULT 0,
        origin_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_event_aggregates_bucket ON event_aggregates (bucket_type, bucket_start)",
    "CREATE INDEX IF NOT EXISTS idx_event_aggregates_dimension ON event_aggregates (dimension, dimension_value)",
    """
    CREATE TABLE IF NOT EXISTS sync_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        from_time TEXT,
        to_time TEXT,
        event_count INTEGER NOT NULL DEFAULT 0,
        aggregate_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        used_stale_data INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS token_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL,
        zone_read INTEGER NOT NULL DEFAULT 0,
        analytics_read INTEGER NOT NULL DEFAULT 0,
        security_events_read INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        rule_type TEXT NOT NULL,
        condition_json TEXT NOT NULL DEFAULT '{}',
        severity TEXT NOT NULL DEFAULT 'medium',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        rule_id TEXT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        message_text TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
]


DEFAULT_RULES = [
    (
        "builtin-sensitive-path",
        "敏感路径探测",
        "path_keyword",
        '{"keywords":[".env","wp-login.php","phpmyadmin","/admin"]}',
        "high",
    ),
    (
        "builtin-sqli",
        "疑似 SQL 注入",
        "query_keyword",
        '{"keywords":[" OR 1=1","UNION SELECT","--"]}',
        "high",
    ),
    (
        "builtin-xss",
        "疑似 XSS",
        "query_keyword",
        '{"keywords":["<script","javascript:","onerror="]}',
        "medium",
    ),
    (
        "builtin-scanner-ua",
        "可疑 User-Agent",
        "user_agent_keyword",
        '{"keywords":["curl","zgrab","python-requests","Go-http-client"]}',
        "medium",
    ),
    (
        "builtin-cloudflare-action",
        "Cloudflare 处置动作",
        "cloudflare_action",
        '{"actions":["block","challenge","managed_challenge"]}',
        "high",
    ),
]


def _insert_default_state(connection: sqlite3.Connection) -> None:
    defaults = {
        "monitored_host": DEFAULT_MONITORED_HOST,
        "refresh_interval_hours": str(DEFAULT_REFRESH_INTERVAL_HOURS),
        "high_risk_threshold": DEFAULT_HIGH_RISK_THRESHOLD,
        "raw_retention_days": str(DEFAULT_RAW_RETENTION_DAYS),
        "aggregate_retention": AGGREGATE_RETENTION_LABEL,
    }
    for key, value in defaults.items():
        connection.execute(
            "INSERT OR IGNORE INTO app_state (key, value) VALUES (?, ?)",
            (key, value),
        )


def _insert_default_rules(connection: sqlite3.Connection) -> None:
    now = utc_now()
    for rule_id, name, rule_type, condition_json, severity in DEFAULT_RULES:
        connection.execute(
            """
            INSERT OR IGNORE INTO rules (
                id, name, enabled, rule_type, condition_json, severity, created_at, updated_at
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (rule_id, name, rule_type, condition_json, severity, now, now),
        )


def init_db() -> None:
    ensure_data_dir()
    with db_session() as connection:
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        _insert_default_state(connection)
        _insert_default_rules(connection)

