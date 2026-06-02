from __future__ import annotations

import sqlite3
import json
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
        attack_category TEXT NOT NULL DEFAULT '',
        attack_subtype TEXT NOT NULL DEFAULT '',
        tool_signature TEXT NOT NULL DEFAULT '',
        behavior_fingerprint TEXT NOT NULL DEFAULT '',
        campaign_id TEXT NOT NULL DEFAULT '',
        rule_hits_json TEXT NOT NULL DEFAULT '[]',
        ai_cluster_id TEXT NOT NULL DEFAULT '',
        rule_version TEXT NOT NULL DEFAULT '',
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
    CREATE TABLE IF NOT EXISTS access_logs (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL DEFAULT 'worker_log',
        source_cursor INTEGER NOT NULL DEFAULT 0,
        received_at TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        client_ip TEXT NOT NULL DEFAULT '',
        ip_hash TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        region TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '',
        colo TEXT NOT NULL DEFAULT '',
        latitude REAL NOT NULL DEFAULT 0,
        longitude REAL NOT NULL DEFAULT 0,
        location_precision TEXT NOT NULL DEFAULT 'estimated',
        method TEXT NOT NULL DEFAULT 'GET',
        host TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '/',
        query TEXT NOT NULL DEFAULT '',
        status_code INTEGER NOT NULL DEFAULT 0,
        user_agent TEXT NOT NULL DEFAULT '',
        referer TEXT NOT NULL DEFAULT '',
        cf_ray TEXT NOT NULL DEFAULT '',
        request_id TEXT NOT NULL DEFAULT '',
        response_bytes INTEGER NOT NULL DEFAULT 0,
        raw_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_access_logs_occurred_at ON access_logs (occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_access_logs_source_cursor ON access_logs (source, source_cursor)",
    "CREATE INDEX IF NOT EXISTS idx_access_logs_country ON access_logs (country)",
    "CREATE INDEX IF NOT EXISTS idx_access_logs_path ON access_logs (path)",
    "CREATE INDEX IF NOT EXISTS idx_access_logs_status_code ON access_logs (status_code)",
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
        version TEXT NOT NULL DEFAULT '1.0.0',
        mode TEXT NOT NULL DEFAULT 'active',
        attack_category TEXT NOT NULL DEFAULT '',
        attack_subtype TEXT NOT NULL DEFAULT '',
        tool_signature TEXT NOT NULL DEFAULT '',
        behavior_fingerprint TEXT NOT NULL DEFAULT '',
        rule_json TEXT NOT NULL DEFAULT '{}',
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
        '{"keywords":[".env",".env.local",".env.bak",".env.backup","wp-login.php","phpmyadmin","/admin","firebase-adminsdk.json","firebase.json","google-credentials.json","credentials.json","config.json","key.json"]}',
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


DEFAULT_RULE_VERSION = "2026.06.02"


DEFAULT_RULE_DEFINITIONS = [
    {
        "id": "builtin-sensitive-path",
        "name": "Sensitive path probe",
        "rule_type": "path_keyword",
        "condition": {
            "keywords": [
                ".env",
                ".env.local",
                ".env.bak",
                ".env.backup",
                "wp-login.php",
                "phpmyadmin",
                "/admin",
                "firebase-adminsdk.json",
                "firebase.json",
                "google-credentials.json",
                "credentials.json",
                "config.json",
                "key.json",
            ]
        },
        "severity": "high",
        "version": DEFAULT_RULE_VERSION,
        "mode": "active",
        "attack_category": "reconnaissance",
        "attack_subtype": "sensitive_path_probe",
        "tool_signature": "scanner_path_probe",
        "behavior_fingerprint": "http_path_keyword_probe",
    },
    {
        "id": "builtin-sqli",
        "name": "SQL injection probe",
        "rule_type": "query_keyword",
        "condition": {"keywords": [" OR 1=1", "UNION SELECT", "--"]},
        "severity": "high",
        "version": DEFAULT_RULE_VERSION,
        "mode": "active",
        "attack_category": "injection",
        "attack_subtype": "sql_injection_probe",
        "tool_signature": "manual_or_scanner_sqli",
        "behavior_fingerprint": "http_query_sqli_keyword",
    },
    {
        "id": "builtin-xss",
        "name": "XSS probe",
        "rule_type": "query_keyword",
        "condition": {"keywords": ["<script", "javascript:", "onerror="]},
        "severity": "medium",
        "version": DEFAULT_RULE_VERSION,
        "mode": "active",
        "attack_category": "injection",
        "attack_subtype": "xss_probe",
        "tool_signature": "manual_or_scanner_xss",
        "behavior_fingerprint": "http_query_xss_keyword",
    },
    {
        "id": "builtin-scanner-ua",
        "name": "Scanner User-Agent",
        "rule_type": "user_agent_keyword",
        "condition": {"keywords": ["curl", "zgrab", "python-requests", "Go-http-client"]},
        "severity": "medium",
        "version": DEFAULT_RULE_VERSION,
        "mode": "active",
        "attack_category": "reconnaissance",
        "attack_subtype": "scanner_user_agent",
        "tool_signature": "scanner_user_agent",
        "behavior_fingerprint": "http_user_agent_keyword",
    },
    {
        "id": "builtin-cloudflare-action",
        "name": "Cloudflare security action",
        "rule_type": "cloudflare_action",
        "condition": {"actions": ["block", "challenge", "managed_challenge"]},
        "severity": "high",
        "version": DEFAULT_RULE_VERSION,
        "mode": "active",
        "attack_category": "edge_security",
        "attack_subtype": "cloudflare_action",
        "tool_signature": "cloudflare_firewall",
        "behavior_fingerprint": "cloudflare_action_match",
    },
]


def versioned_rule_json(rule: dict[str, object]) -> str:
    return json.dumps(
        {
            "id": rule["id"],
            "version": rule["version"],
            "mode": rule["mode"],
            "ruleType": rule["rule_type"],
            "condition": rule["condition"],
            "severity": rule["severity"],
            "classification": {
                "attackCategory": rule["attack_category"],
                "attackSubtype": rule["attack_subtype"],
                "toolSignature": rule["tool_signature"],
                "behaviorFingerprint": rule["behavior_fingerprint"],
            },
        },
        ensure_ascii=False,
    )


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


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row["name"]) for row in rows}


def _add_missing_columns(
    connection: sqlite3.Connection,
    table_name: str,
    column_sql_by_name: dict[str, str],
) -> None:
    existing_columns = _table_columns(connection, table_name)
    for column_name, column_sql in column_sql_by_name.items():
        if column_name not in existing_columns:
            connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def _apply_schema_migrations(connection: sqlite3.Connection) -> None:
    _add_missing_columns(
        connection,
        "raw_events",
        {
            "attack_category": "attack_category TEXT NOT NULL DEFAULT ''",
            "attack_subtype": "attack_subtype TEXT NOT NULL DEFAULT ''",
            "tool_signature": "tool_signature TEXT NOT NULL DEFAULT ''",
            "behavior_fingerprint": "behavior_fingerprint TEXT NOT NULL DEFAULT ''",
            "campaign_id": "campaign_id TEXT NOT NULL DEFAULT ''",
            "rule_hits_json": "rule_hits_json TEXT NOT NULL DEFAULT '[]'",
            "ai_cluster_id": "ai_cluster_id TEXT NOT NULL DEFAULT ''",
            "rule_version": "rule_version TEXT NOT NULL DEFAULT ''",
        },
    )
    _add_missing_columns(
        connection,
        "rules",
        {
            "version": "version TEXT NOT NULL DEFAULT '1.0.0'",
            "mode": "mode TEXT NOT NULL DEFAULT 'active'",
            "attack_category": "attack_category TEXT NOT NULL DEFAULT ''",
            "attack_subtype": "attack_subtype TEXT NOT NULL DEFAULT ''",
            "tool_signature": "tool_signature TEXT NOT NULL DEFAULT ''",
            "behavior_fingerprint": "behavior_fingerprint TEXT NOT NULL DEFAULT ''",
            "rule_json": "rule_json TEXT NOT NULL DEFAULT '{}'",
        },
    )


def _insert_default_rules(connection: sqlite3.Connection) -> None:
    now = utc_now()
    for rule in DEFAULT_RULE_DEFINITIONS:
        condition_json = json.dumps(rule["condition"], ensure_ascii=False)
        rule_json = versioned_rule_json(rule)
        connection.execute(
            """
            INSERT INTO rules (
                id, name, enabled, rule_type, condition_json, severity,
                version, mode, attack_category, attack_subtype, tool_signature,
                behavior_fingerprint, rule_json, created_at, updated_at
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                rule_type = excluded.rule_type,
                condition_json = excluded.condition_json,
                severity = excluded.severity,
                version = excluded.version,
                mode = excluded.mode,
                attack_category = excluded.attack_category,
                attack_subtype = excluded.attack_subtype,
                tool_signature = excluded.tool_signature,
                behavior_fingerprint = excluded.behavior_fingerprint,
                rule_json = excluded.rule_json,
                updated_at = excluded.updated_at
            """,
            (
                rule["id"],
                rule["name"],
                rule["rule_type"],
                condition_json,
                rule["severity"],
                rule["version"],
                rule["mode"],
                rule["attack_category"],
                rule["attack_subtype"],
                rule["tool_signature"],
                rule["behavior_fingerprint"],
                rule_json,
                now,
                now,
            ),
        )


def init_db() -> None:
    ensure_data_dir()
    with db_session() as connection:
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        _apply_schema_migrations(connection)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_raw_events_attack_category ON raw_events (attack_category)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_raw_events_campaign ON raw_events (campaign_id)")
        _insert_default_state(connection)
        _insert_default_rules(connection)
