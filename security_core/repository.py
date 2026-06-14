from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .access_log_normalizer import normalize_worker_access_log, worker_access_log_to_event
from .config import (
    AGGREGATE_RETENTION_LABEL,
    CHENGDU_DESTINATION,
    DEFAULT_HIGH_RISK_THRESHOLD,
    DEFAULT_MONITORED_HOST,
    DEFAULT_RAW_RETENTION_DAYS,
    DEFAULT_REFRESH_INTERVAL_HOURS,
    RISK_ORDER,
)
from .database import db_session, utc_now
from .geo import stable_country_coordinates
from .rule_matcher import apply_rule_matching, normalize_rule_row
from .sample_data import create_sample_events, create_sample_traffic_trend


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


SENSITIVE_KEY_PARTS = ("token", "authorization", "api_key", "apikey", "secret", "password")
SPECIFIC_PRIMARY_RULE_TYPES = {"path_keyword", "query_keyword", "user_agent_keyword"}
SYNC_TYPE_CLOUDFLARE = "cloudflare"
SYNC_TYPE_WORKER_LOG = "worker_log"
COUNTRY_AGGREGATE_SOURCES = (SYNC_TYPE_CLOUDFLARE, SYNC_TYPE_WORKER_LOG)
GLOBE_PRIMARY_VISIBLE_LIMIT = 18
GLOBE_RAW_SECURITY_LIMIT = GLOBE_PRIMARY_VISIBLE_LIMIT // 2
GLOBE_RAW_COUNTRY_LIMIT = max(1, GLOBE_PRIMARY_VISIBLE_LIMIT // 4)
GLOBE_RAW_CLIENT_IP_LIMIT = 1
HOME_GLOBE_POINT_LIMIT = 72
HOME_RAW_SECURITY_LIMIT = 36
HOME_RAW_COUNTRY_LIMIT = 4
HOME_RAW_CLIENT_IP_LIMIT = 1
SECURITY_GLOBE_ACTIONS = ("block", "challenge", "managed_challenge", "js_challenge", "log", "simulate")


def _sanitize_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(part in key_text for part in SENSITIVE_KEY_PARTS):
                sanitized[key] = "[redacted]"
            else:
                sanitized[key] = _sanitize_sensitive(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_sensitive(item) for item in value]
    return value


def get_state(key: str, default: str = "") -> str:
    with db_session() as connection:
        row = connection.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_state(key: str, value: str) -> None:
    with db_session() as connection:
        connection.execute(
            "INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_int_state(key: str, default: int) -> int:
    try:
        return int(get_state(key, str(default)))
    except ValueError:
        return default


def get_monitored_host() -> str:
    return get_state("monitored_host", DEFAULT_MONITORED_HOST).strip() or DEFAULT_MONITORED_HOST


def get_cloudflare_token() -> str:
    return get_state("cloudflare_api_token", "").strip()


def get_cloudflare_zone_id() -> str:
    return get_state("cloudflare_zone_id", "").strip()


def has_cloudflare_token() -> bool:
    return bool(get_cloudflare_token())


def has_worker_log_data() -> bool:
    try:
        with db_session() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM access_logs").fetchone()
        return int(row["count"]) > 0
    except Exception:
        return False


def is_sample_mode() -> bool:
    return not has_cloudflare_token() and not has_worker_log_data()


def active_source_filter() -> tuple[str, list[Any]]:
    if is_sample_mode():
        return "source = ?", ["sample"]
    return "source != ?", ["sample"]


def parse_iso_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def event_to_row(event: dict[str, Any]) -> tuple[Any, ...]:
    now = utc_now()
    raw = event.get("raw") or {}
    return (
        event["id"],
        event.get("source", "sample"),
        event.get("id"),
        event.get("timestamp", now),
        event.get("clientIp", ""),
        event.get("country", ""),
        event.get("region", ""),
        event.get("city", ""),
        float(event.get("latitude") or 0),
        float(event.get("longitude") or 0),
        event.get("locationPrecision", "estimated"),
        event.get("asn", ""),
        event.get("method", "GET"),
        event.get("host", get_monitored_host()),
        event.get("path", "/"),
        event.get("query"),
        int(event.get("statusCode") or 0),
        event.get("userAgent", ""),
        event.get("referer"),
        event.get("rayId", ""),
        event.get("action", "allow"),
        event.get("ruleId", ""),
        event.get("ruleName", ""),
        event.get("eventType", ""),
        event.get("riskLevel", "info"),
        float(event.get("confidence") or 0),
        event.get("summary", ""),
        json.dumps(event.get("ruleMatches", []), ensure_ascii=False),
        event.get("attackCategory", ""),
        event.get("attackSubtype", ""),
        event.get("toolSignature", ""),
        event.get("behaviorFingerprint", ""),
        event.get("campaignId", ""),
        json.dumps(event.get("ruleHits", []), ensure_ascii=False),
        event.get("aiClusterId", ""),
        event.get("ruleVersion", ""),
        json.dumps(raw, ensure_ascii=False),
        now,
    )


def row_to_event(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "timestamp": row["occurred_at"],
        "source": row["source"],
        "clientIp": row["client_ip"],
        "country": row["country"],
        "region": row["region"],
        "city": row["city"],
        "latitude": row["latitude"],
        "longitude": row["longitude"],
        "locationPrecision": row["location_precision"],
        "asn": row["asn"],
        "host": row["host"],
        "method": row["method"],
        "path": row["path"],
        "query": row["query"] or None,
        "statusCode": row["status_code"],
        "userAgent": row["user_agent"],
        "referer": row["referer"] or None,
        "rayId": row["ray_id"],
        "action": row["action"],
        "ruleId": row["rule_id"],
        "ruleName": row["rule_name"],
        "eventType": row["event_type"],
        "riskLevel": row["risk_level"],
        "confidence": row["confidence"],
        "summary": row["summary"],
        "ruleMatches": _json_loads(row["rule_matches_json"], []),
        "attackCategory": row["attack_category"],
        "attackSubtype": row["attack_subtype"],
        "toolSignature": row["tool_signature"],
        "behaviorFingerprint": row["behavior_fingerprint"],
        "campaignId": row["campaign_id"],
        "ruleHits": _json_loads(row["rule_hits_json"], []),
        "aiClusterId": row["ai_cluster_id"],
        "ruleVersion": row["rule_version"],
        "raw": _sanitize_sensitive(_json_loads(row["raw_json"], {})),
    }


def _risk_rank(level: Any) -> int:
    risk_level = str(level or "info")
    return RISK_ORDER.index(risk_level) if risk_level in RISK_ORDER else RISK_ORDER.index("info")


def _select_primary_rule_hit(hits: list[dict[str, Any]]) -> dict[str, Any] | None:
    active_hits = [hit for hit in hits if hit.get("mode") == "active"]
    if not active_hits:
        return None
    specific_hits = [hit for hit in active_hits if hit.get("ruleType") in SPECIFIC_PRIMARY_RULE_TYPES]
    selected_hits = specific_hits or active_hits
    return max(selected_hits, key=lambda hit: _risk_rank(hit.get("severity")))


def _apply_primary_rule_precedence(event: dict[str, Any]) -> dict[str, Any]:
    hits = event.get("ruleHits")
    if not isinstance(hits, list):
        return event
    primary_hit = _select_primary_rule_hit([hit for hit in hits if isinstance(hit, dict)])
    if not primary_hit:
        return event

    event["ruleId"] = primary_hit.get("ruleId", "")
    event["ruleName"] = primary_hit.get("ruleName", "")
    event["attackCategory"] = primary_hit.get("attackCategory", "")
    event["attackSubtype"] = primary_hit.get("attackSubtype", "")
    event["toolSignature"] = primary_hit.get("toolSignature", "")
    event["behaviorFingerprint"] = primary_hit.get("behaviorFingerprint", "")
    event["ruleVersion"] = primary_hit.get("version", event.get("ruleVersion", ""))
    if primary_hit.get("attackSubtype"):
        event["eventType"] = primary_hit["attackSubtype"]

    raw = event.get("raw")
    if isinstance(raw, dict):
        raw["primaryRuleId"] = event["ruleId"]
        raw["primaryRuleType"] = primary_hit.get("ruleType", "")
    return event


def insert_events(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    with db_session() as connection:
        rule_rows = connection.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
        rules = [normalize_rule_row(row) for row in rule_rows]
        matched_events = [_apply_primary_rule_precedence(apply_rule_matching(event, rules)) for event in events]
        connection.executemany(
            """
            INSERT INTO raw_events (
                id, source, event_id, occurred_at, client_ip, country, region, city,
                latitude, longitude, location_precision, asn, method, host, path, query,
                status_code, user_agent, referer, ray_id, action, rule_id, rule_name,
                event_type, risk_level, confidence, summary, rule_matches_json,
                attack_category, attack_subtype, tool_signature, behavior_fingerprint,
                campaign_id, rule_hits_json, ai_cluster_id, rule_version, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source = excluded.source,
                event_id = excluded.event_id,
                occurred_at = excluded.occurred_at,
                client_ip = excluded.client_ip,
                country = excluded.country,
                region = excluded.region,
                city = excluded.city,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                location_precision = excluded.location_precision,
                asn = excluded.asn,
                method = excluded.method,
                host = excluded.host,
                path = excluded.path,
                query = excluded.query,
                status_code = excluded.status_code,
                user_agent = excluded.user_agent,
                referer = excluded.referer,
                ray_id = excluded.ray_id,
                action = excluded.action,
                rule_id = excluded.rule_id,
                rule_name = excluded.rule_name,
                event_type = excluded.event_type,
                risk_level = excluded.risk_level,
                confidence = excluded.confidence,
                summary = excluded.summary,
                rule_matches_json = excluded.rule_matches_json,
                attack_category = excluded.attack_category,
                attack_subtype = excluded.attack_subtype,
                tool_signature = excluded.tool_signature,
                behavior_fingerprint = excluded.behavior_fingerprint,
                campaign_id = excluded.campaign_id,
                rule_hits_json = excluded.rule_hits_json,
                ai_cluster_id = excluded.ai_cluster_id,
                rule_version = excluded.rule_version,
                raw_json = excluded.raw_json
            """,
            [event_to_row(event) for event in matched_events],
        )
    return len(events)


def access_log_to_row(log: dict[str, Any]) -> tuple[Any, ...]:
    return (
        log["id"],
        log.get("source", "worker_log"),
        int(log.get("sourceCursor") or 0),
        log.get("receivedAt", utc_now()),
        log.get("timestamp", utc_now()),
        log.get("clientIp", ""),
        log.get("ipHash", ""),
        log.get("country", ""),
        log.get("region", ""),
        log.get("city", ""),
        log.get("colo", ""),
        float(log.get("latitude") or 0),
        float(log.get("longitude") or 0),
        log.get("locationPrecision", "estimated"),
        log.get("method", "GET"),
        log.get("host", get_monitored_host()),
        log.get("path", "/"),
        log.get("query") or "",
        int(log.get("statusCode") or 0),
        log.get("userAgent", ""),
        log.get("referer") or "",
        log.get("rayId", ""),
        log.get("requestId", ""),
        int(log.get("responseBytes") or 0),
        json.dumps(log.get("raw", {}), ensure_ascii=False),
        utc_now(),
    )


def insert_access_logs(logs: list[dict[str, Any]]) -> int:
    if not logs:
        return 0
    with db_session() as connection:
        connection.executemany(
            """
            INSERT INTO access_logs (
                id, source, source_cursor, received_at, occurred_at, client_ip, ip_hash,
                country, region, city, colo, latitude, longitude, location_precision,
                method, host, path, query, status_code, user_agent, referer, cf_ray,
                request_id, response_bytes, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source_cursor = excluded.source_cursor,
                received_at = excluded.received_at,
                status_code = excluded.status_code,
                response_bytes = excluded.response_bytes,
                raw_json = excluded.raw_json
            """,
            [access_log_to_row(log) for log in logs],
        )
    return len(logs)


def _aggregate_bucket_start(timestamp: str) -> str:
    parsed = parse_iso_datetime(timestamp)
    return parsed.replace(minute=0, second=0, microsecond=0).isoformat(timespec="seconds").replace("+00:00", "Z")


def _aggregate_value(value: Any, fallback: str = "unknown") -> str:
    normalized = str(value or "").strip()
    return normalized if normalized else fallback


def _worker_aggregate_rows(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregates: dict[tuple[str, str, str], dict[str, Any]] = {}
    for log in logs:
        bucket_start = _aggregate_bucket_start(log.get("timestamp", utc_now()))
        status_code = int(log.get("statusCode") or 0)
        response_bytes = int(log.get("responseBytes") or 0)
        dimensions = {
            "worker_log:country": _aggregate_value(log.get("country")),
            "worker_log:path": _aggregate_value(log.get("path"), "/"),
            "worker_log:status": str(status_code),
            "worker_log:traffic": "all",
        }
        for dimension, dimension_value in dimensions.items():
            key = (bucket_start, dimension, dimension_value)
            if key not in aggregates:
                aggregates[key] = {
                    "id": f"{dimension}:{bucket_start}:{dimension_value}",
                    "bucket_type": "hour",
                    "bucket_start": bucket_start,
                    "dimension": dimension,
                    "dimension_value": dimension_value,
                    "total_count": 0,
                    "threat_count": 0,
                    "blocked_count": 0,
                    "challenge_count": 0,
                    "bandwidth_bytes": 0,
                    "cached_bytes": 0,
                    "origin_bytes": 0,
                }
            item = aggregates[key]
            item["total_count"] += 1
            item["bandwidth_bytes"] += response_bytes
            item["origin_bytes"] += response_bytes
            if status_code >= 400:
                item["threat_count"] += 1
    return list(aggregates.values())


def upsert_worker_log_aggregates(rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    created_at = utc_now()
    with db_session() as connection:
        connection.executemany(
            """
            INSERT INTO event_aggregates (
                id, bucket_type, bucket_start, dimension, dimension_value,
                total_count, threat_count, blocked_count, challenge_count,
                bandwidth_bytes, cached_bytes, origin_bytes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                total_count = total_count + excluded.total_count,
                threat_count = threat_count + excluded.threat_count,
                blocked_count = blocked_count + excluded.blocked_count,
                challenge_count = challenge_count + excluded.challenge_count,
                bandwidth_bytes = bandwidth_bytes + excluded.bandwidth_bytes,
                cached_bytes = cached_bytes + excluded.cached_bytes,
                origin_bytes = origin_bytes + excluded.origin_bytes,
                created_at = excluded.created_at
            """,
            [
                (
                    row["id"],
                    row.get("bucket_type", "hour"),
                    row.get("bucket_start", utc_now()),
                    row["dimension"],
                    row.get("dimension_value", "all"),
                    int(row.get("total_count") or 0),
                    int(row.get("threat_count") or 0),
                    int(row.get("blocked_count") or 0),
                    int(row.get("challenge_count") or 0),
                    int(row.get("bandwidth_bytes") or 0),
                    int(row.get("cached_bytes") or 0),
                    int(row.get("origin_bytes") or 0),
                    created_at,
                )
                for row in rows
                if str(row.get("dimension") or "").startswith("worker_log:")
            ],
        )
    return len([row for row in rows if str(row.get("dimension") or "").startswith("worker_log:")])


def insert_worker_logs(export_rows: list[dict[str, Any]]) -> dict[str, int]:
    logs = [normalize_worker_access_log(row) for row in export_rows]
    if not logs:
        return {"accessLogs": 0, "events": 0, "aggregates": 0}
    access_log_count = insert_access_logs(logs)
    aggregate_count = upsert_worker_log_aggregates(_worker_aggregate_rows(logs))

    with db_session() as connection:
        rule_rows = connection.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
    rules = [normalize_rule_row(row) for row in rule_rows]
    events = []
    for log in logs:
        matched_event = _apply_primary_rule_precedence(apply_rule_matching(worker_access_log_to_event(log), rules))
        risk_level = str(matched_event.get("riskLevel") or "info")
        rule_hits = matched_event.get("ruleHits")
        if risk_level != "info" or (isinstance(rule_hits, list) and len(rule_hits) > 0):
            events.append(matched_event)
    event_count = insert_events(events)
    return {"accessLogs": access_log_count, "events": event_count, "aggregates": aggregate_count}


def seed_traffic_aggregates(source: str = "sample") -> int:
    now_dt = datetime.now(timezone.utc)
    trend = create_sample_traffic_trend(now_dt)
    created_at = utc_now()
    with db_session() as connection:
        connection.execute("DELETE FROM event_aggregates WHERE dimension = ?", (f"{source}:traffic",))
        for index, point in enumerate(trend):
            bucket_start = (now_dt - timedelta(hours=(len(trend) - 1 - index) * 3)).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            bandwidth = int(point["bandwidthMb"] * 1024 * 1024)
            cached = int(bandwidth * point["cachedPercent"] / 100)
            origin = int(point["originMb"] * 1024 * 1024)
            connection.execute(
                """
                INSERT OR REPLACE INTO event_aggregates (
                    id, bucket_type, bucket_start, dimension, dimension_value,
                    total_count, threat_count, blocked_count, challenge_count,
                    bandwidth_bytes, cached_bytes, origin_bytes, created_at
                ) VALUES (?, 'hour', ?, ?, 'all', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{source}:traffic:{index}",
                    bucket_start.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    f"{source}:traffic",
                    point["requests"],
                    point["threats"],
                    point["blocked"],
                    max(0, point["threats"] - point["blocked"]),
                    bandwidth,
                    cached,
                    origin,
                    created_at,
                ),
            )
    return len(trend)


def insert_aggregate_rows(rows: list[dict[str, Any]], *, source: str = "cloudflare") -> int:
    if not rows:
        return 0
    created_at = utc_now()
    with db_session() as connection:
        connection.executemany(
            """
            INSERT OR REPLACE INTO event_aggregates (
                id, bucket_type, bucket_start, dimension, dimension_value,
                total_count, threat_count, blocked_count, challenge_count,
                bandwidth_bytes, cached_bytes, origin_bytes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row.get("bucket_type", "range"),
                    row.get("bucket_start", utc_now()),
                    row["dimension"],
                    row.get("dimension_value", "all"),
                    int(row.get("total_count") or 0),
                    int(row.get("threat_count") or 0),
                    int(row.get("blocked_count") or 0),
                    int(row.get("challenge_count") or 0),
                    int(row.get("bandwidth_bytes") or 0),
                    int(row.get("cached_bytes") or 0),
                    int(row.get("origin_bytes") or 0),
                    created_at,
                )
                for row in rows
                if str(row.get("dimension") or "").startswith(f"{source}:")
            ],
        )
    return len([row for row in rows if str(row.get("dimension") or "").startswith(f"{source}:")])


def clear_cloudflare_aggregates() -> None:
    with db_session() as connection:
        connection.execute("DELETE FROM event_aggregates WHERE dimension LIKE 'cloudflare:%'")


def replace_cloudflare_events(events: list[dict[str, Any]]) -> int:
    with db_session() as connection:
        connection.execute("DELETE FROM raw_events WHERE source = 'cloudflare'")
    return insert_events(events)


def replace_cloudflare_aggregates(rows: list[dict[str, Any]]) -> int:
    clear_cloudflare_aggregates()
    return insert_aggregate_rows(rows, source="cloudflare")


def seed_sample_dataset(
    source: str = "sample",
    *,
    sync_status: str | None = None,
    error_message: str | None = None,
    used_stale_data: bool = False,
) -> dict[str, int]:
    host = get_monitored_host()
    events = create_sample_events(source=source, host=host)
    with db_session() as connection:
        connection.execute("DELETE FROM raw_events WHERE source = ?", (source,))
    inserted_events = insert_events(events)
    inserted_aggregates = seed_traffic_aggregates(source)
    status = sync_status or ("sample" if source == "sample" else "success")
    create_sync_run(
        status=status,
        event_count=inserted_events,
        aggregate_count=inserted_aggregates,
        error_message=error_message if error_message is not None else ("未配置 Cloudflare Token，当前自动展示样例数据。" if source == "sample" else None),
        used_stale_data=used_stale_data,
    )
    return {"events": inserted_events, "aggregates": inserted_aggregates}


def create_sync_run(
    *,
    status: str,
    sync_type: str = SYNC_TYPE_CLOUDFLARE,
    event_count: int = 0,
    aggregate_count: int = 0,
    error_message: str | None = None,
    used_stale_data: bool = False,
    from_time: str | None = None,
    to_time: str | None = None,
) -> None:
    now = utc_now()
    with db_session() as connection:
        connection.execute(
            """
            INSERT INTO sync_runs (
                sync_type, started_at, finished_at, status, from_time, to_time,
                event_count, aggregate_count, error_message, used_stale_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sync_type,
                now,
                now,
                status,
                from_time,
                to_time,
                event_count,
                aggregate_count,
                error_message,
                1 if used_stale_data else 0,
            ),
        )
        if status in {"success", "sample"}:
            state_keys = [f"last_success_{sync_type}_sync_at"]
            if sync_type == SYNC_TYPE_CLOUDFLARE:
                state_keys.append("last_success_sync_at")
            for state_key in state_keys:
                connection.execute(
                    """
                    INSERT INTO app_state (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (state_key, now),
                )


def get_last_sync_row(sync_type: str | None = None) -> Any | None:
    with db_session() as connection:
        if sync_type:
            return connection.execute("SELECT * FROM sync_runs WHERE sync_type = ? ORDER BY id DESC LIMIT 1", (sync_type,)).fetchone()
        return connection.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1").fetchone()


def get_last_success_sync_row(sync_type: str) -> Any | None:
    with db_session() as connection:
        return connection.execute(
            """
            SELECT * FROM sync_runs
            WHERE sync_type = ?
              AND status IN ('success', 'sample')
            ORDER BY id DESC
            LIMIT 1
            """,
            (sync_type,),
        ).fetchone()


def get_last_token_check() -> dict[str, Any] | None:
    with db_session() as connection:
        row = connection.execute("SELECT * FROM token_checks ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    return {
        "checkedAt": row["checked_at"],
        "status": row["status"],
        "zoneRead": bool(row["zone_read"]),
        "analyticsRead": bool(row["analytics_read"]),
        "securityEventsRead": bool(row["security_events_read"]),
        "errorMessage": row["error_message"],
        "details": _json_loads(row["details_json"], {}),
    }


def insert_token_check(result: dict[str, Any]) -> None:
    with db_session() as connection:
        connection.execute(
            """
            INSERT INTO token_checks (
                checked_at, status, zone_read, analytics_read, security_events_read, error_message, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["checkedAt"],
                result["status"],
                1 if result["zoneRead"] else 0,
                1 if result["analyticsRead"] else 0,
                1 if result["securityEventsRead"] else 0,
                result.get("errorMessage"),
                json.dumps(result.get("details", {}), ensure_ascii=False),
            ),
        )


def permissions_from_token_check(check: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not check:
        if has_cloudflare_token():
            return [
                {"name": "Zone Read", "ok": False, "detail": "等待执行权限检测"},
                {"name": "Analytics Read", "ok": False, "detail": "等待执行权限检测"},
                {"name": "Security Events Read", "ok": False, "detail": "等待执行权限检测"},
            ]
        return [
            {"name": "Zone Read", "ok": False, "detail": "等待配置 Zone ID"},
            {"name": "Analytics Read", "ok": False, "detail": "等待配置 Token"},
            {"name": "Security Events Read", "ok": False, "detail": "等待配置 Token"},
        ]
    details = check.get("details") or {}
    network_request = bool(details.get("networkRequest"))
    error_message = check.get("errorMessage") or "权限检测未通过"
    if network_request:
        return [
            {"name": "Zone Read", "ok": bool(check["zoneRead"]), "detail": "Cloudflare Zone access verified." if check["zoneRead"] else error_message},
            {"name": "Analytics Read", "ok": bool(check["analyticsRead"]), "detail": "Cloudflare HTTP Analytics access verified." if check["analyticsRead"] else error_message},
            {"name": "Security Events Read", "ok": bool(check["securityEventsRead"]), "detail": "Cloudflare Security Events access verified." if check["securityEventsRead"] else error_message},
        ]
    return [
        {"name": "Zone Read", "ok": bool(check["zoneRead"]), "detail": "Zone ID 格式已通过本地校验" if check["zoneRead"] else "Zone ID 缺失或格式异常"},
        {"name": "Analytics Read", "ok": bool(check["analyticsRead"]), "detail": "Token 格式允许读取 Analytics" if check["analyticsRead"] else "Token 缺失或格式异常"},
        {"name": "Security Events Read", "ok": bool(check["securityEventsRead"]), "detail": "Token 格式允许读取 Security Events" if check["securityEventsRead"] else "Token 缺失或格式异常"},
    ]


def _sync_mode(status: str, used_stale: bool, sample: bool = False) -> str:
    if sample:
        return "sample"
    if status in {"degraded", "partial"}:
        return "degraded"
    if status == "failed" and used_stale:
        return "stale"
    if status == "failed":
        return "degraded"
    return "live"


def _sync_state_from_row(
    row: Any | None,
    *,
    sync_type: str,
    fallback_error: str,
    sample: bool = False,
    last_success_row: Any | None = None,
) -> dict[str, Any]:
    now = utc_now()
    if row:
        status = "sample" if sample else row["status"]
        last_sync_at = row["finished_at"] or row["started_at"]
        api_error = row["error_message"]
        used_stale = bool(row["used_stale_data"])
        event_count = int(row["event_count"])
        aggregate_count = int(row["aggregate_count"])
    else:
        status = "sample" if sample else "failed"
        last_sync_at = now
        api_error = fallback_error
        used_stale = False
        event_count = 0
        aggregate_count = 0
    if last_success_row:
        last_success_at = last_success_row["finished_at"] or last_success_row["started_at"]
    elif status in {"success", "sample"}:
        last_success_at = last_sync_at
    else:
        last_success_at = ""
    mode = _sync_mode(status, used_stale, sample)
    return {
        "syncType": sync_type,
        "source": sync_type,
        "status": status,
        "mode": mode,
        "cloudflareLive": sync_type == SYNC_TYPE_CLOUDFLARE and mode == "live",
        "lastSyncAt": last_sync_at,
        "lastSuccessAt": last_success_at,
        "usedStaleData": used_stale,
        "apiError": api_error,
        "eventCount": event_count,
        "aggregateCount": aggregate_count,
    }


def get_sync_status() -> dict[str, Any]:
    last_sync = get_last_sync_row(SYNC_TYPE_CLOUDFLARE)
    last_success_sync = get_last_success_sync_row(SYNC_TYPE_CLOUDFLARE)
    worker_sync = get_last_sync_row(SYNC_TYPE_WORKER_LOG)
    worker_success_sync = get_last_success_sync_row(SYNC_TYPE_WORKER_LOG)
    token_check = get_last_token_check()
    sample = is_sample_mode()
    event_count, aggregate_count = get_counts()
    cloudflare_state = _sync_state_from_row(
        last_sync,
        sync_type=SYNC_TYPE_CLOUDFLARE,
        fallback_error="未配置 Cloudflare Token，当前自动展示样例数据。" if sample else "尚未执行 Cloudflare 官方同步。",
        sample=sample,
        last_success_row=last_success_sync,
    )
    worker_state = _sync_state_from_row(
        worker_sync,
        sync_type=SYNC_TYPE_WORKER_LOG,
        fallback_error="尚未执行 Worker/D1 访问日志同步。",
        sample=False,
        last_success_row=worker_success_sync,
    )
    return {
        **cloudflare_state,
        "localEventCount": event_count,
        "aggregateCount": aggregate_count,
        "refreshIntervalHours": get_int_state("refresh_interval_hours", DEFAULT_REFRESH_INTERVAL_HOURS),
        "permissions": permissions_from_token_check(token_check),
        "cloudflare": cloudflare_state,
        "workerLog": worker_state,
    }


def get_counts() -> tuple[int, int]:
    source_clause, source_params = active_source_filter()
    aggregate_prefixes = ["sample:%"] if is_sample_mode() else ["cloudflare:%", "worker_log:%"]
    with db_session() as connection:
        events = connection.execute(f"SELECT COUNT(*) AS count FROM raw_events WHERE {source_clause}", source_params).fetchone()["count"]
        aggregates = connection.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM event_aggregates
            WHERE {" OR ".join("dimension LIKE ?" for _ in aggregate_prefixes)}
            """,
            aggregate_prefixes,
        ).fetchone()["count"]
    return int(events), int(aggregates)


def _has_filter(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _event_filter_sql(filters: dict[str, Any]) -> tuple[str, list[Any]]:
    source_clause, params = active_source_filter()
    clauses: list[str] = [source_clause]
    if _has_filter(filters.get("from_time")):
        clauses.append("occurred_at >= ?")
        params.append(str(filters["from_time"]))
    if _has_filter(filters.get("to_time")):
        clauses.append("occurred_at <= ?")
        params.append(str(filters["to_time"]))
    if _has_filter(filters.get("ip")):
        clauses.append("client_ip = ?")
        params.append(str(filters["ip"]).strip())
    if _has_filter(filters.get("country")):
        clauses.append("country = ?")
        params.append(str(filters["country"]).strip())
    if _has_filter(filters.get("region")):
        clauses.append("region = ?")
        params.append(str(filters["region"]).strip())
    if _has_filter(filters.get("risk_level")):
        risk_level = str(filters["risk_level"]).strip()
        if filters.get("risk_at_or_above") and risk_level in RISK_ORDER:
            accepted = RISK_ORDER[RISK_ORDER.index(risk_level) :]
            placeholders = ",".join("?" for _ in accepted)
            clauses.append(f"risk_level IN ({placeholders})")
            params.extend(accepted)
        else:
            clauses.append("risk_level = ?")
            params.append(risk_level)
    if _has_filter(filters.get("event_type")):
        clauses.append("event_type = ?")
        params.append(str(filters["event_type"]).strip())
    if _has_filter(filters.get("attack_category")):
        clauses.append("attack_category = ?")
        params.append(str(filters["attack_category"]).strip())
    if _has_filter(filters.get("rule_id")):
        clauses.append("(rule_id = ? OR rule_hits_json LIKE ?)")
        rule_id = str(filters["rule_id"]).strip()
        params.extend([rule_id, f"%{rule_id}%"])
    if _has_filter(filters.get("action")):
        clauses.append("action = ?")
        params.append(str(filters["action"]).strip())
    if _has_filter(filters.get("path")):
        clauses.append("path LIKE ?")
        params.append(f"%{str(filters['path']).strip()}%")
    if _has_filter(filters.get("user_agent")):
        clauses.append("user_agent LIKE ?")
        params.append(f"%{str(filters['user_agent']).strip()}%")
    if _has_filter(filters.get("method")):
        clauses.append("method = ?")
        params.append(str(filters["method"]).strip().upper())
    if _has_filter(filters.get("status_code")):
        clauses.append("status_code = ?")
        params.append(int(filters["status_code"]))
    return f"WHERE {' AND '.join(clauses)}", params


def normalize_event_limit(value: Any) -> int:
    return max(1, min(int(value or 100), 500))


def normalize_event_offset(value: Any) -> int:
    return max(0, int(value or 0))


def count_events(filters: dict[str, Any]) -> int:
    where_sql, params = _event_filter_sql(filters)
    with db_session() as connection:
        row = connection.execute(
            f"SELECT COUNT(*) AS count FROM raw_events {where_sql}",
            params,
        ).fetchone()
    return int(row["count"])


def list_events(filters: dict[str, Any]) -> list[dict[str, Any]]:
    where_sql, params = _event_filter_sql(filters)
    limit = normalize_event_limit(filters.get("limit"))
    offset = normalize_event_offset(filters.get("offset"))
    with db_session() as connection:
        rows = connection.execute(
            f"SELECT * FROM raw_events {where_sql} ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return [row_to_event(row) for row in rows]


def get_event(event_id: str) -> dict[str, Any] | None:
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        row = connection.execute(
            f"SELECT * FROM raw_events WHERE {source_clause} AND id = ?",
            (*source_params, event_id),
        ).fetchone()
    if not row:
        return None
    event = row_to_event(row)
    event["aiAnalysis"] = {
        "status": "pending",
        "message": "AI 研判接口已预留，一期暂不调用大模型。",
    }
    return event


def has_aggregate_dimension(dimension: str) -> bool:
    with db_session() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM event_aggregates WHERE dimension = ?",
            (dimension,),
        ).fetchone()
    return int(row["count"]) > 0


def preferred_live_aggregate_dimension(suffix: str) -> str:
    worker_dimension = f"worker_log:{suffix}"
    if has_aggregate_dimension(worker_dimension):
        return worker_dimension
    return f"cloudflare:{suffix}"


def get_traffic_trend() -> list[dict[str, Any]]:
    dimension = "sample:traffic" if is_sample_mode() else preferred_live_aggregate_dimension("traffic")
    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT * FROM event_aggregates
            WHERE bucket_type = 'hour' AND dimension = ?
            ORDER BY bucket_start ASC
            LIMIT 24
            """,
            (dimension,),
        ).fetchall()
    if not rows:
        return create_sample_traffic_trend()
    points = []
    for row in rows:
        bucket = parse_iso_datetime(row["bucket_start"])
        bandwidth_mb = round(row["bandwidth_bytes"] / 1024 / 1024)
        cached_percent = round((row["cached_bytes"] / row["bandwidth_bytes"]) * 100) if row["bandwidth_bytes"] else 0
        origin_mb = round(row["origin_bytes"] / 1024 / 1024)
        points.append(
            {
                "label": bucket.strftime("%m-%d %H:00"),
                "requests": row["total_count"],
                "threats": row["threat_count"],
                "blocked": row["blocked_count"],
                "bandwidthMb": bandwidth_mb,
                "cachedPercent": cached_percent,
                "originMb": origin_mb,
            }
        )
    return points


def _distribution(field: str, label_map: dict[str, str] | None = None) -> list[dict[str, Any]]:
    allowed_fields = {"risk_level", "event_type", "status_code", "country", "path", "client_ip", "user_agent"}
    if field not in allowed_fields:
        raise ValueError(f"Unsupported distribution field: {field}")
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        rows = connection.execute(
            f"""
            SELECT {field} AS label, COUNT(*) AS value
            FROM raw_events
            WHERE {source_clause}
            GROUP BY {field}
            ORDER BY value DESC
            LIMIT 10
            """,
            source_params,
        ).fetchall()
    items = []
    for row in rows:
        raw_label = str(row["label"])
        label = label_map.get(raw_label, raw_label) if label_map else raw_label
        item: dict[str, Any] = {"label": label, "value": int(row["value"])}
        if field == "risk_level":
            item["riskLevel"] = raw_label
        if field == "event_type":
            item["riskLevel"] = normalize_max_risk_for_label(raw_label, field)
        items.append(item)
    return items


def _ranked(field: str, detail_field: str | None = None) -> list[dict[str, Any]]:
    allowed_fields = {"client_ip", "path", "user_agent", "country"}
    if field not in allowed_fields:
        raise ValueError(f"Unsupported ranked field: {field}")
    detail_sql = f", MAX({detail_field}) AS detail_value" if detail_field else ""
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        rows = connection.execute(
            f"""
            SELECT {field} AS label, COUNT(*) AS value, MAX(risk_level) AS risk_value {detail_sql}
            FROM raw_events
            WHERE {source_clause}
            GROUP BY {field}
            ORDER BY value DESC
            LIMIT 5
            """,
            source_params,
        ).fetchall()
    items = []
    for row in rows:
        detail = str(row["detail_value"]) if detail_field and row["detail_value"] else ""
        if field == "client_ip":
            detail = detail or "来源 IP"
        elif field == "path":
            detail = detail or "访问路径"
        elif field == "user_agent":
            detail = detail or "User-Agent"
        elif field == "country":
            detail = detail or "来源国家/地区"
        items.append(
            {
                "label": str(row["label"]),
                "value": int(row["value"]),
                "detail": detail,
                "riskLevel": normalize_max_risk_for_label(str(row["label"]), field),
            }
        )
    return items


def normalize_max_risk_for_label(label: str, field: str) -> str:
    allowed_fields = {"client_ip", "path", "user_agent", "country", "event_type"}
    if field not in allowed_fields:
        return "info"
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        rows = connection.execute(
            f"SELECT risk_level FROM raw_events WHERE {source_clause} AND {field} = ?",
            (*source_params, label),
        ).fetchall()
    highest = "info"
    for row in rows:
        risk = row["risk_level"]
        if RISK_ORDER.index(risk) > RISK_ORDER.index(highest):
            highest = risk
    return highest


def get_country_aggregate_globe_points(source: str, limit: int = 50) -> list[dict[str, Any]]:
    if is_sample_mode():
        return []
    dimension = f"{source}:country"
    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT
                dimension_value,
                SUM(total_count) AS total_count,
                SUM(bandwidth_bytes) AS bandwidth_bytes
            FROM event_aggregates
            WHERE dimension = ? AND dimension_value != ''
            GROUP BY dimension_value
            ORDER BY total_count DESC
            LIMIT ?
            """,
            (dimension, limit),
        ).fetchall()

    points = []
    for row in rows:
        country = str(row["dimension_value"])
        count = int(row["total_count"] or 0)
        bandwidth_bytes = int(row["bandwidth_bytes"] or 0)
        latitude, longitude, location_precision = stable_country_coordinates(country)
        points.append(
            {
                "id": f"{source}:country:{country}",
                "label": f"{country} normal_visit",
                "clientIp": "",
                "country": country,
                "city": "",
                "latitude": latitude,
                "longitude": longitude,
                "count": count,
                "riskLevel": "info",
                "eventType": "normal_visit",
                "locationPrecision": location_precision,
                "action": "allow",
                "source": f"{source}_aggregate",
                "sourceType": "normal_visit",
                "trafficKind": "visit",
                "bandwidthBytes": bandwidth_bytes,
                "throughputMb": round(bandwidth_bytes / 1024 / 1024, 1),
            }
        )
    return points


def get_cloudflare_country_globe_points(limit: int = 50) -> list[dict[str, Any]]:
    return get_country_aggregate_globe_points("cloudflare", limit)


def get_worker_log_country_globe_points(limit: int = 50) -> list[dict[str, Any]]:
    return get_country_aggregate_globe_points("worker_log", limit)


def get_combined_country_aggregate_globe_points(limit: int = 50) -> list[dict[str, Any]]:
    if is_sample_mode() or limit <= 0:
        return []
    dimensions = tuple(f"{source}:country" for source in COUNTRY_AGGREGATE_SOURCES)
    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT
                dimension_value,
                SUM(total_count) AS total_count,
                SUM(bandwidth_bytes) AS bandwidth_bytes,
                SUM(CASE WHEN dimension = 'cloudflare:country' THEN total_count ELSE 0 END) AS cloudflare_count,
                SUM(CASE WHEN dimension = 'worker_log:country' THEN total_count ELSE 0 END) AS worker_log_count
            FROM event_aggregates
            WHERE dimension IN (?, ?) AND dimension_value != ''
            GROUP BY dimension_value
            ORDER BY
                CASE WHEN cloudflare_count > 0 THEN 0 ELSE 1 END ASC,
                cloudflare_count DESC,
                total_count DESC,
                dimension_value ASC
            LIMIT ?
            """,
            (*dimensions, limit),
        ).fetchall()

    points = []
    for row in rows:
        country = str(row["dimension_value"])
        count = int(row["total_count"] or 0)
        bandwidth_bytes = int(row["bandwidth_bytes"] or 0)
        cloudflare_count = int(row["cloudflare_count"] or 0)
        worker_log_count = int(row["worker_log_count"] or 0)
        latitude, longitude, location_precision = stable_country_coordinates(country)
        source_label = "cloudflare" if cloudflare_count > 0 else "worker_log"
        points.append(
            {
                "id": f"combined:country:{country}",
                "label": f"{country} normal_visit",
                "clientIp": "",
                "country": country,
                "city": "",
                "latitude": latitude,
                "longitude": longitude,
                "count": count,
                "riskLevel": "info",
                "eventType": "normal_visit",
                "locationPrecision": location_precision,
                "action": "allow",
                "source": f"{source_label}_aggregate",
                "sourceType": "normal_visit",
                "trafficKind": "visit",
                "bandwidthBytes": bandwidth_bytes,
                "throughputMb": round(bandwidth_bytes / 1024 / 1024, 1),
                "cloudflareCount": cloudflare_count,
                "workerLogCount": worker_log_count,
            }
        )
    return points


def raw_security_globe_clause() -> tuple[str, list[Any]]:
    if is_sample_mode():
        return "", []
    placeholders = ",".join("?" for _ in SECURITY_GLOBE_ACTIONS)
    return f" AND (risk_level != ? OR action IN ({placeholders}))", ["info", *SECURITY_GLOBE_ACTIONS]


def stable_globe_point_id(prefix: str, *values: Any) -> str:
    parts = [str(value or "unknown").strip().replace(":", "_").replace("|", "_") or "unknown" for value in values]
    return f"{prefix}:{':'.join(parts)}"


def dedupe_globe_points(points: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for point in points:
        key = (
            point.get("sourceType"),
            point.get("trafficKind"),
            point.get("clientIp"),
            point.get("country"),
            point.get("city"),
            point.get("latitude"),
            point.get("longitude"),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(point)
        if len(selected) >= limit:
            break
    return selected


def get_raw_event_globe_points(
    limit: int = 50,
    filters: dict[str, Any] | None = None,
    *,
    stable_ids: bool = False,
    security_only: bool = True,
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    where_sql, params = _event_filter_sql(filters or {})
    security_clause, security_params = raw_security_globe_clause() if security_only else ("", [])
    filtered_where_sql = f"{where_sql}{security_clause}"
    filtered_params = [*params, *security_params]
    with db_session() as connection:
        rows = connection.execute(
            f"""
            SELECT
                client_ip, country, city, latitude, longitude, location_precision,
                COUNT(*) AS count
            FROM raw_events
            {filtered_where_sql}
            GROUP BY client_ip, country, city, latitude, longitude, location_precision
            ORDER BY count DESC
            LIMIT ?
            """,
            (*filtered_params, limit),
        ).fetchall()
        latest_rows = [
            connection.execute(
                f"""
                SELECT * FROM raw_events
                {filtered_where_sql}
                    AND client_ip = ?
                    AND country = ?
                    AND city = ?
                    AND latitude = ?
                    AND longitude = ?
                    AND location_precision = ?
                ORDER BY occurred_at DESC
                LIMIT 1
                """,
                (
                    *filtered_params,
                    row["client_ip"],
                    row["country"],
                    row["city"],
                    row["latitude"],
                    row["longitude"],
                    row["location_precision"],
                ),
            ).fetchone()
            for row in rows
        ]

    points = []
    for row, latest_row in zip(rows, latest_rows):
        latest = row_to_event(latest_row) if latest_row else {}
        point_id = (
            stable_globe_point_id(
                "raw:security",
                row["client_ip"],
                row["country"],
                row["city"],
                row["latitude"],
                row["longitude"],
            )
            if stable_ids
            else latest.get("id", row["client_ip"])
        )
        points.append(
            {
                "id": point_id,
                "label": f"{row['city']} {latest.get('eventType', '访问')}".strip(),
                "clientIp": row["client_ip"],
                "country": row["country"],
                "city": row["city"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "count": int(row["count"]),
                "riskLevel": latest.get("riskLevel", "info"),
                "eventType": latest.get("eventType", "正常访问"),
                "locationPrecision": row["location_precision"],
                "action": latest.get("action"),
                "method": latest.get("method"),
                "path": latest.get("path"),
                "statusCode": latest.get("statusCode"),
                "rayId": latest.get("rayId"),
                "asn": latest.get("asn"),
                "ruleName": latest.get("ruleName"),
                "throughputMb": round(max(4, int(row["count"]) * 0.42), 1),
                "source": latest.get("source", "raw_events"),
                "sourceType": "security_event" if latest else "raw_event",
                "trafficKind": "attack" if latest.get("riskLevel", "info") != "info" else "visit",
            }
        )
    return points


def limit_raw_globe_points(
    points: list[dict[str, Any]],
    limit: int,
    *,
    country_limit: int,
    client_ip_limit: int,
) -> list[dict[str, Any]]:
    selected = []
    country_counts: dict[str, int] = {}
    client_ip_counts: dict[str, int] = {}
    for point in points:
        country = str(point.get("country") or "")
        client_ip = str(point.get("clientIp") or "")
        if country and country_counts.get(country, 0) >= country_limit:
            continue
        if client_ip and client_ip_counts.get(client_ip, 0) >= client_ip_limit:
            continue
        selected.append(point)
        if country:
            country_counts[country] = country_counts.get(country, 0) + 1
        if client_ip:
            client_ip_counts[client_ip] = client_ip_counts.get(client_ip, 0) + 1
        if len(selected) >= limit:
            break
    return selected


def get_globe_points(limit: int = 50) -> list[dict[str, Any]]:
    if is_sample_mode():
        return get_raw_event_globe_points(min(limit, 10))
    raw_points = get_raw_event_globe_points(max(limit, GLOBE_PRIMARY_VISIBLE_LIMIT))
    security_points = limit_raw_globe_points(
        raw_points,
        min(limit, GLOBE_RAW_SECURITY_LIMIT),
        country_limit=GLOBE_RAW_COUNTRY_LIMIT,
        client_ip_limit=GLOBE_RAW_CLIENT_IP_LIMIT,
    )
    visit_limit = max(0, limit - len(security_points))
    return [
        *security_points,
        *get_combined_country_aggregate_globe_points(visit_limit),
    ]


def get_home_visualization_globe_points(limit: int = HOME_GLOBE_POINT_LIMIT) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    if is_sample_mode():
        return dedupe_globe_points(
            get_raw_event_globe_points(min(limit, HOME_GLOBE_POINT_LIMIT), stable_ids=True, security_only=False),
            limit,
        )
    raw_points = get_raw_event_globe_points(max(limit, HOME_RAW_SECURITY_LIMIT), stable_ids=True)
    security_points = limit_raw_globe_points(
        raw_points,
        min(limit, HOME_RAW_SECURITY_LIMIT),
        country_limit=HOME_RAW_COUNTRY_LIMIT,
        client_ip_limit=HOME_RAW_CLIENT_IP_LIMIT,
    )
    visit_limit = max(0, limit - len(security_points))
    return dedupe_globe_points(
        [
            *security_points,
            *get_combined_country_aggregate_globe_points(visit_limit),
        ],
        limit,
    )


def get_situation_visualization_globe_points(filters: dict[str, Any] | None = None, limit: int = 50) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    if is_sample_mode():
        return dedupe_globe_points(
            get_raw_event_globe_points(min(limit, 10), filters, stable_ids=True, security_only=False),
            limit,
        )
    raw_points = get_raw_event_globe_points(max(limit, GLOBE_PRIMARY_VISIBLE_LIMIT), filters, stable_ids=True)
    security_points = limit_raw_globe_points(
        raw_points,
        min(limit, GLOBE_RAW_SECURITY_LIMIT),
        country_limit=GLOBE_RAW_COUNTRY_LIMIT,
        client_ip_limit=GLOBE_RAW_CLIENT_IP_LIMIT,
    )
    visit_limit = max(0, limit - len(security_points))
    return dedupe_globe_points(
        [
            *security_points,
            *get_combined_country_aggregate_globe_points(visit_limit),
        ],
        limit,
    )


def aggregate_dimension_items(dimension: str, limit: int = 10) -> list[dict[str, Any]]:
    if is_sample_mode() and not dimension.startswith("sample:"):
        return []
    if not is_sample_mode() and not (dimension.startswith("cloudflare:") or dimension.startswith("worker_log:")):
        return []
    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT dimension_value, SUM(total_count) AS total_count
            FROM event_aggregates
            WHERE dimension = ?
            GROUP BY dimension_value
            ORDER BY total_count DESC
            LIMIT ?
            """,
            (dimension, limit),
        ).fetchall()
    return [{"label": str(row["dimension_value"]), "value": int(row["total_count"])} for row in rows]


def aggregate_country_dimension_items(limit: int = 10) -> list[dict[str, Any]]:
    if is_sample_mode() or limit <= 0:
        return []
    dimensions = tuple(f"{source}:country" for source in COUNTRY_AGGREGATE_SOURCES)
    with db_session() as connection:
        rows = connection.execute(
            """
            SELECT
                dimension_value,
                SUM(total_count) AS total_count,
                SUM(CASE WHEN dimension = 'cloudflare:country' THEN total_count ELSE 0 END) AS cloudflare_count
            FROM event_aggregates
            WHERE dimension IN (?, ?) AND dimension_value != ''
            GROUP BY dimension_value
            ORDER BY
                CASE WHEN cloudflare_count > 0 THEN 0 ELSE 1 END ASC,
                cloudflare_count DESC,
                total_count DESC,
                dimension_value ASC
            LIMIT ?
            """,
            (*dimensions, limit),
        ).fetchall()
    return [{"label": str(row["dimension_value"]), "value": int(row["total_count"])} for row in rows]


def aggregate_ranked_items(dimension: str, detail: str, limit: int = 5) -> list[dict[str, Any]]:
    return [
        {
            "label": item["label"],
            "value": item["value"],
            "detail": detail,
            "riskLevel": "info",
        }
        for item in aggregate_dimension_items(dimension, limit)
    ]


def aggregate_country_ranked_items(detail: str, limit: int = 5) -> list[dict[str, Any]]:
    return [
        {
            "label": item["label"],
            "value": item["value"],
            "detail": detail,
            "riskLevel": "info",
        }
        for item in aggregate_country_dimension_items(limit)
    ]


def get_overview(
    *,
    globe_points: list[dict[str, Any]] | None = None,
    recent_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    trend = get_traffic_trend()
    overview_recent_events = recent_events if recent_events is not None else list_events({"limit": 6})
    status_codes = _distribution("status_code")
    for item in status_codes:
        try:
            code = int(item["label"])
        except ValueError:
            code = 0
        if code >= 500:
            item["riskLevel"] = "high"
        elif code >= 400:
            item["riskLevel"] = "medium"
    risk_label_map = {"info": "信息", "low": "低风险", "medium": "关注", "high": "高风险", "critical": "严重"}
    risk_distribution = _distribution("risk_level", risk_label_map)
    event_types = _distribution("event_type")
    top_ips = _ranked("client_ip", "city")
    top_paths = _ranked("path", "event_type")
    top_agents = _ranked("user_agent", "event_type")
    countries = _ranked("country", "event_type")
    if not status_codes and not is_sample_mode():
        status_codes = aggregate_dimension_items(preferred_live_aggregate_dimension("status"))
        for item in status_codes:
            try:
                code = int(item["label"])
            except ValueError:
                code = 0
            if code >= 500:
                item["riskLevel"] = "high"
            elif code >= 400:
                item["riskLevel"] = "medium"
    if not top_paths and not is_sample_mode():
        top_paths = aggregate_ranked_items(preferred_live_aggregate_dimension("path"), "HTTP path")
    if not is_sample_mode():
        aggregate_countries = aggregate_country_ranked_items("Request distribution")
        if aggregate_countries:
            countries = aggregate_countries
    points = globe_points if globe_points is not None else get_globe_points()

    total_24h = sum(point["requests"] for point in trend)
    total_6h = sum(point["requests"] for point in trend[-3:])
    total_7d = max(total_24h * 6, total_24h)
    threats = sum(point["threats"] for point in trend)
    blocked = sum(point["blocked"] for point in trend)
    high_events = count_risk_at_or_above(get_state("high_risk_threshold", DEFAULT_HIGH_RISK_THRESHOLD))
    cf_events = count_cloudflare_actions()
    sample = is_sample_mode()
    return {
        "monitoredHost": get_monitored_host(),
        "timeRangeLabel": "最近 24 小时",
        "sampleMode": sample,
        "generatedAt": utc_now(),
        "kpis": [
            {"id": "requests-6h", "label": "最近 6 小时访问", "value": f"{total_6h:,}", "detail": "边缘侧请求量", "trend": "+8.4%", "tone": "sky", "href": "/security/events?timeRange=6h"},
            {"id": "requests-24h", "label": "最近 24 小时访问", "value": f"{total_24h:,}", "detail": "缓存命中率 78%", "trend": "+4.1%", "tone": "emerald", "href": "/security/events?timeRange=24h"},
            {"id": "requests-7d", "label": "最近 7 天访问", "value": f"{total_7d:,}", "detail": "聚合统计长期保留", "trend": "+11.7%", "tone": "slate", "href": "/security/events?timeRange=7d"},
            {"id": "abnormal", "label": "异常请求", "value": f"{threats:,}", "detail": "扫描、挑战与异常状态码", "trend": f"+{max(0, threats - blocked)}", "tone": "amber", "href": "/security/events?risk=medium"},
            {"id": "high-risk", "label": "高风险事件", "value": f"{high_events:,}", "detail": "high 及以上", "trend": f"+{high_events}", "tone": "rose", "href": "/security/events?risk=high"},
            {"id": "cf-events", "label": "Cloudflare 安全事件", "value": f"{cf_events:,}", "detail": "block / challenge / log", "trend": f"+{blocked}", "tone": "sky", "href": "/security/events?action=block"},
        ],
        "trafficTrend": trend,
        "statusCodes": status_codes,
        "riskDistribution": risk_distribution,
        "eventTypes": event_types,
        "topIps": top_ips,
        "topPaths": top_paths,
        "topAgents": top_agents,
        "countries": countries,
        "globePoints": points,
        "sync": get_sync_status(),
        "recentEvents": overview_recent_events,
    }


def get_home_visualization_overview() -> dict[str, Any]:
    return get_overview(globe_points=get_home_visualization_globe_points())


def get_situation_visualization_overview(filters: dict[str, Any] | None = None) -> dict[str, Any]:
    event_filters = dict(filters or {})
    event_filters["limit"] = 6
    return get_overview(
        globe_points=get_situation_visualization_globe_points(filters),
        recent_events=list_events(event_filters),
    )


def count_risk_at_or_above(threshold: str) -> int:
    if threshold not in RISK_ORDER:
        threshold = DEFAULT_HIGH_RISK_THRESHOLD
    accepted = RISK_ORDER[RISK_ORDER.index(threshold) :]
    placeholders = ",".join("?" for _ in accepted)
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        row = connection.execute(
            f"SELECT COUNT(*) AS count FROM raw_events WHERE {source_clause} AND risk_level IN ({placeholders})",
            (*source_params, *accepted),
        ).fetchone()
    return int(row["count"])


def count_cloudflare_actions() -> int:
    source_clause, source_params = active_source_filter()
    with db_session() as connection:
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS count FROM raw_events
            WHERE {source_clause} AND action IN ('block', 'challenge', 'managed_challenge', 'log')
            """,
            source_params,
        ).fetchone()
    return int(row["count"])


def get_settings() -> dict[str, Any]:
    token_check = get_last_token_check()
    return {
        "monitoredHost": get_monitored_host(),
        "zoneId": get_cloudflare_zone_id(),
        "hasCloudflareToken": has_cloudflare_token(),
        "sampleMode": is_sample_mode(),
        "refreshIntervalHours": get_int_state("refresh_interval_hours", DEFAULT_REFRESH_INTERVAL_HOURS),
        "highRiskThreshold": get_state("high_risk_threshold", DEFAULT_HIGH_RISK_THRESHOLD),
        "rawRetentionDays": get_int_state("raw_retention_days", DEFAULT_RAW_RETENTION_DAYS),
        "aggregateRetention": get_state("aggregate_retention", AGGREGATE_RETENTION_LABEL),
        "permissions": permissions_from_token_check(token_check),
        "lastTokenCheckAt": token_check["checkedAt"] if token_check else None,
    }


def update_cloudflare_settings(payload: dict[str, Any]) -> None:
    monitored_host = str(payload.get("monitoredHost") or payload.get("host") or get_monitored_host()).strip()
    zone_id = str(payload.get("zoneId") or payload.get("cloudflareZoneId") or "").strip()
    token = str(payload.get("apiToken") or payload.get("cloudflareToken") or payload.get("token") or "").strip()
    refresh_hours = payload.get("refreshIntervalHours")
    if monitored_host:
        set_state("monitored_host", monitored_host)
    if zone_id:
        set_state("cloudflare_zone_id", zone_id)
    if token:
        set_state("cloudflare_api_token", token)
    elif payload.get("clearToken") is True:
        set_state("cloudflare_api_token", "")
    if refresh_hours is not None:
        set_state("refresh_interval_hours", str(max(1, min(int(refresh_hours), 24))))


def update_risk_threshold(level: str) -> None:
    if level not in RISK_ORDER:
        raise ValueError("Unsupported risk threshold.")
    set_state("high_risk_threshold", level)


def get_rules() -> list[dict[str, Any]]:
    with db_session() as connection:
        rows = connection.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
    rules = []
    for row in rows:
        rule = normalize_rule_row(row)
        rule["createdAt"] = row["created_at"]
        rule["updatedAt"] = row["updated_at"]
        rules.append(rule)
    return rules


def source_summary() -> dict[str, Any]:
    overview = get_overview()
    return {
        "topIps": overview["topIps"],
        "topPaths": overview["topPaths"],
        "topAgents": overview["topAgents"],
        "countries": overview["countries"],
    }


def map_payload() -> dict[str, Any]:
    points = get_globe_points()
    return {
        "destination": CHENGDU_DESTINATION,
        "points": points,
        "flows": [
            {
                "id": f"{point['id']}:chengdu",
                "from": {
                    "latitude": point["latitude"],
                    "longitude": point["longitude"],
                    "label": point["label"],
                },
                "to": CHENGDU_DESTINATION,
                "riskLevel": point["riskLevel"],
                "count": point["count"],
            }
            for point in points
        ],
    }
