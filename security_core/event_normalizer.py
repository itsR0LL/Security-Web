from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from .geo import resolve_geo_coordinates


IpLookup = Callable[[Any], dict[str, Any] | None]


CACHED_STATUSES = {"hit", "stale", "updating", "revalidated"}
BLOCK_ACTIONS = {"block", "blocked"}
CHALLENGE_ACTIONS = {"challenge", "managed_challenge", "js_challenge"}


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _iso(value: Any) -> str:
    text = _text(value)
    if text:
        return text
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _path(value: Any) -> str:
    text = _text(value, "/")
    if not text:
        return "/"
    if text.startswith("http://") or text.startswith("https://"):
        parsed = urlsplit(text)
        return parsed.path or "/"
    return text if text.startswith("/") else f"/{text}"


def _event_id(row: dict[str, Any]) -> str:
    ray_name = _text(row.get("rayName"))
    if ray_name:
        return f"cloudflare:{ray_name}"
    digest_source = "|".join(
        [
            _text(row.get("datetime")),
            _text(row.get("clientIP")),
            _text(row.get("clientRequestHTTPMethodName")),
            _text(row.get("clientRequestPath")),
            _text(row.get("action")),
        ]
    )
    return "cloudflare:" + hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:24]


def normalize_security_event(row: dict[str, Any], ip_lookup: IpLookup | None = None) -> dict[str, Any]:
    action = _text(row.get("action"), "allow").lower()
    source = _text(row.get("source"), "cloudflare")
    rule_id = _text(row.get("ruleId"))
    description = _text(row.get("description"))
    path = _path(row.get("clientRequestPath"))
    method = _text(row.get("clientRequestHTTPMethodName"), "GET").upper()
    status_code = _int(row.get("edgeResponseStatus"))
    country = _text(row.get("clientCountryName"))
    region = ""
    city = ""
    latitude_input = row.get("latitude")
    longitude_input = row.get("longitude")
    ip_location = ip_lookup(row.get("clientIP")) if ip_lookup else None
    if ip_location:
        country = country or _text(ip_location.get("countryCode"))
        region = _text(ip_location.get("regionName"))
        city = _text(ip_location.get("cityName"))
        latitude_input = latitude_input if latitude_input is not None else ip_location.get("latitude")
        longitude_input = longitude_input if longitude_input is not None else ip_location.get("longitude")
    latitude, longitude, location_precision = resolve_geo_coordinates(
        country=country,
        latitude=latitude_input,
        longitude=longitude_input,
        city=city,
        region=region,
        client_ip=row.get("clientIP"),
    )
    event_type = source or "cloudflare_security_event"
    risk_level = "info"
    confidence = 0.65
    if action in BLOCK_ACTIONS:
        risk_level = "high"
        confidence = 0.9
    elif action in CHALLENGE_ACTIONS:
        risk_level = "medium"
        confidence = 0.82
    elif action in {"log", "simulate"}:
        risk_level = "low"
        confidence = 0.72

    return {
        "id": _event_id(row),
        "source": "cloudflare",
        "timestamp": _iso(row.get("datetime")),
        "clientIp": _text(row.get("clientIP")),
        "country": country,
        "region": region,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
        "locationPrecision": location_precision,
        "asn": _text(row.get("clientAsn")),
        "method": method,
        "host": _text(row.get("clientRequestHTTPHost")),
        "path": path,
        "query": _text(row.get("clientRequestQuery")) or None,
        "statusCode": status_code,
        "userAgent": _text(row.get("userAgent")),
        "referer": None,
        "rayId": _text(row.get("rayName")),
        "action": action or "allow",
        "ruleId": rule_id,
        "ruleName": description or source or rule_id,
        "eventType": event_type,
        "riskLevel": risk_level,
        "confidence": confidence,
        "summary": description or f"Cloudflare {action or 'event'} {method} {path}",
        "ruleMatches": [value for value in [source, rule_id, action] if value],
        "attackCategory": "edge_security" if action in BLOCK_ACTIONS or action in CHALLENGE_ACTIONS else "",
        "attackSubtype": source or "cloudflare_security_event",
        "toolSignature": "cloudflare_firewall" if action in BLOCK_ACTIONS or action in CHALLENGE_ACTIONS else "",
        "behaviorFingerprint": "cloudflare_security_event",
        "campaignId": "",
        "ruleHits": [],
        "aiClusterId": "",
        "ruleVersion": "",
        "raw": {
            "cloudflare": row,
            "geo": {
                "source": _text(ip_location.get("source")) if ip_location else "",
                "edition": _text(ip_location.get("edition")) if ip_location else "",
                "country": country,
                "countryName": _text(ip_location.get("countryName")) if ip_location else "",
                "region": region,
                "city": city,
                "latitude": latitude,
                "longitude": longitude,
                "locationPrecision": location_precision,
                "zipCode": _text(ip_location.get("zipCode")) if ip_location else "",
                "timeZone": _text(ip_location.get("timeZone")) if ip_location else "",
            },
        },
    }


def normalize_security_events(rows: list[dict[str, Any]], ip_lookup: IpLookup | None = None) -> list[dict[str, Any]]:
    return [normalize_security_event(row, ip_lookup=ip_lookup) for row in rows if isinstance(row, dict)]


def _sum_bytes(row: dict[str, Any]) -> int:
    return _int((row.get("sum") or {}).get("edgeResponseBytes"))


def _dimension(row: dict[str, Any], key: str, default: str = "") -> str:
    return _text((row.get("dimensions") or {}).get(key), default)


def build_http_aggregate_rows(http_analytics: dict[str, list[dict[str, Any]]], from_time: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cache_bytes_by_hour: dict[str, int] = {}
    cache_requests_by_hour: dict[str, int] = {}
    for row in http_analytics.get("httpCache", []):
        hour = _dimension(row, "datetimeHour")
        cache_status = _dimension(row, "cacheStatus").lower()
        if hour and cache_status in CACHED_STATUSES:
            cache_bytes_by_hour[hour] = cache_bytes_by_hour.get(hour, 0) + _sum_bytes(row)
            cache_requests_by_hour[hour] = cache_requests_by_hour.get(hour, 0) + _int(row.get("count"))

    for index, row in enumerate(http_analytics.get("httpHourly", [])):
        hour = _dimension(row, "datetimeHour", from_time)
        bandwidth = _sum_bytes(row)
        cached = cache_bytes_by_hour.get(hour, 0)
        rows.append(
            {
                "id": f"cloudflare:traffic:{hour or index}",
                "bucket_type": "hour",
                "bucket_start": hour or from_time,
                "dimension": "cloudflare:traffic",
                "dimension_value": "all",
                "total_count": _int(row.get("count")),
                "threat_count": 0,
                "blocked_count": 0,
                "challenge_count": 0,
                "bandwidth_bytes": bandwidth,
                "cached_bytes": cached,
                "origin_bytes": max(0, bandwidth - cached),
            }
        )

    rows.extend(_ranked_rows("cloudflare:country", "clientCountryName", http_analytics.get("httpCountries", []), from_time))
    rows.extend(_ranked_rows("cloudflare:status", "edgeResponseStatus", http_analytics.get("httpStatuses", []), from_time))
    rows.extend(_ranked_rows("cloudflare:path", "clientRequestPath", http_analytics.get("httpPaths", []), from_time))
    return rows


def _ranked_rows(dimension: str, dimension_key: str, source_rows: list[dict[str, Any]], bucket_start: str) -> list[dict[str, Any]]:
    rows = []
    for index, row in enumerate(source_rows):
        value = _dimension(row, dimension_key, "unknown")
        bandwidth = _sum_bytes(row)
        rows.append(
            {
                "id": f"{dimension}:{index}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}",
                "bucket_type": "range",
                "bucket_start": bucket_start,
                "dimension": dimension,
                "dimension_value": value or "unknown",
                "total_count": _int(row.get("count")),
                "threat_count": 0,
                "blocked_count": 0,
                "challenge_count": 0,
                "bandwidth_bytes": bandwidth,
                "cached_bytes": 0,
                "origin_bytes": bandwidth,
            }
        )
    return rows
