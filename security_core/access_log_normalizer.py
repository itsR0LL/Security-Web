from __future__ import annotations

import json
from typing import Any

from .config import DEFAULT_MONITORED_HOST
from .database import utc_now
from .geo import stable_country_coordinates


def _string(value: Any) -> str:
    return str(value or "").strip()


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _raw_json(value: Any) -> str:
    if isinstance(value, str):
        return value or "{}"
    try:
        return json.dumps(value or {}, ensure_ascii=False)
    except (TypeError, ValueError):
        return "{}"


def _raw_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(_raw_json(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def normalize_worker_access_log(row: dict[str, Any]) -> dict[str, Any]:
    country = _string(row.get("country")).upper()
    latitude, longitude, precision = stable_country_coordinates(country)
    return {
        "id": _string(row.get("id")),
        "source": "worker_log",
        "sourceCursor": _integer(row.get("cursor")),
        "receivedAt": _string(row.get("received_at")) or utc_now(),
        "timestamp": _string(row.get("occurred_at")) or utc_now(),
        "clientIp": _string(row.get("client_ip")),
        "ipHash": _string(row.get("ip_hash")),
        "country": country,
        "region": _string(row.get("region")),
        "city": _string(row.get("city")),
        "colo": _string(row.get("colo")),
        "latitude": latitude,
        "longitude": longitude,
        "locationPrecision": precision,
        "method": (_string(row.get("method")) or "GET").upper(),
        "host": _string(row.get("host")) or DEFAULT_MONITORED_HOST,
        "path": _string(row.get("path")) or "/",
        "query": _string(row.get("query")) or None,
        "statusCode": _integer(row.get("status_code")),
        "userAgent": _string(row.get("user_agent")),
        "referer": _string(row.get("referer")) or None,
        "rayId": _string(row.get("cf_ray")),
        "requestId": _string(row.get("request_id")),
        "responseBytes": _integer(row.get("response_bytes")),
        "action": "allow",
        "ruleId": "",
        "ruleName": "",
        "eventType": "normal_visit",
        "riskLevel": "info",
        "confidence": 0.35,
        "summary": "Worker access log",
        "ruleMatches": [],
        "attackCategory": "",
        "attackSubtype": "",
        "toolSignature": "",
        "behaviorFingerprint": "",
        "campaignId": "",
        "ruleHits": [],
        "aiClusterId": "",
        "ruleVersion": "",
        "raw": {
            "source": "worker_log",
            "sourceCursor": _integer(row.get("cursor")),
            "ipHash": _string(row.get("ip_hash")),
            "colo": _string(row.get("colo")),
            "requestId": _string(row.get("request_id")),
            "responseBytes": _integer(row.get("response_bytes")),
            "workerRaw": _raw_object(row.get("raw_json")),
        },
    }


def worker_access_log_to_event(log: dict[str, Any]) -> dict[str, Any]:
    event_id = f"worker-log:{log['id']}"
    path = log.get("path") or "/"
    method = log.get("method") or "GET"
    query = log.get("query")
    return {
        "id": event_id,
        "source": "worker_log",
        "timestamp": log["timestamp"],
        "clientIp": log.get("clientIp", ""),
        "country": log.get("country", ""),
        "region": log.get("region", ""),
        "city": log.get("city", ""),
        "latitude": log.get("latitude", 0),
        "longitude": log.get("longitude", 0),
        "locationPrecision": log.get("locationPrecision", "estimated"),
        "asn": "",
        "method": method,
        "host": log.get("host", DEFAULT_MONITORED_HOST),
        "path": path,
        "query": query,
        "statusCode": log.get("statusCode", 0),
        "userAgent": log.get("userAgent", ""),
        "referer": log.get("referer"),
        "rayId": log.get("rayId", ""),
        "action": "allow",
        "ruleId": "",
        "ruleName": "",
        "eventType": "normal_visit",
        "riskLevel": "info",
        "confidence": 0.35,
        "summary": f"{method} {path}",
        "ruleMatches": [],
        "attackCategory": "",
        "attackSubtype": "",
        "toolSignature": "",
        "behaviorFingerprint": "",
        "campaignId": "",
        "ruleHits": [],
        "aiClusterId": "",
        "ruleVersion": "",
        "raw": {
            **log.get("raw", {}),
            "query": query,
        },
    }
