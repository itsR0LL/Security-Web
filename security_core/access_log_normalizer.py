from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .config import DEFAULT_MONITORED_HOST
from .database import utc_now
from .geo import resolve_geo_coordinates


IpLookup = Callable[[Any], dict[str, Any] | None]


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


def _nested_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_string(*values: Any) -> str:
    for value in values:
        text = _string(value)
        if text:
            return text
    return ""


def _first_value(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            if value.strip():
                return value
        else:
            return value
    return None


def normalize_worker_access_log(row: dict[str, Any], ip_lookup: IpLookup | None = None) -> dict[str, Any]:
    stored_raw = _raw_object(row.get("raw_json"))
    worker_raw = _nested_object(stored_raw.get("workerRaw")) or stored_raw
    body = _nested_object(worker_raw.get("body"))
    cf = _nested_object(worker_raw.get("cf"))
    visitor_location = _nested_object(worker_raw.get("visitorLocation"))
    body_client_ip = _first_string(body.get("clientIp"), body.get("client_ip"))
    client_ip = _first_string(row.get("client_ip"), body_client_ip)
    if body_client_ip:
        country = _first_string(body.get("country")).upper()
        region = _first_string(body.get("region"))
        city = _first_string(body.get("city"))
        latitude_input = _first_value(body.get("latitude"), body.get("lat"))
        longitude_input = _first_value(body.get("longitude"), body.get("lon"))
        asn = _first_string(body.get("asn"))
    else:
        country = _first_string(row.get("country"), visitor_location.get("country"), cf.get("country")).upper()
        region = _first_string(row.get("region"), visitor_location.get("region"), cf.get("region"))
        city = _first_string(row.get("city"), visitor_location.get("city"), cf.get("city"))
        latitude_input = _first_value(visitor_location.get("latitude"), cf.get("latitude"))
        longitude_input = _first_value(visitor_location.get("longitude"), cf.get("longitude"))
        asn = _first_string(visitor_location.get("asn"), cf.get("asn"))
    ip_location = ip_lookup(client_ip) if ip_lookup else None
    if ip_location:
        country = country or _first_string(ip_location.get("countryCode")).upper()
        region = region or _first_string(ip_location.get("regionName"))
        city = city or _first_string(ip_location.get("cityName"))
        latitude_input = latitude_input if _first_value(latitude_input) is not None else ip_location.get("latitude")
        longitude_input = longitude_input if _first_value(longitude_input) is not None else ip_location.get("longitude")
    latitude, longitude, precision = resolve_geo_coordinates(
        country=country,
        region=region,
        city=city,
        latitude=latitude_input,
        longitude=longitude_input,
        client_ip=client_ip,
    )
    return {
        "id": _string(row.get("id")),
        "source": "worker_log",
        "sourceCursor": _integer(row.get("cursor")),
        "receivedAt": _string(row.get("received_at")) or utc_now(),
        "timestamp": _string(row.get("occurred_at")) or utc_now(),
        "clientIp": client_ip,
        "ipHash": _string(row.get("ip_hash")),
        "country": country,
        "region": region,
        "city": city,
        "colo": _string(row.get("colo")),
        "latitude": latitude,
        "longitude": longitude,
        "locationPrecision": precision,
        "asn": f"AS{asn}" if asn and not asn.upper().startswith("AS") else asn,
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
            "workerRaw": worker_raw,
            "geo": {
                "source": _first_string(ip_location.get("source")) if ip_location else "",
                "edition": _first_string(ip_location.get("edition")) if ip_location else "",
                "country": country,
                "countryName": _first_string(ip_location.get("countryName")) if ip_location else "",
                "region": region,
                "city": city,
                "latitude": latitude,
                "longitude": longitude,
                "locationPrecision": precision,
                "asn": asn,
                "zipCode": _first_string(ip_location.get("zipCode")) if ip_location else "",
                "timeZone": _first_string(ip_location.get("timeZone")) if ip_location else "",
            },
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
        "asn": log.get("asn", ""),
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
