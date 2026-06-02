from __future__ import annotations

import re
from typing import Any

from .cloudflare_client import CloudflareClient, CloudflareClientError
from .database import utc_now
from .repository import get_cloudflare_token, get_cloudflare_zone_id, insert_token_check


ZONE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,}$")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _permission(name: str, ok: bool, detail: str | None) -> dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail or ""}


def _build_result(
    *,
    status: str,
    zone_read: bool,
    analytics_read: bool,
    security_events_read: bool,
    error_message: str | None,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "checkedAt": utc_now(),
        "status": status,
        "zoneRead": zone_read,
        "analyticsRead": analytics_read,
        "securityEventsRead": security_events_read,
        "errorMessage": error_message,
        "details": details,
        "permissions": [
            _permission("Zone Read", zone_read, "Cloudflare zone access verified." if zone_read else error_message),
            _permission("Analytics Read", analytics_read, "Cloudflare HTTP analytics access verified." if analytics_read else error_message),
            _permission(
                "Security Events Read",
                security_events_read,
                "Cloudflare Security Events access verified." if security_events_read else error_message,
            ),
        ],
    }


def _local_validation_result(zone_id: str, token: str) -> dict[str, Any] | None:
    zone_format_ok = bool(zone_id and ZONE_ID_PATTERN.match(zone_id))
    token_format_ok = bool(token and len(token) >= 10 and not any(char.isspace() for char in token))
    missing = []
    if not zone_id:
        missing.append("Zone ID")
    if not token:
        missing.append("Cloudflare API Token")
    if missing:
        message = f"Missing required Cloudflare configuration: {', '.join(missing)}."
        return _build_result(
            status="failed",
            zone_read=False,
            analytics_read=False,
            security_events_read=False,
            error_message=message,
            details={"mode": "live", "networkRequest": False, "endpoint": None, "errorType": "token_missing"},
        )
    if not zone_format_ok:
        message = "Zone ID format is invalid."
        return _build_result(
            status="failed",
            zone_read=False,
            analytics_read=False,
            security_events_read=False,
            error_message=message,
            details={"mode": "live", "networkRequest": False, "endpoint": None, "errorType": "zone_not_found"},
        )
    if not token_format_ok:
        message = "Cloudflare API Token format is invalid."
        return _build_result(
            status="failed",
            zone_read=True,
            analytics_read=False,
            security_events_read=False,
            error_message=message,
            details={"mode": "live", "networkRequest": False, "endpoint": None, "errorType": "token_invalid"},
        )
    return None


def check_cloudflare_token(payload: dict[str, Any] | None = None, *, persist: bool = True) -> dict[str, Any]:
    data = payload or {}
    zone_id = _clean(data.get("zoneId") or data.get("cloudflareZoneId") or get_cloudflare_zone_id())
    token = _clean(data.get("apiToken") or data.get("cloudflareToken") or data.get("token") or get_cloudflare_token())

    local_result = _local_validation_result(zone_id, token)
    if local_result:
        if persist:
            insert_token_check(local_result)
        return local_result

    client = CloudflareClient()
    try:
        access = client.check_access(zone_id=zone_id, token=token)
    except CloudflareClientError as error:
        result = _build_result(
            status="failed",
            zone_read=error.error_type not in {"token_invalid", "network_error"},
            analytics_read=False,
            security_events_read=False,
            error_message=str(error),
            details={
                "mode": "live",
                "networkRequest": True,
                "endpoint": client.endpoint,
                "errorType": error.error_type,
            },
        )
        if persist:
            insert_token_check(result)
        return result

    result = _build_result(
        status=access.status,
        zone_read=access.zone_read,
        analytics_read=access.analytics_read,
        security_events_read=access.security_events_read,
        error_message=access.error_message,
        details={
            **access.details,
            "mode": "live",
            "errorType": access.error_type,
        },
    )
    if persist:
        insert_token_check(result)
    return result
