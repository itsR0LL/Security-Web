from __future__ import annotations

import re
from typing import Any

from .database import utc_now
from .repository import get_cloudflare_token, get_cloudflare_zone_id, insert_token_check


ZONE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,}$")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def check_cloudflare_token(payload: dict[str, Any] | None = None, *, persist: bool = True) -> dict[str, Any]:
    data = payload or {}
    zone_id = _clean(data.get("zoneId") or data.get("cloudflareZoneId") or get_cloudflare_zone_id())
    token = _clean(data.get("apiToken") or data.get("cloudflareToken") or data.get("token") or get_cloudflare_token())

    zone_read = bool(zone_id and ZONE_ID_PATTERN.match(zone_id))
    token_format_ok = bool(token and len(token) >= 10 and not any(char.isspace() for char in token))
    analytics_read = zone_read and token_format_ok
    security_events_read = zone_read and token_format_ok

    missing = []
    if not zone_read:
        missing.append("Zone ID")
    if not token_format_ok:
        missing.append("Cloudflare API Token")

    status = "success" if zone_read and analytics_read and security_events_read else "failed"
    error_message = None if status == "success" else f"本地配置校验未通过：{', '.join(missing)}。"
    result = {
        "checkedAt": utc_now(),
        "status": status,
        "zoneRead": zone_read,
        "analyticsRead": analytics_read,
        "securityEventsRead": security_events_read,
        "errorMessage": error_message,
        "details": {
            "mode": "mock",
            "networkRequest": False,
            "message": "MVP 阶段仅校验 Zone ID 和 Token 格式，不调用 Cloudflare。",
        },
        "permissions": [
            {"name": "Zone Read", "ok": zone_read, "detail": "Zone ID 格式已通过本地校验" if zone_read else "Zone ID 缺失或格式异常"},
            {"name": "Analytics Read", "ok": analytics_read, "detail": "Token 格式允许读取 Analytics" if analytics_read else "Token 缺失或格式异常"},
            {"name": "Security Events Read", "ok": security_events_read, "detail": "Token 格式允许读取 Security Events" if security_events_read else "Token 缺失或格式异常"},
        ],
    }
    if persist:
        insert_token_check(result)
    return result

