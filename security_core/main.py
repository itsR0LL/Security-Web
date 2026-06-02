from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from .cloudflare_client import CloudflareClient, CloudflareClientError
from .config import DEFAULT_ALLOWED_ORIGINS
from .database import init_db, utc_now
from .event_normalizer import build_http_aggregate_rows, normalize_security_events
from .repository import (
    count_events,
    create_sync_run,
    get_cloudflare_token,
    get_cloudflare_zone_id,
    get_event,
    get_monitored_host,
    get_overview,
    get_rules,
    get_settings,
    get_sync_status,
    get_traffic_trend,
    has_cloudflare_token,
    list_events,
    map_payload,
    normalize_event_limit,
    normalize_event_offset,
    replace_cloudflare_aggregates,
    replace_cloudflare_events,
    seed_sample_dataset,
    source_summary,
    update_cloudflare_settings,
    update_risk_threshold,
)
from .token_check import check_cloudflare_token


def api_success(data: Any, **extra: Any) -> dict[str, Any]:
    return {"success": True, "data": data, **extra}


def token_check_state(check: dict[str, Any], *, sample_mode: bool = False) -> dict[str, Any]:
    if sample_mode:
        return {
            "mode": "sample",
            "status": "sample",
            "cloudflareLive": False,
            "message": "Cloudflare Token is not configured. Sample data mode is active.",
        }
    if check["status"] == "success":
        return {
            "mode": "live",
            "status": "success",
            "cloudflareLive": True,
            "message": "Cloudflare GraphQL access verified.",
        }
    if check["status"] == "degraded":
        return {
            "mode": "degraded",
            "status": "degraded",
            "cloudflareLive": True,
            "message": check.get("errorMessage") or "Cloudflare GraphQL access is partially available.",
        }
    return {
        "mode": "degraded",
        "status": "degraded",
        "cloudflareLive": False,
        "message": check.get("errorMessage") or "Cloudflare token check failed.",
    }


def configured_origins() -> set[str]:
    raw = os.environ.get("SECURITY_ALLOWED_ORIGINS", "")
    if not raw:
        return set(DEFAULT_ALLOWED_ORIGINS)
    return {origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()}


def is_allowed_origin(origin: str) -> bool:
    if not origin:
        return True
    cleaned = origin.rstrip("/")
    if cleaned in configured_origins():
        return True
    return cleaned.startswith("http://127.0.0.1:") or cleaned.startswith("http://localhost:")


def cors_headers(origin: str) -> dict[str, str]:
    if not origin or not is_allowed_origin(origin):
        return {}
    return {
        "Access-Control-Allow-Origin": origin.rstrip("/"),
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Manager-Token",
        "Vary": "Origin",
    }


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if not has_cloudflare_token():
        seed_sample_dataset("sample")
    yield


app = FastAPI(title="Security Studio API", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def local_cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")
    if origin and not is_allowed_origin(origin):
        return JSONResponse({"success": False, "message": "Origin is not allowed."}, status_code=403)
    if request.method.upper() == "OPTIONS":
        return Response(status_code=204, headers=cors_headers(origin))
    response = await call_next(request)
    for key, value in cors_headers(origin).items():
        response.headers[key] = value
    return response


@app.get("/api/health")
def health() -> dict[str, Any]:
    return api_success({"status": "online", "service": "security-studio", "time": utc_now()})


@app.get("/api/status")
def status() -> dict[str, Any]:
    return api_success({"status": "online", "message": "Security Studio backend is connected."})


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    return api_success(get_overview())


@app.get("/api/events")
def events(
    from_time: str | None = Query(None, alias="from"),
    to_time: str | None = Query(None, alias="to"),
    time_range: str | None = Query(None, alias="timeRange"),
    ip: str | None = None,
    country: str | None = None,
    region: str | None = None,
    risk_level: str | None = Query(None, alias="risk_level"),
    risk_level_camel: str | None = Query(None, alias="riskLevel"),
    risk: str | None = None,
    event_type: str | None = Query(None, alias="event_type"),
    event_type_camel: str | None = Query(None, alias="eventType"),
    action: str | None = None,
    path: str | None = None,
    user_agent: str | None = Query(None, alias="userAgent"),
    method: str | None = None,
    status_code: int | None = Query(None, alias="status_code"),
    status_code_camel: int | None = Query(None, alias="statusCode"),
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    if time_range and not from_time:
        hours_by_key = {"6h": 6, "24h": 24, "7d": 24 * 7}
        hours = hours_by_key.get(time_range)
        if hours:
            from_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds").replace("+00:00", "Z")
    explicit_risk_level = risk_level or risk_level_camel
    risk_value = explicit_risk_level or ("high" if risk == "high+" else risk)
    filters = {
        "from_time": from_time,
        "to_time": to_time,
        "ip": ip,
        "country": country,
        "region": region,
        "risk_level": risk_value,
        "risk_at_or_above": bool(risk and not explicit_risk_level and risk in {"high", "high+"}),
        "event_type": event_type or event_type_camel,
        "action": action,
        "path": path,
        "user_agent": user_agent,
        "method": method,
        "status_code": status_code if status_code is not None else status_code_camel,
        "limit": limit,
        "offset": offset,
    }
    data = list_events(filters)
    total = count_events(filters)
    return api_success(
        data,
        total=total,
        limit=normalize_event_limit(limit),
        offset=normalize_event_offset(offset),
    )


@app.get("/api/events/{event_id}")
def event_detail(event_id: str) -> dict[str, Any]:
    event = get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    return api_success(event)


@app.get("/api/aggregates/trends")
def aggregate_trends() -> dict[str, Any]:
    overview_data = get_overview()
    return api_success(
        {
            "trafficTrend": get_traffic_trend(),
            "statusCodes": overview_data["statusCodes"],
            "riskDistribution": overview_data["riskDistribution"],
            "eventTypes": overview_data["eventTypes"],
        }
    )


@app.get("/api/aggregates/sources")
def aggregate_sources() -> dict[str, Any]:
    return api_success(source_summary())


@app.get("/api/aggregates/map")
def aggregate_map() -> dict[str, Any]:
    return api_success(map_payload())


@app.get("/api/sync/status")
def sync_status() -> dict[str, Any]:
    return api_success(get_sync_status())


@app.post("/api/sync/run")
def sync_run() -> dict[str, Any]:
    token = get_cloudflare_token()
    if not token:
        result = seed_sample_dataset("sample")
        return api_success(
            {
                "mode": "sample",
                "status": "sample",
                "cloudflareLive": False,
                "usedStaleData": False,
                **result,
                "message": "Cloudflare Token is not configured. Sample data was refreshed.",
            }
        )

    check = check_cloudflare_token(persist=True)
    if not check["zoneRead"] or not check["analyticsRead"]:
        create_sync_run(status="failed", error_message=check["errorMessage"], used_stale_data=True)
        return api_success(
            {
                "mode": "stale",
                "status": "stale",
                "cloudflareLive": False,
                "usedStaleData": True,
                "message": "Cloudflare sync was not executed. Existing data was kept.",
                "tokenCheck": check,
            }
        )

    client = CloudflareClient()
    try:
        fetched = client.fetch_zone_data(zone_id=get_cloudflare_zone_id(), token=token, host=get_monitored_host(), hours=24)
    except CloudflareClientError as error:
        create_sync_run(status="failed", error_message=str(error), used_stale_data=True)
        return api_success(
            {
                "mode": "stale",
                "status": "stale",
                "cloudflareLive": False,
                "usedStaleData": True,
                "message": "Cloudflare sync failed. Existing data was kept.",
                "errorType": error.error_type,
                "tokenCheck": check,
            }
        )

    aggregate_rows = build_http_aggregate_rows(fetched.http_analytics, fetched.from_time)
    aggregate_count = replace_cloudflare_aggregates(aggregate_rows)
    event_count = 0
    used_stale_data = False
    if fetched.security_events_read:
        events_data = normalize_security_events(fetched.security_events)
        event_count = replace_cloudflare_events(events_data)
    else:
        used_stale_data = True

    status_value = "success" if fetched.security_events_read else "degraded"
    error_message = None
    if fetched.degraded_reasons:
        error_message = "Cloudflare Security Events are unavailable. HTTP analytics were synced."
    create_sync_run(
        status=status_value,
        event_count=event_count,
        aggregate_count=aggregate_count,
        error_message=error_message,
        used_stale_data=used_stale_data,
        from_time=fetched.from_time,
        to_time=fetched.to_time,
    )
    return api_success(
        {
            "mode": "live" if status_value == "success" else "degraded",
            "status": status_value,
            "syncStatus": status_value,
            "cloudflareLive": True,
            "httpAnalyticsLive": fetched.analytics_read,
            "securityEventsLive": fetched.security_events_read,
            "usedStaleData": used_stale_data,
            "events": event_count,
            "aggregates": aggregate_count,
            "monitoredHost": get_monitored_host(),
            "degradedReasons": fetched.degraded_reasons,
            "fromTime": fetched.from_time,
            "toTime": fetched.to_time,
            "tokenCheck": check,
            "message": error_message or "Cloudflare GraphQL data synced.",
        }
    )


@app.get("/api/settings")
def settings() -> dict[str, Any]:
    return api_success(get_settings())


@app.post("/api/settings/cloudflare")
def save_cloudflare_settings(payload: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    payload = payload or {}
    update_cloudflare_settings(payload)
    check = check_cloudflare_token(persist=True)
    settings_data = get_settings()
    return api_success(
        {
            **token_check_state(check, sample_mode=settings_data["sampleMode"]),
            "settings": settings_data,
            "tokenCheck": check,
        }
    )


@app.post("/api/token/check")
def token_check(payload: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    payload = payload or {}
    check = check_cloudflare_token(payload, persist=True)
    sample_mode = not get_cloudflare_token() and not any(
        str(payload.get(key) or "").strip() for key in ("apiToken", "cloudflareToken", "token")
    )
    return api_success({**token_check_state(check, sample_mode=sample_mode), "tokenCheck": check})


@app.post("/api/settings/risk-threshold")
def save_risk_threshold(payload: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    payload = payload or {}
    level = str(payload.get("riskLevel") or payload.get("highRiskThreshold") or "").strip()
    try:
        update_risk_threshold(level)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return api_success(get_settings())


@app.get("/api/rules")
def rules() -> dict[str, Any]:
    return api_success(get_rules())


@app.get("/api/analysis/summary")
def analysis_summary() -> dict[str, Any]:
    overview_data = get_overview()
    sync = overview_data["sync"]
    return api_success(
        {
            "status": "reserved",
            "message": "AI analysis is reserved. Current summary is generated from rule matching and Cloudflare aggregates.",
            "generatedAt": overview_data["generatedAt"],
            "items": [
                {"label": "mode", "value": sync.get("mode") or sync.get("status"), "detail": "Current data source mode"},
                {"label": "events", "value": sync["localEventCount"], "detail": "Stored event rows"},
                {"label": "aggregates", "value": sync["aggregateCount"], "detail": "Stored aggregate rows"},
                {"label": "sources", "value": len(overview_data["globePoints"]), "detail": "Visible source points"},
            ],
        }
    )
