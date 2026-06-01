from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from .config import DEFAULT_ALLOWED_ORIGINS
from .database import init_db, utc_now
from .repository import (
    count_events,
    get_cloudflare_token,
    get_event,
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
            "message": "未配置 Cloudflare Token，当前保持样例数据模式。",
        }
    if check["status"] == "success":
        return {
            "mode": "mock",
            "status": "mock",
            "cloudflareLive": False,
            "message": "Token 仅通过本地结构校验，MVP 阶段尚未调用 Cloudflare。",
        }
    return {
        "mode": "degraded",
        "status": "degraded",
        "cloudflareLive": False,
        "message": check.get("errorMessage") or "Token 配置未通过本地校验。",
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
    if not get_cloudflare_token():
        result = seed_sample_dataset("sample")
        return api_success(
            {
                "mode": "sample",
                "status": "sample",
                "cloudflareLive": False,
                "usedStaleData": False,
                **result,
                "message": "未配置 Cloudflare Token，已刷新样例数据。",
            }
        )

    check = check_cloudflare_token(persist=True)
    if check["status"] != "success":
        from .repository import create_sync_run

        create_sync_run(status="failed", error_message=check["errorMessage"], used_stale_data=True)
        return api_success(
            {
                "mode": "degraded",
                "status": "stale",
                "cloudflareLive": False,
                "usedStaleData": True,
                "message": "Token 配置未通过本地校验，同步未执行，继续保留旧数据。",
                "tokenCheck": check,
            }
        )

    result = seed_sample_dataset(
        "cloudflare",
        sync_status="partial",
        error_message="MVP 阶段未调用 Cloudflare，当前为结构等价的 mock 同步数据。",
        used_stale_data=False,
    )
    return api_success(
        {
            "mode": "mock",
            "status": "mock",
            "syncStatus": "partial",
            "cloudflareLive": False,
            "usedStaleData": False,
            "tokenCheck": check,
            **result,
            "message": "MVP 阶段尚未调用 Cloudflare，已写入结构等价的模拟同步数据。",
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
