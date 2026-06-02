from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"


class CloudflareClientError(Exception):
    def __init__(self, error_type: str, message: str, errors: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.errors = errors or []


@dataclass
class CloudflareAccessResult:
    status: str
    error_type: str | None
    error_message: str | None
    zone_read: bool
    analytics_read: bool
    security_events_read: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudflareFetchResult:
    security_events: list[dict[str, Any]]
    http_analytics: dict[str, list[dict[str, Any]]]
    degraded_reasons: list[str]
    from_time: str
    to_time: str

    @property
    def analytics_read(self) -> bool:
        return any(self.http_analytics.get(key) for key in self.http_analytics)

    @property
    def security_events_read(self) -> bool:
        return "security_events_unavailable" not in self.degraded_reasons


def utc_window(hours: int = 24) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    return (
        since.isoformat(timespec="seconds").replace("+00:00", "Z"),
        now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _error_messages(errors: list[dict[str, Any]]) -> list[str]:
    return [str(error.get("message") or "") for error in errors if error.get("message")]


def classify_graphql_error(errors: list[dict[str, Any]], http_status: int | None = None) -> str:
    messages = " ".join(_error_messages(errors)).lower()
    if http_status in {401, 403}:
        if "authentication" in messages or "token" in messages:
            return "token_invalid"
        return "permission_denied"
    if "authentication" in messages or "invalid token" in messages or "token" in messages and "invalid" in messages:
        return "token_invalid"
    if "permission" in messages or "not authorized" in messages or "access" in messages or "forbidden" in messages:
        return "permission_denied"
    return "graphql_error"


def is_error_for_path(error: dict[str, Any], field_name: str) -> bool:
    path = error.get("path")
    if isinstance(path, list) and field_name in {str(item) for item in path}:
        return True
    message = str(error.get("message") or "")
    return field_name in message


class CloudflareClient:
    def __init__(self, *, endpoint: str = GRAPHQL_ENDPOINT, timeout: float = 20.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def execute(self, token: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                response = client.post(self.endpoint, headers=headers, json={"query": query, "variables": variables})
        except httpx.RequestError as error:
            raise CloudflareClientError("network_error", f"Cloudflare network error: {error.__class__.__name__}") from error

        try:
            payload = response.json()
        except ValueError as error:
            raise CloudflareClientError("graphql_error", "Cloudflare returned a non-JSON response.") from error

        errors = payload.get("errors") if isinstance(payload, dict) else None
        if response.status_code >= 400:
            normalized_errors = errors if isinstance(errors, list) else []
            error_type = classify_graphql_error(normalized_errors, response.status_code)
            message = "; ".join(_error_messages(normalized_errors)) or f"Cloudflare HTTP {response.status_code}."
            raise CloudflareClientError(error_type, message, normalized_errors)
        if not isinstance(payload, dict):
            raise CloudflareClientError("graphql_error", "Cloudflare returned an invalid GraphQL payload.")
        return payload

    def check_access(self, *, zone_id: str, token: str) -> CloudflareAccessResult:
        since, until = utc_window(24)
        query = """
        query CheckCloudflareAccess($zoneTag: string, $since: Time, $until: Time) {
          viewer {
            zones(filter: {zoneTag: $zoneTag}) {
              zoneTag
              httpRequestsAdaptiveGroups(
                limit: 1
                filter: {datetime_geq: $since, datetime_leq: $until}
              ) {
                count
              }
              firewallEventsAdaptive(
                limit: 1
                filter: {datetime_geq: $since, datetime_leq: $until}
              ) {
                datetime
                rayName
              }
            }
          }
        }
        """
        payload = self.execute(token, query, {"zoneTag": zone_id, "since": since, "until": until})
        errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
        data = payload.get("data") or {}
        zones = ((data.get("viewer") or {}).get("zones") or []) if isinstance(data, dict) else []
        zone_read = bool(zones)
        if not zone_read:
            return CloudflareAccessResult(
                status="failed",
                error_type="zone_not_found",
                error_message="Cloudflare Zone was not found for the saved zoneId.",
                zone_read=False,
                analytics_read=False,
                security_events_read=False,
                details={"networkRequest": True, "endpoint": self.endpoint, "zoneCount": 0},
            )

        analytics_error = any(is_error_for_path(error, "httpRequestsAdaptiveGroups") for error in errors)
        security_error = any(is_error_for_path(error, "firewallEventsAdaptive") for error in errors)
        other_errors = [
            error for error in errors if not is_error_for_path(error, "httpRequestsAdaptiveGroups") and not is_error_for_path(error, "firewallEventsAdaptive")
        ]
        analytics_read = not analytics_error and "httpRequestsAdaptiveGroups" in zones[0]
        security_events_read = not security_error and "firewallEventsAdaptive" in zones[0]
        if other_errors or not analytics_read:
            error_type = classify_graphql_error(other_errors or errors)
            return CloudflareAccessResult(
                status="failed",
                error_type=error_type,
                error_message="; ".join(_error_messages(other_errors or errors)) or "Cloudflare GraphQL access check failed.",
                zone_read=zone_read,
                analytics_read=analytics_read,
                security_events_read=security_events_read,
                details={"networkRequest": True, "endpoint": self.endpoint, "zoneCount": len(zones)},
            )
        if not security_events_read:
            return CloudflareAccessResult(
                status="degraded",
                error_type=classify_graphql_error(errors),
                error_message="; ".join(_error_messages(errors)) or "Cloudflare Security Events are unavailable.",
                zone_read=zone_read,
                analytics_read=True,
                security_events_read=False,
                details={"networkRequest": True, "endpoint": self.endpoint, "zoneCount": len(zones)},
            )
        return CloudflareAccessResult(
            status="success",
            error_type=None,
            error_message=None,
            zone_read=True,
            analytics_read=True,
            security_events_read=True,
            details={"networkRequest": True, "endpoint": self.endpoint, "zoneCount": len(zones)},
        )

    def fetch_zone_data(self, *, zone_id: str, token: str, host: str, hours: int = 24) -> CloudflareFetchResult:
        since, until = utc_window(hours)
        query = """
        query FetchCloudflareSecurityData($zoneTag: string, $since: Time, $until: Time, $host: string) {
          viewer {
            zones(filter: {zoneTag: $zoneTag}) {
              httpHourly: httpRequestsAdaptiveGroups(
                limit: 48
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [datetimeHour_ASC]
              ) {
                count
                dimensions { datetimeHour }
                sum { edgeResponseBytes }
              }
              httpCache: httpRequestsAdaptiveGroups(
                limit: 200
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [datetimeHour_ASC]
              ) {
                count
                dimensions { datetimeHour cacheStatus }
                sum { edgeResponseBytes }
              }
              httpCountries: httpRequestsAdaptiveGroups(
                limit: 20
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [count_DESC]
              ) {
                count
                dimensions { clientCountryName }
                sum { edgeResponseBytes }
              }
              httpStatuses: httpRequestsAdaptiveGroups(
                limit: 20
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [count_DESC]
              ) {
                count
                dimensions { edgeResponseStatus }
                sum { edgeResponseBytes }
              }
              httpPaths: httpRequestsAdaptiveGroups(
                limit: 20
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [count_DESC]
              ) {
                count
                dimensions { clientRequestPath }
                sum { edgeResponseBytes }
              }
              firewallEventsAdaptive(
                limit: 100
                filter: {datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host}
                orderBy: [datetime_DESC]
              ) {
                action
                clientASNDescription
                clientAsn
                clientCountryName
                clientIP
                clientRequestHTTPHost
                clientRequestHTTPMethodName
                clientRequestPath
                clientRequestQuery
                datetime
                description
                edgeResponseStatus
                rayName
                ruleId
                source
                userAgent
              }
            }
          }
        }
        """
        payload = self.execute(token, query, {"zoneTag": zone_id, "since": since, "until": until, "host": host})
        errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
        data = payload.get("data") or {}
        zones = ((data.get("viewer") or {}).get("zones") or []) if isinstance(data, dict) else []
        if not zones:
            raise CloudflareClientError("zone_not_found", "Cloudflare Zone was not found for the saved zoneId.")
        zone = zones[0]
        degraded_reasons = []
        http_fields = ["httpHourly", "httpCache", "httpCountries", "httpStatuses", "httpPaths"]
        if any(is_error_for_path(error, "firewallEventsAdaptive") for error in errors):
            degraded_reasons.append("security_events_unavailable")
        if any(is_error_for_path(error, field_name) for field_name in http_fields for error in errors):
            degraded_reasons.append("http_analytics_unavailable")
        other_errors = [
            error
            for error in errors
            if not is_error_for_path(error, "firewallEventsAdaptive") and not any(is_error_for_path(error, field_name) for field_name in http_fields)
        ]
        if other_errors:
            raise CloudflareClientError(classify_graphql_error(other_errors), "; ".join(_error_messages(other_errors)), other_errors)
        return CloudflareFetchResult(
            security_events=list(zone.get("firewallEventsAdaptive") or []),
            http_analytics={field_name: list(zone.get(field_name) or []) for field_name in http_fields},
            degraded_reasons=degraded_reasons,
            from_time=since,
            to_time=until,
        )
