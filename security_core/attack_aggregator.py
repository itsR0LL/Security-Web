from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import RISK_ORDER
from .database import db_session, utc_now
from .repository import active_source_filter, get_rules as repository_rules, is_sample_mode, row_to_event


TIME_RANGE_HOURS = {"6h": 6, "24h": 24, "7d": 24 * 7}
DEFAULT_TIME_RANGE = "24h"
SECURITY_ACTIONS = ("block", "blocked", "challenge", "managed_challenge", "js_challenge", "log", "simulate")


@dataclass(frozen=True)
class AnalysisFilters:
    time_range: str | None = DEFAULT_TIME_RANGE
    risk: str | None = None
    country: str | None = None
    attack_category: str | None = None
    rule_id: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "timeRange": _time_range_text(self.time_range),
            "risk": _filter_text(self.risk),
            "country": _filter_text(self.country),
            "attackCategory": _filter_text(self.attack_category),
            "ruleId": _filter_text(self.rule_id),
        }


def _filter_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "all":
        return None
    return text


def _time_range_text(value: Any) -> str:
    if value is None:
        return DEFAULT_TIME_RANGE
    text = str(value).strip()
    return text or DEFAULT_TIME_RANGE


def _time_bounds(filters: AnalysisFilters) -> tuple[str | None, str | None]:
    time_range = _time_range_text(filters.time_range)
    if time_range == "all":
        return None, None
    hours = TIME_RANGE_HOURS.get(time_range)
    if hours is None:
        return None, None
    to_time = datetime.now(timezone.utc)
    from_time = to_time - timedelta(hours=hours)
    return (
        from_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
        to_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _risk_rank(level: Any) -> int:
    text = str(level or "info")
    return RISK_ORDER.index(text) if text in RISK_ORDER else RISK_ORDER.index("info")


def _risk_from_rank(rank: Any) -> str:
    try:
        index = int(rank)
    except (TypeError, ValueError):
        return "info"
    if 0 <= index < len(RISK_ORDER):
        return RISK_ORDER[index]
    return "info"


def _risk_case_sql(column: str = "risk_level") -> str:
    cases = " ".join(f"WHEN '{level}' THEN {index}" for index, level in enumerate(RISK_ORDER))
    return f"CASE {column} {cases} ELSE 0 END"


def _normalize_limit(value: Any, default: int, maximum: int) -> int:
    try:
        limit = int(value or default)
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, maximum))


def _attack_condition_sql() -> tuple[str, list[Any]]:
    placeholders = ",".join("?" for _ in SECURITY_ACTIONS)
    return (
        f"(risk_level != 'info' OR action IN ({placeholders}) OR status_code >= 400)",
        list(SECURITY_ACTIONS),
    )


def _append_time_and_country_filters(clauses: list[str], params: list[Any], filters: AnalysisFilters, *, time_column: str) -> None:
    from_time, to_time = _time_bounds(filters)
    if from_time:
        clauses.append(f"{time_column} >= ?")
        params.append(from_time)
    if to_time:
        clauses.append(f"{time_column} <= ?")
        params.append(to_time)
    country = _filter_text(filters.country)
    if country:
        clauses.append("country = ?")
        params.append(country)


def _raw_event_where_sql(filters: AnalysisFilters, *, attacks_only: bool) -> tuple[str, list[Any]]:
    source_clause, params = active_source_filter()
    clauses = [source_clause]
    _append_time_and_country_filters(clauses, params, filters, time_column="occurred_at")
    if attacks_only:
        attack_sql, attack_params = _attack_condition_sql()
        clauses.append(attack_sql)
        params.extend(attack_params)
    risk = _filter_text(filters.risk)
    if risk:
        if risk in {"high", "high+"}:
            accepted = RISK_ORDER[RISK_ORDER.index("high") :]
            clauses.append(f"risk_level IN ({','.join('?' for _ in accepted)})")
            params.extend(accepted)
        else:
            clauses.append("risk_level = ?")
            params.append(risk)
    attack_category = _filter_text(filters.attack_category)
    if attack_category:
        clauses.append("attack_category = ?")
        params.append(attack_category)
    rule_id = _filter_text(filters.rule_id)
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id)
    return f"WHERE {' AND '.join(clauses)}", params


def _access_log_where_sql(filters: AnalysisFilters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    _append_time_and_country_filters(clauses, params, filters, time_column="occurred_at")
    if not clauses:
        return "", params
    return f"WHERE {' AND '.join(clauses)}", params


def _aggregate_country_where_sql(filters: AnalysisFilters) -> tuple[str, list[Any]]:
    if is_sample_mode():
        dimensions = ["sample:country"]
    else:
        dimensions = ["worker_log:country", "cloudflare:country"]
    clauses = [f"dimension IN ({','.join('?' for _ in dimensions)})"]
    params: list[Any] = list(dimensions)
    from_time, to_time = _time_bounds(filters)
    if from_time:
        clauses.append("bucket_start >= ?")
        params.append(from_time)
    if to_time:
        clauses.append("bucket_start <= ?")
        params.append(to_time)
    country = _filter_text(filters.country)
    if country:
        clauses.append("dimension_value = ?")
        params.append(country)
    return f"WHERE {' AND '.join(clauses)}", params


def _rows_to_events(rows: list[Any]) -> list[dict[str, Any]]:
    return [row_to_event(row) for row in rows]


def _hash_id(prefix: str, values: list[Any]) -> str:
    text = json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"


def _count_values(values: list[Any], limit: int = 8) -> list[dict[str, Any]]:
    counter = Counter(str(value or "") for value in values if str(value or "").strip())
    return [{"label": label, "value": count} for label, count in counter.most_common(limit)]


def _top_tuple(items: list[tuple[Any, ...]]) -> tuple[tuple[Any, ...], int] | tuple[None, int]:
    counter = Counter(items)
    if not counter:
        return None, 0
    value, count = counter.most_common(1)[0]
    return value, count


def _max_risk(events: list[dict[str, Any]]) -> str:
    highest = "info"
    for event in events:
        risk = str(event.get("riskLevel") or "info")
        if _risk_rank(risk) > _risk_rank(highest):
            highest = risk
    return highest


def _event_evidence(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event["id"],
        "timestamp": event["timestamp"],
        "clientIp": event["clientIp"],
        "country": event["country"],
        "method": event["method"],
        "path": event["path"],
        "query": event.get("query"),
        "statusCode": event["statusCode"],
        "action": event["action"],
        "riskLevel": event["riskLevel"],
        "ruleId": event["ruleId"],
        "ruleName": event["ruleName"],
        "summary": event["summary"],
        "ruleMatches": event.get("ruleMatches", []),
    }


def _cluster_group_filters(row: Any) -> list[tuple[str, Any]]:
    return [
        ("attack_category", row["attack_category"]),
        ("attack_subtype", row["attack_subtype"]),
        ("tool_signature", row["tool_signature"]),
        ("behavior_fingerprint", row["behavior_fingerprint"]),
        ("rule_id", row["rule_id"]),
        ("rule_name", row["rule_name"]),
    ]


class AttackAggregator:
    def summary(self, filters: AnalysisFilters) -> dict[str, Any]:
        attack_count = self._count_attack_events(filters)
        blocked_count = self._count_attack_events(filters, actions=("block", "blocked"))
        challenge_count = self._count_attack_events(filters, actions=("challenge", "managed_challenge", "js_challenge"))
        clusters = self.clusters(filters, limit=5)
        rules = self.rules(filters, limit=5)
        sources = self.sources(filters, limit=8)
        risk_distribution = self._field_distribution(filters, "risk_level", label_key="riskLevel")
        category_distribution = self._field_distribution(filters, "attack_category", label_key="attackCategory")

        top_cluster = clusters["items"][0] if clusters["items"] else None
        summary_text = (
            f"Detected {attack_count} attack events in {clusters['totalClusters']} behavior groups."
            if attack_count
            else "No attack behavior groups were detected for the selected filters."
        )
        if top_cluster:
            summary_text += (
                f" The leading group is {top_cluster['attackCategory'] or 'unclassified'}"
                f" with {top_cluster['eventCount']} events."
            )

        return {
            "status": "ready",
            "message": "Analysis is generated from local aggregation. No large model was called.",
            "summary": summary_text,
            "generatedAt": utc_now(),
            "filters": filters.payload(),
            "totals": {
                "attackEvents": attack_count,
                "behaviorGroups": clusters["totalClusters"],
                "affectedSources": sources["affectedSources"],
                "affectedCountries": sources["affectedCountries"],
                "blockedEvents": blocked_count,
                "challengedEvents": challenge_count,
                "totalRequests": sources["totalRequests"],
                "normalRequests": sources["normalRequests"],
                "attackShare": sources["attackShare"],
            },
            "items": [
                {"label": "attackEvents", "value": attack_count, "detail": "raw_events rows included in attack aggregation"},
                {"label": "behaviorGroups", "value": clusters["totalClusters"], "detail": "Attack behavior groups after normal visits were excluded"},
                {"label": "affectedSources", "value": sources["affectedSources"], "detail": "Source IPs associated with attack events"},
                {"label": "totalRequests", "value": sources["totalRequests"], "detail": "Normal and attack request comparison baseline"},
            ],
            "riskDistribution": risk_distribution,
            "attackCategories": category_distribution,
            "topClusters": clusters["items"],
            "topRules": rules["items"],
            "topSources": sources["items"],
        }

    def clusters(self, filters: AnalysisFilters, *, limit: int = 50) -> dict[str, Any]:
        limit = _normalize_limit(limit, 50, 200)
        where_sql, params = _raw_event_where_sql(filters, attacks_only=True)
        risk_case = _risk_case_sql()
        with db_session() as connection:
            count_rows = connection.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM (
                    SELECT 1
                    FROM raw_events
                    {where_sql}
                    GROUP BY attack_category, attack_subtype, tool_signature,
                        behavior_fingerprint, rule_id, rule_name
                )
                """,
                params,
            ).fetchone()
            rows = connection.execute(
                f"""
                SELECT
                    attack_category,
                    attack_subtype,
                    tool_signature,
                    behavior_fingerprint,
                    rule_id,
                    rule_name,
                    COUNT(*) AS event_count,
                    MIN(occurred_at) AS first_seen,
                    MAX(occurred_at) AS last_seen,
                    AVG(confidence) AS avg_confidence,
                    MAX({risk_case}) AS max_risk_rank
                FROM raw_events
                {where_sql}
                GROUP BY attack_category, attack_subtype, tool_signature,
                    behavior_fingerprint, rule_id, rule_name
                ORDER BY max_risk_rank DESC, event_count DESC, last_seen DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()

        return {
            "generatedAt": utc_now(),
            "filters": filters.payload(),
            "totalClusters": int(count_rows["count"] if count_rows else 0),
            "items": [self._cluster_payload(filters, row) for row in rows],
        }

    def rules(self, filters: AnalysisFilters, *, limit: int = 50) -> dict[str, Any]:
        limit = _normalize_limit(limit, 50, 200)
        events = self._attack_events(filters)
        rule_defs = {rule["id"]: rule for rule in repository_rules()}
        stats: dict[str, dict[str, Any]] = {}
        for event in events:
            hits = event.get("ruleHits") if isinstance(event.get("ruleHits"), list) else []
            normalized_hits = [hit for hit in hits if isinstance(hit, dict)]
            if not normalized_hits and event.get("ruleId"):
                normalized_hits = [
                    {
                        "ruleId": event.get("ruleId"),
                        "ruleName": event.get("ruleName"),
                        "severity": event.get("riskLevel"),
                        "mode": "active",
                        "version": event.get("ruleVersion"),
                        "attackCategory": event.get("attackCategory"),
                        "attackSubtype": event.get("attackSubtype"),
                    }
                ]
            if not normalized_hits:
                normalized_hits = [
                    {
                        "ruleId": "unmapped-rule",
                        "ruleName": "Unmapped rule",
                        "severity": event.get("riskLevel"),
                        "mode": "observe",
                        "version": event.get("ruleVersion"),
                        "attackCategory": event.get("attackCategory"),
                        "attackSubtype": event.get("attackSubtype"),
                    }
                ]

            for hit in normalized_hits:
                rule_id = str(hit.get("ruleId") or hit.get("id") or "unmapped-rule")
                item = stats.setdefault(
                    rule_id,
                    {
                        "ruleId": rule_id,
                        "ruleName": str(hit.get("ruleName") or hit.get("name") or rule_defs.get(rule_id, {}).get("name") or rule_id),
                        "eventCount": 0,
                        "riskLevel": "info",
                        "severity": str(hit.get("severity") or rule_defs.get(rule_id, {}).get("severity") or "info"),
                        "mode": str(hit.get("mode") or rule_defs.get(rule_id, {}).get("mode") or "observe"),
                        "version": str(hit.get("version") or rule_defs.get(rule_id, {}).get("version") or ""),
                        "attackCategory": str(hit.get("attackCategory") or event.get("attackCategory") or ""),
                        "attackSubtype": str(hit.get("attackSubtype") or event.get("attackSubtype") or ""),
                        "firstSeen": event["timestamp"],
                        "lastSeen": event["timestamp"],
                        "sourceCount": set(),
                        "pathCount": set(),
                        "matchedFields": Counter(),
                        "matchedValues": Counter(),
                        "evidence": [],
                        "definition": rule_defs.get(rule_id, {}).get("definition"),
                    },
                )
                item["eventCount"] += 1
                item["riskLevel"] = max([item["riskLevel"], event["riskLevel"]], key=_risk_rank)
                item["firstSeen"] = min(item["firstSeen"], event["timestamp"])
                item["lastSeen"] = max(item["lastSeen"], event["timestamp"])
                if event.get("clientIp"):
                    item["sourceCount"].add(event["clientIp"])
                if event.get("path"):
                    item["pathCount"].add(event["path"])
                matched_field = str(hit.get("matchedField") or "")
                matched_value = str(hit.get("matchedValue") or "")
                if matched_field:
                    item["matchedFields"][matched_field] += 1
                if matched_value:
                    item["matchedValues"][matched_value] += 1
                if len(item["evidence"]) < 5:
                    item["evidence"].append(_event_evidence(event))

        items = []
        for item in stats.values():
            items.append(
                {
                    "ruleId": item["ruleId"],
                    "ruleName": item["ruleName"],
                    "eventCount": item["eventCount"],
                    "riskLevel": item["riskLevel"],
                    "severity": item["severity"],
                    "mode": item["mode"],
                    "version": item["version"],
                    "attackCategory": item["attackCategory"],
                    "attackSubtype": item["attackSubtype"],
                    "firstSeen": item["firstSeen"],
                    "lastSeen": item["lastSeen"],
                    "sourceCount": len(item["sourceCount"]),
                    "pathCount": len(item["pathCount"]),
                    "matchedFields": [{"label": label, "value": count} for label, count in item["matchedFields"].most_common(8)],
                    "matchedValues": [{"label": label, "value": count} for label, count in item["matchedValues"].most_common(8)],
                    "definition": item["definition"],
                    "evidence": item["evidence"],
                }
            )
        items.sort(key=lambda item: (_risk_rank(item["riskLevel"]), item["eventCount"], item["lastSeen"]), reverse=True)
        return {
            "generatedAt": utc_now(),
            "filters": filters.payload(),
            "totalRules": len(items),
            "items": items[:limit],
        }

    def sources(self, filters: AnalysisFilters, *, limit: int = 50) -> dict[str, Any]:
        limit = _normalize_limit(limit, 50, 200)
        attack_events = self._attack_events(filters)
        request_by_ip = self._access_requests_by_ip(filters)
        country_requests = self._access_requests_by_country(filters)
        if not request_by_ip:
            request_by_ip = self._raw_requests_by_ip(filters)
        if not country_requests:
            country_requests = self._aggregate_requests_by_country(filters)
        if not country_requests:
            country_requests = self._raw_requests_by_country(filters)

        attack_by_ip: dict[str, dict[str, Any]] = {}
        country_attacks: dict[str, dict[str, Any]] = {}
        for event in attack_events:
            client_ip = event.get("clientIp") or ""
            if client_ip:
                item = attack_by_ip.setdefault(
                    client_ip,
                    {
                        "clientIp": client_ip,
                        "country": event.get("country") or "",
                        "region": event.get("region") or "",
                        "city": event.get("city") or "",
                        "latitude": event.get("latitude") or 0,
                        "longitude": event.get("longitude") or 0,
                        "locationPrecision": event.get("locationPrecision") or "estimated",
                        "attackCount": 0,
                        "riskLevel": "info",
                        "latestSeen": event["timestamp"],
                        "attackCategories": Counter(),
                        "ruleIds": Counter(),
                        "paths": Counter(),
                    },
                )
                item["attackCount"] += 1
                item["riskLevel"] = max([item["riskLevel"], event["riskLevel"]], key=_risk_rank)
                item["latestSeen"] = max(item["latestSeen"], event["timestamp"])
                if event.get("attackCategory"):
                    item["attackCategories"][event["attackCategory"]] += 1
                if event.get("ruleId"):
                    item["ruleIds"][event["ruleId"]] += 1
                if event.get("path"):
                    item["paths"][event["path"]] += 1

            country = event.get("country") or "unknown"
            country_item = country_attacks.setdefault(country, {"country": country, "attackCount": 0, "riskLevel": "info"})
            country_item["attackCount"] += 1
            country_item["riskLevel"] = max([country_item["riskLevel"], event["riskLevel"]], key=_risk_rank)

        items_by_ip: dict[str, dict[str, Any]] = {}
        for client_ip, request_item in request_by_ip.items():
            items_by_ip[client_ip] = dict(request_item)
        for client_ip, attack_item in attack_by_ip.items():
            item = items_by_ip.setdefault(
                client_ip,
                {
                    "clientIp": client_ip,
                    "country": attack_item["country"],
                    "region": attack_item["region"],
                    "city": attack_item["city"],
                    "latitude": attack_item["latitude"],
                    "longitude": attack_item["longitude"],
                    "locationPrecision": attack_item["locationPrecision"],
                    "requestCount": 0,
                    "latestSeen": attack_item["latestSeen"],
                },
            )
            item["attackCount"] = attack_item["attackCount"]
            item["riskLevel"] = attack_item["riskLevel"]
            item["latestSeen"] = max(str(item.get("latestSeen") or ""), attack_item["latestSeen"])
            item["topAttackCategory"] = _counter_label(attack_item["attackCategories"])
            item["topRuleId"] = _counter_label(attack_item["ruleIds"])
            item["topPath"] = _counter_label(attack_item["paths"])

        items = []
        for item in items_by_ip.values():
            request_count = int(item.get("requestCount") or 0)
            attack_count = int(item.get("attackCount") or 0)
            items.append(
                {
                    "clientIp": item.get("clientIp") or "",
                    "country": item.get("country") or "",
                    "region": item.get("region") or "",
                    "city": item.get("city") or "",
                    "latitude": item.get("latitude") or 0,
                    "longitude": item.get("longitude") or 0,
                    "locationPrecision": item.get("locationPrecision") or "estimated",
                    "requestCount": request_count,
                    "attackCount": attack_count,
                    "normalCount": max(0, request_count - attack_count),
                    "attackShare": round(attack_count / request_count, 4) if request_count else 0,
                    "riskLevel": item.get("riskLevel") or "info",
                    "latestSeen": item.get("latestSeen"),
                    "topAttackCategory": item.get("topAttackCategory") or "",
                    "topRuleId": item.get("topRuleId") or "",
                    "topPath": item.get("topPath") or "",
                }
            )
        items.sort(key=lambda item: (item["attackCount"], item["requestCount"], item.get("latestSeen") or ""), reverse=True)

        countries = []
        for country, request_count in country_requests.items():
            attack_item = country_attacks.get(country, {"attackCount": 0, "riskLevel": "info"})
            attack_count = int(attack_item["attackCount"])
            countries.append(
                {
                    "country": country,
                    "requestCount": int(request_count),
                    "attackCount": attack_count,
                    "normalCount": max(0, int(request_count) - attack_count),
                    "attackShare": round(attack_count / int(request_count), 4) if int(request_count) else 0,
                    "riskLevel": attack_item["riskLevel"],
                }
            )
        for country, attack_item in country_attacks.items():
            if country not in country_requests:
                attack_count = int(attack_item["attackCount"])
                countries.append(
                    {
                        "country": country,
                        "requestCount": attack_count,
                        "attackCount": attack_count,
                        "normalCount": 0,
                        "attackShare": 1,
                        "riskLevel": attack_item["riskLevel"],
                    }
                )
        countries.sort(key=lambda item: (item["attackCount"], item["requestCount"]), reverse=True)

        total_requests = sum(item["requestCount"] for item in countries) if countries else sum(item["requestCount"] for item in items)
        total_attacks = len(attack_events)
        return {
            "generatedAt": utc_now(),
            "filters": filters.payload(),
            "totalRequests": total_requests,
            "totalAttackEvents": total_attacks,
            "normalRequests": max(0, total_requests - total_attacks),
            "attackShare": round(total_attacks / total_requests, 4) if total_requests else 0,
            "affectedSources": len({event.get("clientIp") for event in attack_events if event.get("clientIp")}),
            "affectedCountries": len({event.get("country") for event in attack_events if event.get("country")}),
            "items": items[:limit],
            "countries": countries[:limit],
        }

    def advice(self, filters: AnalysisFilters, *, limit: int = 10) -> dict[str, Any]:
        limit = _normalize_limit(limit, 10, 50)
        clusters = self.clusters(filters, limit=limit)
        drafts = [self._advice_from_cluster(cluster) for cluster in clusters["items"][:limit]]
        return {
            "status": "draft",
            "message": "Rule advice is generated from aggregate data only. No large model was called.",
            "generatedAt": utc_now(),
            "filters": filters.payload(),
            "totalDrafts": len(drafts),
            "items": drafts,
        }

    def _count_attack_events(self, filters: AnalysisFilters, *, actions: tuple[str, ...] | None = None) -> int:
        where_sql, params = _raw_event_where_sql(filters, attacks_only=True)
        if actions:
            where_sql += f" AND action IN ({','.join('?' for _ in actions)})"
            params = [*params, *actions]
        with db_session() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS count FROM raw_events {where_sql}", params).fetchone()
        return int(row["count"] if row else 0)

    def _attack_events(self, filters: AnalysisFilters) -> list[dict[str, Any]]:
        where_sql, params = _raw_event_where_sql(filters, attacks_only=True)
        with db_session() as connection:
            rows = connection.execute(
                f"SELECT * FROM raw_events {where_sql} ORDER BY occurred_at DESC",
                params,
            ).fetchall()
        return _rows_to_events(rows)

    def _field_distribution(self, filters: AnalysisFilters, field: str, *, label_key: str) -> list[dict[str, Any]]:
        allowed_fields = {"risk_level", "attack_category", "rule_id", "country", "action"}
        if field not in allowed_fields:
            raise ValueError(f"Unsupported analysis distribution field: {field}")
        where_sql, params = _raw_event_where_sql(filters, attacks_only=True)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT {field} AS label, COUNT(*) AS value, MAX({_risk_case_sql()}) AS max_risk_rank
                FROM raw_events
                {where_sql}
                GROUP BY {field}
                ORDER BY value DESC
                LIMIT 12
                """,
                params,
            ).fetchall()
        items = []
        for row in rows:
            label = str(row["label"] or "unclassified")
            item: dict[str, Any] = {"label": label, "value": int(row["value"]), "riskLevel": _risk_from_rank(row["max_risk_rank"])}
            if label_key:
                item[label_key] = label
            items.append(item)
        return items

    def _cluster_payload(self, filters: AnalysisFilters, row: Any) -> dict[str, Any]:
        group_where_sql, group_params = _raw_event_where_sql(filters, attacks_only=True)
        group_clauses = []
        for column, value in _cluster_group_filters(row):
            group_clauses.append(f"{column} = ?")
            group_params.append(value)
        group_where_sql = f"{group_where_sql} AND {' AND '.join(group_clauses)}"
        with db_session() as connection:
            group_rows = connection.execute(
                f"SELECT * FROM raw_events {group_where_sql} ORDER BY occurred_at DESC",
                group_params,
            ).fetchall()
        events = _rows_to_events(group_rows)
        source_tuple, source_count = _top_tuple(
            [
                (
                    event.get("clientIp") or "",
                    event.get("country") or "",
                    event.get("region") or "",
                    event.get("city") or "",
                    event.get("asn") or "",
                    event.get("latitude") or 0,
                    event.get("longitude") or 0,
                    event.get("locationPrecision") or "estimated",
                )
                for event in events
                if event.get("clientIp")
            ]
        )
        path_tuple, path_count = _top_tuple(
            [
                (event.get("method") or "", event.get("path") or "", event.get("statusCode") or 0)
                for event in events
                if event.get("path")
            ]
        )
        action_tuple, action_count = _top_tuple([(event.get("action") or "",) for event in events if event.get("action")])
        user_agent_tuple, user_agent_count = _top_tuple([(event.get("userAgent") or "",) for event in events if event.get("userAgent")])

        cluster_id = _hash_id(
            "cluster",
            [
                row["attack_category"],
                row["attack_subtype"],
                row["tool_signature"],
                row["behavior_fingerprint"],
                row["rule_id"],
                row["rule_name"],
            ],
        )
        primary_source = None
        if source_tuple:
            primary_source = {
                "clientIp": source_tuple[0],
                "country": source_tuple[1],
                "region": source_tuple[2],
                "city": source_tuple[3],
                "asn": source_tuple[4],
                "latitude": source_tuple[5],
                "longitude": source_tuple[6],
                "locationPrecision": source_tuple[7],
                "count": source_count,
            }
        primary_path = None
        if path_tuple:
            primary_path = {
                "method": path_tuple[0],
                "path": path_tuple[1],
                "statusCode": path_tuple[2],
                "count": path_count,
            }
        return {
            "clusterId": cluster_id,
            "attackCategory": row["attack_category"] or "unclassified",
            "attackSubtype": row["attack_subtype"] or "",
            "ruleId": row["rule_id"] or "",
            "ruleName": row["rule_name"] or "",
            "toolSignature": row["tool_signature"] or "",
            "behaviorFingerprint": row["behavior_fingerprint"] or "",
            "eventCount": int(row["event_count"]),
            "riskLevel": _risk_from_rank(row["max_risk_rank"]),
            "confidence": round(float(row["avg_confidence"] or 0), 3),
            "timeRange": {"firstSeen": row["first_seen"], "lastSeen": row["last_seen"]},
            "primarySource": primary_source,
            "primaryPath": primary_path,
            "primaryAction": {"action": action_tuple[0], "count": action_count} if action_tuple else None,
            "primaryUserAgent": {"userAgent": user_agent_tuple[0], "count": user_agent_count} if user_agent_tuple else None,
            "countries": _count_values([event.get("country") for event in events]),
            "paths": _count_values([event.get("path") for event in events]),
            "methods": _count_values([event.get("method") for event in events]),
            "statusCodes": _count_values([event.get("statusCode") for event in events]),
            "actions": _count_values([event.get("action") for event in events]),
            "userAgents": _count_values([event.get("userAgent") for event in events], limit=5),
            "evidence": [_event_evidence(event) for event in events[:5]],
        }

    def _access_requests_by_ip(self, filters: AnalysisFilters) -> dict[str, dict[str, Any]]:
        where_sql, params = _access_log_where_sql(filters)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT
                    client_ip,
                    country,
                    region,
                    city,
                    latitude,
                    longitude,
                    location_precision,
                    COUNT(*) AS request_count,
                    MAX(occurred_at) AS latest_seen
                FROM access_logs
                {where_sql}
                GROUP BY client_ip, country, region, city, latitude, longitude, location_precision
                ORDER BY request_count DESC
                """,
                params,
            ).fetchall()
        return {
            str(row["client_ip"]): {
                "clientIp": row["client_ip"],
                "country": row["country"],
                "region": row["region"],
                "city": row["city"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "locationPrecision": row["location_precision"],
                "requestCount": int(row["request_count"]),
                "latestSeen": row["latest_seen"],
            }
            for row in rows
            if row["client_ip"]
        }

    def _raw_requests_by_ip(self, filters: AnalysisFilters) -> dict[str, dict[str, Any]]:
        where_sql, params = _raw_event_where_sql(filters, attacks_only=False)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT
                    client_ip,
                    country,
                    region,
                    city,
                    latitude,
                    longitude,
                    location_precision,
                    COUNT(*) AS request_count,
                    MAX(occurred_at) AS latest_seen
                FROM raw_events
                {where_sql}
                GROUP BY client_ip, country, region, city, latitude, longitude, location_precision
                ORDER BY request_count DESC
                """,
                params,
            ).fetchall()
        return {
            str(row["client_ip"]): {
                "clientIp": row["client_ip"],
                "country": row["country"],
                "region": row["region"],
                "city": row["city"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "locationPrecision": row["location_precision"],
                "requestCount": int(row["request_count"]),
                "latestSeen": row["latest_seen"],
            }
            for row in rows
            if row["client_ip"]
        }

    def _access_requests_by_country(self, filters: AnalysisFilters) -> dict[str, int]:
        where_sql, params = _access_log_where_sql(filters)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT country, COUNT(*) AS request_count
                FROM access_logs
                {where_sql}
                GROUP BY country
                ORDER BY request_count DESC
                """,
                params,
            ).fetchall()
        return {str(row["country"] or "unknown"): int(row["request_count"]) for row in rows}

    def _raw_requests_by_country(self, filters: AnalysisFilters) -> dict[str, int]:
        where_sql, params = _raw_event_where_sql(filters, attacks_only=False)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT country, COUNT(*) AS request_count
                FROM raw_events
                {where_sql}
                GROUP BY country
                ORDER BY request_count DESC
                """,
                params,
            ).fetchall()
        return {str(row["country"] or "unknown"): int(row["request_count"]) for row in rows}

    def _aggregate_requests_by_country(self, filters: AnalysisFilters) -> dict[str, int]:
        where_sql, params = _aggregate_country_where_sql(filters)
        with db_session() as connection:
            rows = connection.execute(
                f"""
                SELECT dimension_value AS country, SUM(total_count) AS request_count
                FROM event_aggregates
                {where_sql}
                GROUP BY dimension_value
                ORDER BY request_count DESC
                """,
                params,
            ).fetchall()
        return {str(row["country"] or "unknown"): int(row["request_count"] or 0) for row in rows}

    def _advice_from_cluster(self, cluster: dict[str, Any]) -> dict[str, Any]:
        primary_path = cluster.get("primaryPath") or {}
        primary_action = cluster.get("primaryAction") or {}
        primary_user_agent = cluster.get("primaryUserAgent") or {}
        rule_type = "path_keyword"
        condition: dict[str, Any] = {"keywords": []}
        if primary_path.get("path"):
            condition = {"keywords": [primary_path["path"]]}
        elif primary_user_agent.get("userAgent"):
            rule_type = "user_agent_keyword"
            condition = {"keywords": [primary_user_agent["userAgent"]]}
        elif primary_action.get("action"):
            rule_type = "cloudflare_action"
            condition = {"actions": [primary_action["action"]]}

        draft_id = f"draft-{cluster['clusterId']}"
        return {
            "id": draft_id,
            "status": "draft",
            "sourceClusterId": cluster["clusterId"],
            "title": f"Review rule for {cluster['attackCategory']}",
            "riskLevel": cluster["riskLevel"],
            "confidence": cluster["confidence"],
            "rationale": (
                f"{cluster['eventCount']} events share rule, action, source, path, or tool evidence."
            ),
            "impact": {
                "eventCount": cluster["eventCount"],
                "sourceCount": len(cluster["countries"]),
                "pathCount": len(cluster["paths"]),
                "timeRange": cluster["timeRange"],
            },
            "ruleDraft": {
                "id": draft_id,
                "version": "draft",
                "name": f"Review {cluster['attackCategory']}",
                "enabled": False,
                "mode": "shadow",
                "ruleType": rule_type,
                "condition": condition,
                "severity": cluster["riskLevel"],
                "classification": {
                    "attackCategory": cluster["attackCategory"],
                    "attackSubtype": cluster["attackSubtype"],
                    "toolSignature": cluster["toolSignature"],
                    "behaviorFingerprint": cluster["behaviorFingerprint"],
                },
                "actions": {
                    "alert": True,
                    "block": False,
                },
                "lifecycle": {
                    "createdBy": "attack_aggregator",
                    "reviewStatus": "manual_review_required",
                },
            },
            "evidence": cluster["evidence"],
            "manualReviewQuestions": [
                "Confirm whether the primary path is expected production traffic.",
                "Confirm whether the source countries and user agents match known legitimate clients.",
                "Confirm the rule mode before enabling enforcement.",
            ],
        }


def _counter_label(counter: Counter[str]) -> str:
    if not counter:
        return ""
    return counter.most_common(1)[0][0]
