from __future__ import annotations

import json
from typing import Any

from .config import RISK_ORDER


MATCH_FIELD_BY_RULE_TYPE = {
    "path_keyword": "path",
    "query_keyword": "query",
    "user_agent_keyword": "userAgent",
    "cloudflare_action": "action",
}

FIELD_OPERATORS = {
    "path": {"contains", "equals", "in"},
    "query": {"contains", "equals", "in"},
    "userAgent": {"contains", "equals", "in"},
    "action": {"equals", "in"},
    "method": {"equals", "in"},
    "statusCode": {"equals", "range"},
    "clientIp": {"equals", "in"},
    "country": {"equals", "in"},
    "region": {"equals", "in"},
    "city": {"equals", "in"},
    "asn": {"equals", "in"},
}

EVENT_FIELD_FALLBACKS = {
    "userAgent": "user_agent",
    "clientIp": "client_ip",
    "statusCode": "status_code",
}


def json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def risk_rank(level: str) -> int:
    return RISK_ORDER.index(level) if level in RISK_ORDER else RISK_ORDER.index("info")


def max_risk(first: str, second: str) -> str:
    return first if risk_rank(first) >= risk_rank(second) else second


def normalize_rule_row(row: Any) -> dict[str, Any]:
    condition = json_loads(row["condition_json"], {})
    rule_definition = json_loads(row["rule_json"], {})
    return {
        "id": row["id"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "ruleType": row["rule_type"],
        "condition": condition,
        "severity": row["severity"],
        "version": row["version"],
        "mode": row["mode"],
        "attackCategory": row["attack_category"],
        "attackSubtype": row["attack_subtype"],
        "toolSignature": row["tool_signature"],
        "behaviorFingerprint": row["behavior_fingerprint"],
        "definition": rule_definition or build_rule_definition(
            {
                "id": row["id"],
                "ruleType": row["rule_type"],
                "condition": condition,
                "severity": row["severity"],
                "version": row["version"],
                "mode": row["mode"],
                "attackCategory": row["attack_category"],
                "attackSubtype": row["attack_subtype"],
                "toolSignature": row["tool_signature"],
                "behaviorFingerprint": row["behavior_fingerprint"],
            }
        ),
    }


def build_rule_definition(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": rule["id"],
        "version": rule["version"],
        "mode": rule["mode"],
        "ruleType": rule["ruleType"],
        "condition": rule["condition"],
        "severity": rule["severity"],
        "classification": {
            "attackCategory": rule["attackCategory"],
            "attackSubtype": rule["attackSubtype"],
            "toolSignature": rule["toolSignature"],
            "behaviorFingerprint": rule["behaviorFingerprint"],
        },
    }


def field_text(event: dict[str, Any], field: str) -> str:
    value = event.get(field)
    if value is None:
        fallback_field = EVENT_FIELD_FALLBACKS.get(field)
        if fallback_field:
            value = event.get(fallback_field)
    return str(value or "")


def keyword_hit(rule: dict[str, Any], event: dict[str, Any], field: str) -> dict[str, str] | None:
    text = field_text(event, field)
    lowered_text = text.lower()
    for keyword in rule["condition"].get("keywords", []):
        keyword_text = str(keyword)
        if keyword_text.lower() in lowered_text:
            return {"matchedField": field, "matchedValue": keyword_text}
    return None


def action_hit(rule: dict[str, Any], event: dict[str, Any]) -> dict[str, str] | None:
    action = field_text(event, "action")
    normalized_action = action.lower()
    for configured_action in rule["condition"].get("actions", []):
        action_text = str(configured_action)
        if normalized_action == action_text.lower():
            return {"matchedField": "action", "matchedValue": action_text}
    return None


def rule_conditions(rule: dict[str, Any]) -> list[dict[str, Any]]:
    condition = rule.get("condition")
    if not isinstance(condition, dict):
        return []
    conditions = condition.get("conditions")
    if not isinstance(conditions, list):
        return []
    return [item for item in conditions if isinstance(item, dict)]


def condition_value_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def equals_condition(event_value: Any, expected: Any, *, numeric: bool = False) -> bool:
    if numeric:
        try:
            return int(event_value) == int(expected)
        except (TypeError, ValueError):
            return False
    return condition_value_text(event_value).lower() == condition_value_text(expected).lower()


def in_condition(event_value: Any, expected_values: Any) -> tuple[bool, str]:
    if not isinstance(expected_values, list):
        return False, ""
    event_text = condition_value_text(event_value).lower()
    for expected in expected_values:
        expected_text = condition_value_text(expected)
        if event_text == expected_text.lower():
            return True, expected_text
    return False, ""


def range_condition(event_value: Any, range_value: Any) -> bool:
    if not isinstance(range_value, dict):
        return False
    try:
        number = int(event_value)
    except (TypeError, ValueError):
        return False
    minimum = range_value.get("min")
    maximum = range_value.get("max")
    if minimum is None and maximum is None:
        return False
    try:
        if minimum is not None and number < int(minimum):
            return False
        if maximum is not None and number > int(maximum):
            return False
    except (TypeError, ValueError):
        return False
    return True


def evaluate_condition(condition: dict[str, Any], event: dict[str, Any]) -> dict[str, str] | None:
    field = str(condition.get("field") or "")
    operator = str(condition.get("operator") or "")
    if operator not in FIELD_OPERATORS.get(field, set()):
        return None

    event_value = event.get(field)
    if event_value is None:
        fallback_field = EVENT_FIELD_FALLBACKS.get(field)
        if fallback_field:
            event_value = event.get(fallback_field)

    expected = condition.get("value")
    if operator == "contains":
        expected_text = condition_value_text(expected)
        if expected_text and expected_text.lower() in condition_value_text(event_value).lower():
            return {"matchedField": field, "matchedValue": expected_text}
        return None
    if operator == "equals":
        numeric = field == "statusCode"
        if equals_condition(event_value, expected, numeric=numeric):
            return {"matchedField": field, "matchedValue": condition_value_text(expected)}
        return None
    if operator == "in":
        matched, matched_value = in_condition(event_value, expected)
        if matched:
            return {"matchedField": field, "matchedValue": matched_value}
        return None
    if operator == "range":
        if range_condition(event_value, expected):
            return {"matchedField": field, "matchedValue": json.dumps(expected, ensure_ascii=False, sort_keys=True)}
        return None
    return None


def conditions_hit(rule: dict[str, Any], event: dict[str, Any]) -> dict[str, str] | None:
    conditions = rule_conditions(rule)
    if not conditions:
        return None
    hits = []
    for condition in conditions:
        hit = evaluate_condition(condition, event)
        if not hit:
            return None
        hits.append(hit)
    return {
        "matchedField": ",".join(hit["matchedField"] for hit in hits),
        "matchedValue": json.dumps([hit["matchedValue"] for hit in hits], ensure_ascii=False),
    }


def match_rule(rule: dict[str, Any], event: dict[str, Any]) -> dict[str, Any] | None:
    if not rule["enabled"]:
        return None
    rule_type = rule["ruleType"]
    condition_hit = conditions_hit(rule, event)
    if condition_hit:
        hit = condition_hit
    elif rule_type == "cloudflare_action":
        hit = action_hit(rule, event)
    else:
        field = MATCH_FIELD_BY_RULE_TYPE.get(rule_type)
        hit = keyword_hit(rule, event, field) if field else None
    if not hit:
        return None
    return {
        "ruleId": rule["id"],
        "ruleName": rule["name"],
        "ruleType": rule_type,
        "mode": rule["mode"],
        "severity": rule["severity"],
        "version": rule["version"],
        "matchedField": hit["matchedField"],
        "matchedValue": hit["matchedValue"],
        "attackCategory": rule["attackCategory"],
        "attackSubtype": rule["attackSubtype"],
        "toolSignature": rule["toolSignature"],
        "behaviorFingerprint": rule["behaviorFingerprint"],
    }


def primary_active_hit(hits: list[dict[str, Any]]) -> dict[str, Any] | None:
    active_hits = [hit for hit in hits if hit["mode"] == "active"]
    if not active_hits:
        return None
    return max(active_hits, key=lambda hit: risk_rank(hit["severity"]))


def describe_hit(hit: dict[str, Any]) -> str:
    return f"{hit['ruleName']}:{hit['matchedField']}={hit['matchedValue']}"


def apply_rule_matching(event: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    enriched = dict(event)
    hits = [hit for rule in rules if (hit := match_rule(rule, enriched))]
    active_hit = primary_active_hit(hits)
    final_risk = str(enriched.get("riskLevel") or "info")
    for hit in hits:
        if hit["mode"] == "active":
            final_risk = max_risk(final_risk, hit["severity"])

    existing_matches = enriched.get("ruleMatches")
    if not isinstance(existing_matches, list):
        existing_matches = []
    hit_labels = [describe_hit(hit) for hit in hits]

    enriched["riskLevel"] = final_risk
    enriched["ruleHits"] = hits
    enriched["ruleMatches"] = hit_labels or existing_matches
    if hits:
        enriched["ruleVersion"] = active_hit["version"] if active_hit else hits[0]["version"]
    if active_hit:
        enriched["ruleId"] = active_hit["ruleId"]
        enriched["ruleName"] = active_hit["ruleName"]
        enriched["attackCategory"] = active_hit["attackCategory"]
        enriched["attackSubtype"] = active_hit["attackSubtype"]
        enriched["toolSignature"] = active_hit["toolSignature"]
        enriched["behaviorFingerprint"] = active_hit["behaviorFingerprint"]
        if not enriched.get("eventType"):
            enriched["eventType"] = active_hit["attackSubtype"]
        if float(enriched.get("confidence") or 0) < 0.75:
            enriched["confidence"] = 0.75
    else:
        enriched.setdefault("attackCategory", "")
        enriched.setdefault("attackSubtype", "")
        enriched.setdefault("toolSignature", "")
        enriched.setdefault("behaviorFingerprint", "")
    enriched.setdefault("campaignId", "")
    enriched.setdefault("aiClusterId", "")
    enriched.setdefault("ruleVersion", "")
    raw = enriched.get("raw")
    if isinstance(raw, dict):
        raw["matchedRules"] = enriched["ruleMatches"]
        raw["ruleHits"] = hits
        raw["ruleVersion"] = enriched["ruleVersion"]
    return enriched
