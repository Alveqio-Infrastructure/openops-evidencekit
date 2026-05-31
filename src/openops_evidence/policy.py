from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .pathquery import query


SUPPORTED_OPERATORS = {
    "after_now",
    "at_least",
    "at_most",
    "contains",
    "equals",
    "exists",
    "matches",
    "missing",
    "not_equals",
    "one_of",
    "within_days",
}
SUPPORTED_SEVERITIES = {"critical", "high", "medium", "low"}
SUPPORTED_MODES = {"any", "all", "none"}
OPERATORS_REQUIRING_VALUE = {
    "at_least",
    "at_most",
    "contains",
    "equals",
    "matches",
    "not_equals",
    "one_of",
    "within_days",
}
NUMERIC_VALUE_OPERATORS = {"at_least", "at_most", "within_days"}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    path: str
    operator: str
    value: Any = None
    severity: str = "medium"
    mode: str = "any"
    required: bool = True
    remediation: str = ""


def parse_policy(raw: dict[str, Any]) -> list[Check]:
    checks = raw.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("Policy must contain a list named 'checks'")
    parsed: list[Check] = []
    for item in checks:
        if not isinstance(item, dict):
            raise ValueError("Each check must be a table/object")
        parsed.append(
            Check(
                id=str(item["id"]),
                title=str(item.get("title") or item["id"]),
                path=str(item["path"]),
                operator=str(item["operator"]),
                value=item.get("value"),
                severity=str(item.get("severity", "medium")),
                mode=str(item.get("mode", "any")),
                required=bool(item.get("required", True)),
                remediation=str(item.get("remediation", "")),
            )
        )
    return parsed


def validate_policy_document(raw: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        return ["Policy must be a table/object."]
    metadata = raw.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be a table/object when present.")
    checks = raw.get("checks")
    if not isinstance(checks, list):
        return [*errors, "Policy must contain a list named 'checks'."]
    if not checks:
        errors.append("checks must contain at least one check.")
    seen_ids: set[str] = set()
    for index, item in enumerate(checks):
        prefix = f"checks[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a table/object.")
            continue
        check_id = _required_string(item, "id", errors, prefix)
        if check_id:
            if check_id in seen_ids:
                errors.append(f"{prefix}.id duplicates another check id: {check_id}")
            seen_ids.add(check_id)
        _optional_string(item, "title", errors, prefix)
        _required_string(item, "path", errors, prefix)
        operator = _required_string(item, "operator", errors, prefix)
        if operator and operator not in SUPPORTED_OPERATORS:
            errors.append(f"{prefix}.operator is unsupported: {operator}")
        severity = str(item.get("severity", "medium"))
        if severity not in SUPPORTED_SEVERITIES:
            errors.append(f"{prefix}.severity is unsupported: {severity}")
        mode = str(item.get("mode", "any"))
        if mode not in SUPPORTED_MODES:
            errors.append(f"{prefix}.mode is unsupported: {mode}")
        if "required" in item and not isinstance(item["required"], bool):
            errors.append(f"{prefix}.required must be a boolean when present.")
        _validate_operator_value(item, operator, errors, prefix)
    return errors


def evaluate_policy(evidence: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    results = [evaluate_check(evidence, check) for check in checks]
    failed_required = [r for r in results if r["status"] == "fail" and r["required"]]
    warnings = [r for r in results if r["status"] == "warn"]
    passed = [r for r in results if r["status"] == "pass"]
    total_weight = sum(_severity_weight(r["severity"]) for r in results) or 1
    lost_weight = sum(_severity_weight(r["severity"]) for r in failed_required)
    score = max(0, round(100 * (1 - lost_weight / total_weight)))
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "score": score,
            "status": "fail" if failed_required else "pass",
            "checks_total": len(results),
            "checks_passed": len(passed),
            "checks_failed": len(failed_required),
            "checks_warn": len(warnings),
        },
        "results": results,
    }


def evaluate_check(evidence: dict[str, Any], check: Check) -> dict[str, Any]:
    values = query(evidence, check.path)
    try:
        passed = _evaluate_values(values, check)
        error = None
    except Exception as exc:  # noqa: BLE001 - user-authored policies should not crash the CLI.
        passed = False
        error = str(exc)
    status = "pass" if passed else ("fail" if check.required else "warn")
    return {
        "id": check.id,
        "title": check.title,
        "status": status,
        "severity": check.severity,
        "required": check.required,
        "path": check.path,
        "operator": check.operator,
        "expected": check.value,
        "observed": values[:20],
        "observed_count": len(values),
        "mode": check.mode,
        "remediation": check.remediation,
        "error": error,
    }


def _evaluate_values(values: list[Any], check: Check) -> bool:
    if check.operator == "missing":
        return not values
    if not values:
        return False
    evaluated = [_evaluate_one(value, check.operator, check.value) for value in values]
    if check.mode == "all":
        return all(evaluated)
    if check.mode == "none":
        return not any(evaluated)
    return any(evaluated)


def _evaluate_one(value: Any, operator: str, expected: Any) -> bool:
    if operator == "exists":
        return value is not None and value != ""
    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected
    if operator == "contains":
        return expected in value if isinstance(value, (list, str, dict)) else False
    if operator == "one_of":
        return value in expected
    if operator == "at_least":
        return float(value) >= float(expected)
    if operator == "at_most":
        return float(value) <= float(expected)
    if operator == "matches":
        return re.search(str(expected), str(value)) is not None
    if operator == "within_days":
        age_days = _age_days(value)
        return age_days is not None and age_days <= float(expected)
    if operator == "after_now":
        parsed = _parse_datetime(value)
        return parsed is not None and parsed > datetime.now(UTC)
    raise ValueError(f"Unsupported operator: {operator}")


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_days(value: Any) -> float | None:
    parsed = _parse_datetime(value)
    if parsed is None:
        return None
    return (datetime.now(UTC) - parsed).total_seconds() / 86400


def _severity_weight(severity: str) -> int:
    return {"critical": 5, "high": 3, "medium": 2, "low": 1}.get(severity, 2)


def _required_string(item: dict[str, Any], key: str, errors: list[str], prefix: str) -> str | None:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{prefix}.{key} must be a non-empty string.")
        return None
    return value


def _optional_string(item: dict[str, Any], key: str, errors: list[str], prefix: str) -> None:
    if key in item and (not isinstance(item[key], str) or not item[key]):
        errors.append(f"{prefix}.{key} must be a non-empty string when present.")


def _validate_operator_value(
    item: dict[str, Any],
    operator: str | None,
    errors: list[str],
    prefix: str,
) -> None:
    if not operator:
        return
    if operator in OPERATORS_REQUIRING_VALUE and "value" not in item:
        errors.append(f"{prefix}.value is required for operator {operator}.")
        return
    if operator == "one_of" and not isinstance(item.get("value"), list):
        errors.append(f"{prefix}.value must be a list for operator one_of.")
        return
    if operator == "one_of" and not item.get("value"):
        errors.append(f"{prefix}.value must not be empty for operator one_of.")
        return
    if operator in NUMERIC_VALUE_OPERATORS and "value" in item:
        try:
            float(item["value"])
        except (TypeError, ValueError):
            errors.append(f"{prefix}.value must be numeric for operator {operator}.")
