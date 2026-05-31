from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .pathquery import query


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
