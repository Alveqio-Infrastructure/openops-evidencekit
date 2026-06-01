from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def evaluate_report_gate(
    report: dict[str, Any],
    *,
    min_score: int | None = None,
    max_failed: int | None = None,
    max_warnings: int | None = None,
    max_critical: int | None = None,
    max_high: int | None = None,
    ignore_report_status: bool = False,
) -> dict[str, Any]:
    summary = report.get("summary", {})
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    thresholds = {
        "min_score": min_score,
        "max_failed": max_failed,
        "max_warnings": max_warnings,
        "max_critical": max_critical,
        "max_high": max_high,
        "ignore_report_status": ignore_report_status,
    }
    conditions = []
    if not ignore_report_status:
        conditions.append(
            _condition(
                "report_status",
                "Source report status is pass",
                observed=str(summary.get("status", "unknown")),
                operator="equals",
                expected="pass",
                passed=summary.get("status") == "pass",
            )
        )
    if min_score is not None:
        score = _integer_or_zero(summary.get("score"))
        conditions.append(
            _condition(
                "min_score",
                f"Readiness score is at least {min_score}",
                observed=score,
                operator="at_least",
                expected=min_score,
                passed=score >= min_score,
            )
        )
    if max_failed is not None:
        failed = _integer_or_zero(summary.get("checks_failed"))
        conditions.append(
            _condition(
                "max_failed",
                f"Required failures are at most {max_failed}",
                observed=failed,
                operator="at_most",
                expected=max_failed,
                passed=failed <= max_failed,
            )
        )
    if max_warnings is not None:
        warnings = _integer_or_zero(summary.get("checks_warn"))
        conditions.append(
            _condition(
                "max_warnings",
                f"Warnings are at most {max_warnings}",
                observed=warnings,
                operator="at_most",
                expected=max_warnings,
                passed=warnings <= max_warnings,
            )
        )
    if max_critical is not None:
        critical = _count_findings(results, severity="critical")
        conditions.append(
            _condition(
                "max_critical",
                f"Critical findings are at most {max_critical}",
                observed=critical,
                operator="at_most",
                expected=max_critical,
                passed=critical <= max_critical,
            )
        )
    if max_high is not None:
        high = _count_findings(results, severity="high")
        conditions.append(
            _condition(
                "max_high",
                f"High findings are at most {max_high}",
                observed=high,
                operator="at_most",
                expected=max_high,
                passed=high <= max_high,
            )
        )
    failed_conditions = [condition for condition in conditions if condition["status"] == "fail"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source_report_generated_at": report.get("generated_at"),
            "source_status": summary.get("status"),
            "source_score": summary.get("score"),
            "thresholds": thresholds,
        },
        "summary": {
            "status": "pass" if not failed_conditions else "fail",
            "conditions_total": len(conditions),
            "conditions_failed": len(failed_conditions),
            "source_score": _integer_or_zero(summary.get("score")),
            "source_failed": _integer_or_zero(summary.get("checks_failed")),
            "source_warnings": _integer_or_zero(summary.get("checks_warn")),
        },
        "conditions": conditions,
    }


def render_gate_markdown(gate: dict[str, Any]) -> str:
    summary = gate.get("summary", {})
    metadata = gate.get("metadata", {})
    lines = [
        "# OpenOps Gate Result",
        "",
        f"- Generated: {format_markdown_code(gate.get('generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Source status: {format_markdown_code(metadata.get('source_status', 'unknown'))}",
        f"- Source score: {format_markdown_code(metadata.get('source_score', 'n/a'))}",
        f"- Failed conditions: **{escape_markdown_text(summary.get('conditions_failed', 0))}**",
        "",
        "| Status | Condition | Observed | Expected |",
        "| --- | --- | --- | --- |",
    ]
    for condition in gate.get("conditions", []):
        lines.append(
            "| "
            f"{escape_markdown_text(condition.get('status', ''))} | "
            f"{escape_markdown_text(condition.get('title', ''))} | "
            f"{format_markdown_code(condition.get('observed', ''))} | "
            f"{escape_markdown_text(condition.get('operator', ''))} {format_markdown_code(condition.get('expected', ''))} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _condition(
    condition_id: str,
    title: str,
    *,
    observed: Any,
    operator: str,
    expected: Any,
    passed: bool,
) -> dict[str, Any]:
    return {
        "id": condition_id,
        "title": title,
        "status": "pass" if passed else "fail",
        "observed": observed,
        "operator": operator,
        "expected": expected,
    }


def _count_findings(results: list[dict[str, Any]], *, severity: str) -> int:
    return sum(1 for item in results if item.get("status") in {"fail", "warn"} and item.get("severity") == severity)


def _integer_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0
