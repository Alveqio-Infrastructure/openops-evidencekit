from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_review_summary(
    *,
    report: dict[str, Any],
    gate: dict[str, Any],
    privacy_scan: dict[str, Any],
    freshness_report: dict[str, Any] | None = None,
    risk_register: dict[str, Any] | None = None,
    scope_report: dict[str, Any] | None = None,
    evidence_drift: dict[str, Any] | None = None,
    service_catalog: dict[str, Any] | None = None,
    runbook_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report_summary = report.get("summary", {})
    gate_summary = gate.get("summary", {})
    privacy_summary = privacy_scan.get("summary", {})
    freshness_summary = (freshness_report or {}).get("summary", {})
    risk_summary = (risk_register or {}).get("summary", {})
    scope_summary = (scope_report or {}).get("summary", {})
    drift_summary = (evidence_drift or {}).get("summary", {})
    catalog_summary = (service_catalog or {}).get("summary", {})
    runbook_summary = (runbook_report or {}).get("summary", {})
    metrics = {
        "readiness_score": _int_or_none(report_summary.get("score")),
        "report_status": str(report_summary.get("status") or "unknown"),
        "gate_status": str(gate_summary.get("status") or "unknown"),
        "checks_failed": _int_or_zero(report_summary.get("checks_failed")),
        "checks_warn": _int_or_zero(report_summary.get("checks_warn")),
        "open_risks": _int_or_zero(risk_summary.get("open_count")),
        "accepted_risks": _int_or_zero(risk_summary.get("accepted_count")),
        "expired_acceptances": _int_or_zero(risk_summary.get("expired_acceptance_count")),
        "stale_timestamps": _int_or_zero(freshness_summary.get("stale_count")),
        "invalid_timestamps": _int_or_zero(freshness_summary.get("invalid_count")),
        "privacy_findings": _int_or_zero(privacy_summary.get("findings_count")),
        "scope_warnings": 1 if scope_summary.get("status") == "warn" else 0,
        "drift_changes": _int_or_zero(drift_summary.get("asset_changes_count"))
        + _int_or_zero(drift_summary.get("domain_changes_count")),
        "catalog_warnings": _int_or_zero(catalog_summary.get("services_warn")),
        "runbook_warnings": _int_or_zero(runbook_summary.get("missing_runbooks_count"))
        + _int_or_zero(runbook_summary.get("stale_runbooks_count"))
        + _int_or_zero(runbook_summary.get("unreferenced_runbooks_count"))
        + _int_or_zero(runbook_summary.get("invalid_timestamp_count")),
    }
    decision = _decision(metrics)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source_report_generated_at": report.get("generated_at"),
            "created_by": "openops-evidencekit",
        },
        "decision": decision,
        "metrics": metrics,
        "highlights": _highlights(metrics),
        "next_steps": _next_steps(decision, metrics),
    }


def render_review_summary_markdown(summary: dict[str, Any]) -> str:
    decision = summary.get("decision", {})
    metrics = summary.get("metrics", {})
    lines = [
        "# OpenOps Review Summary",
        "",
        f"- Generated: {format_markdown_code(summary.get('generated_at', 'unknown'))}",
        f"- Decision: **{escape_markdown_text(str(decision.get('status', 'unknown')).upper())}**",
        f"- Recommendation: {format_markdown_code(decision.get('recommendation', 'unknown'))}",
        f"- Reason: {escape_markdown_text(decision.get('reason', 'No reason recorded.'))}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key in (
        "readiness_score",
        "checks_failed",
        "checks_warn",
        "open_risks",
        "accepted_risks",
        "stale_timestamps",
        "invalid_timestamps",
        "privacy_findings",
        "drift_changes",
        "catalog_warnings",
        "runbook_warnings",
    ):
        lines.append(f"| {escape_markdown_text(key.replace('_', ' ').title())} | {escape_markdown_text(_display(metrics.get(key)))} |")
    lines.extend(["", "## Highlights", ""])
    highlights = summary.get("highlights", [])
    if highlights:
        lines.extend(f"- {escape_markdown_text(item)}" for item in highlights)
    else:
        lines.append("- No notable review highlights.")
    lines.extend(["", "## Next Steps", ""])
    for item in summary.get("next_steps", []):
        lines.append(f"- {escape_markdown_text(item)}")
    return "\n".join(lines).rstrip() + "\n"


def _decision(metrics: dict[str, Any]) -> dict[str, str]:
    blockers = []
    if metrics["gate_status"] == "fail":
        blockers.append("gate failed")
    if metrics["report_status"] == "fail":
        blockers.append("report failed")
    if metrics["open_risks"] > 0:
        blockers.append("open risks remain")
    if metrics["privacy_findings"] > 0:
        blockers.append("privacy findings exist")
    if blockers:
        return {
            "status": "fail",
            "recommendation": "blocked",
            "reason": "; ".join(blockers) + ".",
        }
    warnings = []
    if metrics["accepted_risks"] > 0:
        warnings.append("accepted risks need review")
    if metrics["stale_timestamps"] > 0 or metrics["invalid_timestamps"] > 0:
        warnings.append("evidence freshness needs review")
    if metrics["scope_warnings"] > 0:
        warnings.append("scope warnings exist")
    if metrics["drift_changes"] > 0:
        warnings.append("evidence drift exists")
    if metrics["catalog_warnings"] > 0 or metrics["runbook_warnings"] > 0:
        warnings.append("service or runbook warnings exist")
    if warnings:
        return {
            "status": "warn",
            "recommendation": "review_required",
            "reason": "; ".join(warnings) + ".",
        }
    return {
        "status": "pass",
        "recommendation": "ready_for_handoff",
        "reason": "No blocking review conditions were found.",
    }


def _highlights(metrics: dict[str, Any]) -> list[str]:
    highlights = [
        f"Readiness score is {_display(metrics.get('readiness_score'))}.",
        f"Gate status is {metrics.get('gate_status')}.",
    ]
    if metrics["open_risks"]:
        highlights.append(f"{metrics['open_risks']} open risk(s) require treatment.")
    if metrics["accepted_risks"]:
        highlights.append(f"{metrics['accepted_risks']} risk(s) are accepted and need expiry tracking.")
    if metrics["privacy_findings"]:
        highlights.append(f"{metrics['privacy_findings']} privacy finding(s) must be reviewed before sharing.")
    if metrics["drift_changes"]:
        highlights.append(f"{metrics['drift_changes']} evidence drift change(s) were detected.")
    return highlights


def _next_steps(decision: dict[str, str], metrics: dict[str, Any]) -> list[str]:
    if decision.get("status") == "pass":
        return [
            "Share the review pack with the intended reviewers.",
            "Record reviewer sign-off with `attest review` when the pack is accepted.",
        ]
    steps = []
    if metrics["open_risks"] > 0:
        steps.append("Review `risk-register.md` and assign treatment owners for open risks.")
    if metrics["privacy_findings"] > 0:
        steps.append("Review `privacy-scan.md` before sending the pack outside the operating team.")
    if metrics["stale_timestamps"] > 0 or metrics["invalid_timestamps"] > 0:
        steps.append("Refresh stale or invalid evidence timestamps before relying on the handoff.")
    if metrics["catalog_warnings"] > 0 or metrics["runbook_warnings"] > 0:
        steps.append("Review service catalog and runbook warnings with service owners.")
    if not steps:
        steps.append("Review warning artifacts and record the treatment decision.")
    return steps


def _int_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _display(value: Any) -> Any:
    return "n/a" if value is None else value
