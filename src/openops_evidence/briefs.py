from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}


def create_report_brief(report: dict[str, Any], *, max_findings: int = 5) -> dict[str, Any]:
    summary = report.get("summary", {})
    findings = _top_findings(report, max_findings=max_findings)
    health = _health(summary)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_report_generated_at": report.get("generated_at"),
            "max_findings": max_findings,
        },
        "summary": {
            "status": str(summary.get("status", "fail")),
            "score": _int(summary.get("score")),
            "health": health,
            "message": _message(health, summary),
            "checks_total": _int(summary.get("checks_total")),
            "checks_passed": _int(summary.get("checks_passed")),
            "checks_failed": _int(summary.get("checks_failed")),
            "checks_warn": _int(summary.get("checks_warn")),
            "top_findings_count": len(findings),
            "critical_count": _severity_count(report, "critical"),
            "high_count": _severity_count(report, "high"),
            "medium_count": _severity_count(report, "medium"),
            "low_count": _severity_count(report, "low"),
        },
        "top_findings": findings,
        "next_steps": _next_steps(findings),
    }


def render_brief_markdown(brief: dict[str, Any]) -> str:
    summary = brief.get("summary", {})
    metadata = brief.get("metadata", {})
    lines = [
        "# OpenOps Executive Brief",
        "",
        f"- Generated: {format_markdown_code(brief.get('generated_at', 'unknown'))}",
        f"- Source report: {format_markdown_code(metadata.get('source_report_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Score: **{escape_markdown_text(summary.get('score', 0))}**",
        f"- Health: **{escape_markdown_text(str(summary.get('health', 'unknown')).replace('_', ' '))}**",
        "",
        "## Readout",
        "",
        escape_markdown_text(summary.get("message", "No summary message available.")),
        "",
        "## Top Findings",
        "",
    ]
    findings = brief.get("top_findings", [])
    if not findings:
        lines.extend(["No failed checks or warnings were reported.", ""])
    else:
        lines.extend(
            [
                "| Status | Severity | Check | Recommended action |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in findings:
            lines.append(
                "| "
                f"{escape_markdown_text(item.get('status', ''))} | "
                f"{escape_markdown_text(item.get('severity', ''))} | "
                f"{format_markdown_code(item.get('id', ''))} {escape_markdown_text(item.get('title', ''))} | "
                f"{escape_markdown_text(item.get('remediation', '') or 'Review and document the finding.')} |"
            )
        lines.append("")
    lines.extend(["## Next Steps", ""])
    for step in brief.get("next_steps", []):
        lines.append(f"- {escape_markdown_text(step)}")
    lines.extend(
        [
            "",
            "## Note",
            "",
            "This brief summarizes operational evidence. It is not a compliance certification or legal assessment.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _top_findings(report: dict[str, Any], *, max_findings: int) -> list[dict[str, Any]]:
    findings = [
        item
        for item in report.get("results", [])
        if isinstance(item, dict) and item.get("status") in {"fail", "warn"}
    ]
    findings.sort(key=_finding_sort_key)
    return [_brief_finding(item) for item in findings[:max(0, max_findings)]]


def _brief_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id", "")),
        "title": str(item.get("title") or item.get("id") or ""),
        "status": str(item.get("status", "")),
        "severity": str(item.get("severity", "")),
        "required": bool(item.get("required")),
        "path": str(item.get("path", "")),
        "remediation": str(item.get("remediation") or "Review and document the finding."),
    }


def _finding_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    status_rank = STATUS_RANK.get(str(item.get("status", "")), 9)
    severity_rank = SEVERITY_RANK.get(str(item.get("severity", "")), 9)
    return status_rank, severity_rank, str(item.get("id", ""))


def _health(summary: dict[str, Any]) -> str:
    status = summary.get("status")
    failed = _int(summary.get("checks_failed"))
    warnings = _int(summary.get("checks_warn"))
    score = _int(summary.get("score"))
    if status == "fail" or failed > 0:
        return "action_required"
    if warnings > 0 or score < 90:
        return "watch"
    return "on_track"


def _message(health: str, summary: dict[str, Any]) -> str:
    score = _int(summary.get("score"))
    failed = _int(summary.get("checks_failed"))
    warnings = _int(summary.get("checks_warn"))
    if health == "action_required":
        return (
            f"Readiness needs attention: score {score}, "
            f"{failed} failed checks, and {warnings} warnings."
        )
    if health == "watch":
        return (
            f"Readiness is mostly stable with score {score}, "
            f"{failed} failed checks, and {warnings} warnings."
        )
    return f"Readiness is on track with score {score} and no failed checks or warnings."


def _next_steps(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return [
            "Keep the recurring evidence review cadence.",
            "Keep backup restore evidence, monitoring coverage, and runbooks current.",
            "Publish the signed evidence bundle with the next review or release.",
        ]
    steps = []
    seen: set[str] = set()
    for finding in findings:
        action = finding.get("remediation") or "Review and document the finding."
        if action not in seen:
            steps.append(str(action))
            seen.add(str(action))
    return steps[:5]


def _severity_count(report: dict[str, Any], severity: str) -> int:
    return sum(
        1
        for item in report.get("results", [])
        if isinstance(item, dict) and item.get("status") in {"fail", "warn"} and item.get("severity") == severity
    )


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
