from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .pathquery import query
from .policy import Check
from .reports import escape_markdown_text, format_markdown_code


def create_completeness_report(evidence: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    items = [_item(evidence, check) for check in checks]
    failed = [item for item in items if item["status"] == "fail"]
    warnings = [item for item in items if item["status"] == "warn"]
    passed = [item for item in items if item["status"] == "pass"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "policy_check_count": len(checks),
        },
        "summary": {
            "status": "warn" if failed or warnings else "pass",
            "checks_total": len(items),
            "checks_present": len([item for item in items if item["evidence_status"] == "present"]),
            "checks_expected_absent": len([item for item in items if item["evidence_status"] == "expected_absent"]),
            "checks_missing": len([item for item in items if item["evidence_status"] == "missing"]),
            "required_missing": len(failed),
            "optional_missing": len(warnings),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "items": items,
    }


def render_completeness_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Evidence Completeness Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Checks: **{escape_markdown_text(summary.get('checks_total', 0))}**",
        f"- Present: **{escape_markdown_text(summary.get('checks_present', 0))}**",
        f"- Missing required: **{escape_markdown_text(summary.get('required_missing', 0))}**",
        f"- Missing optional: **{escape_markdown_text(summary.get('optional_missing', 0))}**",
        "",
        "## Items",
        "",
        "| Check | Status | Evidence | Required | Severity | Path | Observed | Request |",
        "| --- | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for item in report.get("items", []):
        lines.append(
            "| "
            f"{format_markdown_code(item.get('id') or '')} {escape_markdown_text(item.get('title') or '')} | "
            f"{escape_markdown_text(item.get('status') or '-')} | "
            f"{escape_markdown_text(item.get('evidence_status') or '-')} | "
            f"{format_markdown_code(str(bool(item.get('required'))).lower())} | "
            f"{escape_markdown_text(item.get('severity') or '-')} | "
            f"{format_markdown_code(item.get('path') or '-')} | "
            f"{escape_markdown_text(item.get('observed_count', 0))} | "
            f"{escape_markdown_text(item.get('request') or '-')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_completeness_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "title",
            "status",
            "evidence_status",
            "required",
            "severity",
            "path",
            "operator",
            "observed_count",
            "request",
            "remediation",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in report.get("items", []):
        writer.writerow({key: item.get(key, "") for key in writer.fieldnames})
    return output.getvalue()


def _item(evidence: dict[str, Any], check: Check) -> dict[str, Any]:
    values = _query_values(evidence, check.path)
    observed = [value for value in values if _has_value(value)]
    observed_count = len(observed)
    if check.operator == "missing" and observed_count == 0:
        status = "pass"
        evidence_status = "expected_absent"
        request = "No evidence is needed because this check expects the path to be absent."
    elif observed_count > 0:
        status = "pass"
        evidence_status = "present"
        request = "Evidence is present for this policy path."
    else:
        status = "fail" if check.required else "warn"
        evidence_status = "missing"
        request = f"Provide evidence for `{check.path}`."
    return {
        "id": check.id,
        "title": check.title,
        "status": status,
        "evidence_status": evidence_status,
        "required": check.required,
        "severity": check.severity,
        "path": check.path,
        "operator": check.operator,
        "observed_count": observed_count,
        "request": request,
        "remediation": check.remediation,
    }


def _query_values(evidence: dict[str, Any], path: str) -> list[Any]:
    try:
        return query(evidence, path)
    except ValueError:
        return []


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, (list, dict)):
        return bool(value)
    return True
