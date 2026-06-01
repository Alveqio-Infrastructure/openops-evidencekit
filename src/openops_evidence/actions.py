from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SEVERITY_PRIORITY = {
    "critical": ("P0", 0),
    "high": ("P1", 1),
    "medium": ("P2", 2),
    "low": ("P3", 3),
}
STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}


def create_action_plan(
    report: dict[str, Any],
    *,
    fail_only: bool = False,
    include_pass: bool = False,
) -> dict[str, Any]:
    items = [
        _action_item(item)
        for item in report.get("results", [])
        if isinstance(item, dict) and _include_result(item, fail_only=fail_only, include_pass=include_pass)
    ]
    items.sort(key=_action_sort_key)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source_report_generated_at": report.get("generated_at"),
            "source_status": report.get("summary", {}).get("status"),
            "source_score": report.get("summary", {}).get("score"),
            "item_count": len(items),
            "fail_only": fail_only,
            "include_pass": include_pass,
        },
        "summary": {
            "status": "pass" if not items else "action_required",
            "items_total": len(items),
            "fail_count": sum(1 for item in items if item["status"] == "fail"),
            "warn_count": sum(1 for item in items if item["status"] == "warn"),
            "pass_count": sum(1 for item in items if item["status"] == "pass"),
            "critical_count": sum(1 for item in items if item["severity"] == "critical"),
            "high_count": sum(1 for item in items if item["severity"] == "high"),
            "medium_count": sum(1 for item in items if item["severity"] == "medium"),
            "low_count": sum(1 for item in items if item["severity"] == "low"),
        },
        "items": items,
    }


def render_action_plan_markdown(plan: dict[str, Any]) -> str:
    summary = plan.get("summary", {})
    metadata = plan.get("metadata", {})
    lines = [
        "# OpenOps Action Plan",
        "",
        f"- Generated: {format_markdown_code(plan.get('generated_at', 'unknown'))}",
        f"- Source status: {format_markdown_code(metadata.get('source_status', 'unknown'))}",
        f"- Source score: {format_markdown_code(_display(metadata.get('source_score')))}",
        f"- Open items: **{escape_markdown_text(summary.get('items_total', 0))}**",
        "",
    ]
    items = plan.get("items", [])
    if not items:
        lines.extend(["No action items.", ""])
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(
        [
            "| Priority | Status | Severity | Check | Action |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for item in items:
        lines.append(
            "| "
            f"{escape_markdown_text(item['priority'])} | "
            f"{escape_markdown_text(item['status'])} | "
            f"{escape_markdown_text(item['severity'])} | "
            f"{format_markdown_code(item['id'])} {escape_markdown_text(item['title'])} | "
            f"{escape_markdown_text(item['recommended_action'])} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_action_plan_csv(plan: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "priority",
            "id",
            "title",
            "status",
            "severity",
            "required",
            "path",
            "operator",
            "observed_count",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in plan.get("items", []):
        writer.writerow({key: item.get(key) for key in writer.fieldnames})
    return output.getvalue()


def _include_result(item: dict[str, Any], *, fail_only: bool, include_pass: bool) -> bool:
    status = item.get("status")
    if include_pass:
        return status in {"fail", "warn", "pass"}
    if fail_only:
        return status == "fail"
    return status in {"fail", "warn"}


def _action_item(item: dict[str, Any]) -> dict[str, Any]:
    severity = str(item.get("severity") or "medium")
    priority = SEVERITY_PRIORITY.get(severity, ("P2", 2))[0]
    return {
        "priority": priority,
        "id": str(item.get("id") or ""),
        "title": str(item.get("title") or item.get("id") or ""),
        "status": str(item.get("status") or ""),
        "severity": severity,
        "required": bool(item.get("required")),
        "path": str(item.get("path") or ""),
        "operator": str(item.get("operator") or ""),
        "observed_count": _integer_or_zero(item.get("observed_count")),
        "recommended_action": str(item.get("remediation") or "Review this finding and record the remediation."),
    }


def _action_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    priority_rank = SEVERITY_PRIORITY.get(item["severity"], ("P2", 2))[1]
    status_rank = STATUS_RANK.get(item["status"], 3)
    return priority_rank, status_rank, item["id"]


def _integer_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _display(value: Any) -> Any:
    return "n/a" if value is None else value
