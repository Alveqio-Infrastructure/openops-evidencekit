from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code
from .waivers import waiver_index


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
    waiver_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    waivers = waiver_index(waiver_document or {})
    items = [
        _action_item(item, waivers.get(str(item.get("id") or "")))
        for item in report.get("results", [])
        if isinstance(item, dict) and _include_result(item, fail_only=fail_only, include_pass=include_pass)
    ]
    items.sort(key=_action_sort_key)
    actionable = [item for item in items if not item["waived"] and item["status"] != "pass"]
    waived = [item for item in items if item["waived"]]
    expired = [item for item in items if item.get("waiver", {}).get("status") == "expired"]
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
            "waiver_count": len(waivers),
        },
        "summary": {
            "status": "pass" if not actionable else "action_required",
            "items_total": len(items),
            "action_required_count": len(actionable),
            "waived_count": len(waived),
            "expired_waiver_count": len(expired),
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
        f"- Plan items: **{escape_markdown_text(summary.get('items_total', 0))}**",
        f"- Action required: **{escape_markdown_text(summary.get('action_required_count', 0))}**",
        f"- Waived: **{escape_markdown_text(summary.get('waived_count', 0))}**",
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
        action = item["recommended_action"]
        if item["waived"]:
            waiver = item.get("waiver", {})
            action = (
                f"Waived until {waiver.get('expires_at')} by {waiver.get('owner')}: "
                f"{waiver.get('reason')}"
            )
        elif item.get("waiver", {}).get("status") == "expired":
            waiver = item["waiver"]
            action = (
                f"Waiver expired at {waiver.get('expires_at')}; "
                f"{item['recommended_action']}"
            )
        lines.append(
            "| "
            f"{escape_markdown_text(item['priority'])} | "
            f"{escape_markdown_text(item['status'])} | "
            f"{escape_markdown_text(item['severity'])} | "
            f"{format_markdown_code(item['id'])} {escape_markdown_text(item['title'])} | "
            f"{escape_markdown_text(action)} |"
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
            "waived",
            "waiver_owner",
            "waiver_expires_at",
            "waiver_reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in plan.get("items", []):
        waiver = item.get("waiver") or {}
        row = {key: item.get(key) for key in writer.fieldnames}
        row["waiver_owner"] = waiver.get("owner")
        row["waiver_expires_at"] = waiver.get("expires_at")
        row["waiver_reason"] = waiver.get("reason")
        writer.writerow(row)
    return output.getvalue()


def _include_result(item: dict[str, Any], *, fail_only: bool, include_pass: bool) -> bool:
    status = item.get("status")
    if include_pass:
        return status in {"fail", "warn", "pass"}
    if fail_only:
        return status == "fail"
    return status in {"fail", "warn"}


def _action_item(item: dict[str, Any], waiver: dict[str, Any] | None = None) -> dict[str, Any]:
    severity = str(item.get("severity") or "medium")
    priority = SEVERITY_PRIORITY.get(severity, ("P2", 2))[0]
    waiver_record = waiver or {}
    waived = waiver_record.get("status") == "active"
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
        "waived": waived,
        "waiver": waiver_record,
        "recommended_action": str(item.get("remediation") or "Review this finding and record the remediation."),
    }


def _action_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    priority_rank = SEVERITY_PRIORITY.get(item["severity"], ("P2", 2))[1]
    status_rank = STATUS_RANK.get(item["status"], 3)
    waived_rank = 1 if item["waived"] else 0
    return waived_rank, priority_rank, status_rank, item["id"]


def _integer_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _display(value: Any) -> Any:
    return "n/a" if value is None else value
