from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def export_action_plan_tickets(
    plan: dict[str, Any],
    output_dir: str | Path,
    *,
    include_waived: bool = False,
) -> dict[str, Any]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    items = [
        item
        for item in plan.get("items", [])
        if isinstance(item, dict) and _include_ticket(item, include_waived=include_waived)
    ]
    tickets = []
    for index, item in enumerate(items, start=1):
        filename = _ticket_filename(index, item)
        path = target / filename
        path.write_text(render_ticket_markdown(plan, item), encoding="utf-8", newline="\n")
        tickets.append(
            {
                "path": filename,
                "id": str(item.get("id") or ""),
                "priority": str(item.get("priority") or ""),
                "status": str(item.get("status") or ""),
                "severity": str(item.get("severity") or ""),
                "waived": bool(item.get("waived")),
            }
        )
    (target / "index.md").write_text(
        render_ticket_index(plan, tickets, include_waived=include_waived),
        encoding="utf-8",
        newline="\n",
    )
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "output_dir": str(target),
            "include_waived": include_waived,
        },
        "summary": {
            "ticket_count": len(tickets),
            "source_items_total": plan.get("summary", {}).get("items_total", 0),
        },
        "tickets": tickets,
    }


def render_ticket_index(
    plan: dict[str, Any],
    tickets: list[dict[str, Any]],
    *,
    include_waived: bool = False,
) -> str:
    summary = plan.get("summary", {})
    lines = [
        "# OpenOps Ticket Export",
        "",
        f"- Source generated: {format_markdown_code(plan.get('generated_at', 'unknown'))}",
        f"- Action required: **{escape_markdown_text(summary.get('action_required_count', 0))}**",
        f"- Waived source items: **{escape_markdown_text(summary.get('waived_count', 0))}**",
        f"- Exported tickets: **{escape_markdown_text(len(tickets))}**",
        f"- Include waived: {format_markdown_code(str(include_waived).lower())}",
        "",
    ]
    if not tickets:
        lines.extend(["No ticket files were generated.", ""])
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(
        [
            "| Ticket | Priority | Status | Severity | Check |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for ticket in tickets:
        path = str(ticket["path"])
        lines.append(
            "| "
            f"[{escape_markdown_text(path)}]({path}) | "
            f"{escape_markdown_text(ticket['priority'])} | "
            f"{escape_markdown_text(ticket['status'])} | "
            f"{escape_markdown_text(ticket['severity'])} | "
            f"{format_markdown_code(ticket['id'])} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_ticket_markdown(plan: dict[str, Any], item: dict[str, Any]) -> str:
    title = f"{item.get('priority', 'P2')} {item.get('id', 'check')}: {item.get('title', 'Review finding')}"
    lines = [
        f"# {escape_markdown_text(title)}",
        "",
        f"- Status: {format_markdown_code(item.get('status', 'unknown'))}",
        f"- Severity: {format_markdown_code(item.get('severity', 'unknown'))}",
        f"- Waived: {format_markdown_code(str(bool(item.get('waived'))).lower())}",
        f"- Check ID: {format_markdown_code(item.get('id', 'unknown'))}",
        f"- Evidence path: {format_markdown_code(item.get('path', ''))}",
        f"- Operator: {format_markdown_code(item.get('operator', ''))}",
        f"- Observed count: {format_markdown_code(item.get('observed_count', 0))}",
        "",
    ]
    waiver = item.get("waiver") if isinstance(item.get("waiver"), dict) else {}
    if waiver:
        lines.extend(
            [
                "## Waiver",
                "",
                f"- Status: {format_markdown_code(waiver.get('status', 'unknown'))}",
                f"- Owner: {escape_markdown_text(waiver.get('owner', ''))}",
                f"- Expires: {format_markdown_code(waiver.get('expires_at', ''))}",
                f"- Reason: {escape_markdown_text(waiver.get('reason', ''))}",
                "",
            ]
        )
    lines.extend(
        [
            "## Recommended Action",
            "",
            escape_markdown_text(item.get("recommended_action", "Review this finding.")),
            "",
            "## Acceptance Criteria",
            "",
            "- Updated evidence and report artifacts have been generated.",
            "- The related check no longer reports an unwaived `fail` or `warn` status.",
            "- Any remaining accepted risk has an owner, reason, and expiry date.",
            "",
            "## Source",
            "",
            f"- Action plan generated: {format_markdown_code(plan.get('generated_at', 'unknown'))}",
            f"- Source report generated: {format_markdown_code(plan.get('metadata', {}).get('source_report_generated_at', 'unknown'))}",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _include_ticket(item: dict[str, Any], *, include_waived: bool) -> bool:
    if item.get("status") == "pass":
        return False
    if item.get("waived") and not include_waived:
        return False
    return True


def _ticket_filename(index: int, item: dict[str, Any]) -> str:
    priority = _slug(str(item.get("priority") or "p2"))
    check_id = _slug(str(item.get("id") or "check"))
    return f"{index:03d}-{priority}-{check_id}.md"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-._")
    return slug or "item"
