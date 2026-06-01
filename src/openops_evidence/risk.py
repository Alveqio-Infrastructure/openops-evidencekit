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
SOURCE_STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}
RISK_STATUS_RANK = {"open": 0, "accepted": 1, "closed": 2}


def create_risk_register(
    report: dict[str, Any],
    *,
    waiver_document: dict[str, Any] | None = None,
    include_pass: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    waivers = waiver_index(waiver_document or {}, now=now)
    risks = [
        _risk_item(item, waivers.get(str(item.get("id") or "")))
        for item in report.get("results", [])
        if isinstance(item, dict) and _include_result(item, include_pass=include_pass)
    ]
    risks.sort(key=_risk_sort_key)
    open_risks = [item for item in risks if item["risk_status"] == "open"]
    accepted = [item for item in risks if item["risk_status"] == "accepted"]
    closed = [item for item in risks if item["risk_status"] == "closed"]
    expired = [item for item in risks if item["waiver_status"] == "expired"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source_report_generated_at": report.get("generated_at"),
            "source_status": report.get("summary", {}).get("status"),
            "source_score": report.get("summary", {}).get("score"),
            "include_pass": include_pass,
            "waiver_count": len(waivers),
        },
        "summary": {
            "status": "pass" if not open_risks else "action_required",
            "risks_total": len(risks),
            "open_count": len(open_risks),
            "accepted_count": len(accepted),
            "closed_count": len(closed),
            "expired_acceptance_count": len(expired),
            "fail_count": sum(1 for item in risks if item["source_status"] == "fail"),
            "warn_count": sum(1 for item in risks if item["source_status"] == "warn"),
            "pass_count": sum(1 for item in risks if item["source_status"] == "pass"),
            "critical_count": sum(1 for item in risks if item["severity"] == "critical"),
            "high_count": sum(1 for item in risks if item["severity"] == "high"),
            "medium_count": sum(1 for item in risks if item["severity"] == "medium"),
            "low_count": sum(1 for item in risks if item["severity"] == "low"),
        },
        "risks": risks,
    }


def render_risk_register_markdown(register: dict[str, Any]) -> str:
    summary = register.get("summary", {})
    metadata = register.get("metadata", {})
    lines = [
        "# OpenOps Risk Register",
        "",
        f"- Generated: {format_markdown_code(register.get('generated_at', 'unknown'))}",
        f"- Source status: {format_markdown_code(metadata.get('source_status', 'unknown'))}",
        f"- Source score: {format_markdown_code(_display(metadata.get('source_score')))}",
        f"- Register status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Risks: **{escape_markdown_text(summary.get('risks_total', 0))}**",
        f"- Open: **{escape_markdown_text(summary.get('open_count', 0))}**",
        f"- Accepted: **{escape_markdown_text(summary.get('accepted_count', 0))}**",
        f"- Expired acceptances: **{escape_markdown_text(summary.get('expired_acceptance_count', 0))}**",
        "",
    ]
    risks = register.get("risks", [])
    if not risks:
        lines.extend(["No risks were found in the selected report results.", ""])
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(
        [
            "| Priority | Risk Status | Source | Severity | Check | Owner | Expiry | Action |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for risk in risks:
        owner = risk.get("owner") or "-"
        expiry = risk.get("waiver_expires_at") or "-"
        action = _risk_action_text(risk)
        lines.append(
            "| "
            f"{escape_markdown_text(risk.get('priority', ''))} | "
            f"{escape_markdown_text(risk.get('risk_status', ''))} | "
            f"{escape_markdown_text(risk.get('source_status', ''))} | "
            f"{escape_markdown_text(risk.get('severity', ''))} | "
            f"{format_markdown_code(risk.get('id', ''))} {escape_markdown_text(risk.get('title', ''))} | "
            f"{escape_markdown_text(owner)} | "
            f"{escape_markdown_text(expiry)} | "
            f"{escape_markdown_text(action)} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_risk_register_csv(register: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "priority",
            "id",
            "title",
            "risk_status",
            "source_status",
            "severity",
            "required",
            "path",
            "operator",
            "observed_count",
            "owner",
            "waiver_status",
            "waiver_expires_at",
            "acceptance_reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for risk in register.get("risks", []):
        writer.writerow({key: risk.get(key, "") for key in writer.fieldnames})
    return output.getvalue()


def _include_result(item: dict[str, Any], *, include_pass: bool) -> bool:
    status = item.get("status")
    if include_pass:
        return status in {"fail", "warn", "pass"}
    return status in {"fail", "warn"}


def _risk_item(item: dict[str, Any], waiver: dict[str, Any] | None = None) -> dict[str, Any]:
    source_status = str(item.get("status") or "")
    severity = str(item.get("severity") or "medium")
    priority = SEVERITY_PRIORITY.get(severity, ("P2", 2))[0]
    waiver_record = waiver or {}
    waiver_status = str(waiver_record.get("status") or "none")
    if source_status == "pass":
        risk_status = "closed"
    elif waiver_status == "active":
        risk_status = "accepted"
    else:
        risk_status = "open"
    return {
        "priority": priority,
        "id": str(item.get("id") or ""),
        "title": str(item.get("title") or item.get("id") or ""),
        "risk_status": risk_status,
        "source_status": source_status,
        "severity": severity,
        "required": bool(item.get("required")),
        "path": str(item.get("path") or ""),
        "operator": str(item.get("operator") or ""),
        "observed_count": _integer_or_zero(item.get("observed_count")),
        "owner": str(waiver_record.get("owner") or ""),
        "waiver_status": waiver_status,
        "waiver_expires_at": str(waiver_record.get("expires_at") or ""),
        "acceptance_reason": str(waiver_record.get("reason") or ""),
        "recommended_action": str(item.get("remediation") or "Review this risk and record the treatment decision."),
    }


def _risk_sort_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    risk_rank = RISK_STATUS_RANK.get(item["risk_status"], 3)
    priority_rank = SEVERITY_PRIORITY.get(item["severity"], ("P2", 2))[1]
    source_rank = SOURCE_STATUS_RANK.get(item["source_status"], 3)
    return risk_rank, priority_rank, source_rank, item["id"]


def _risk_action_text(risk: dict[str, Any]) -> str:
    if risk.get("risk_status") == "accepted":
        return f"Accepted: {risk.get('acceptance_reason') or 'No reason recorded.'}"
    if risk.get("waiver_status") == "expired":
        return f"Acceptance expired; {risk.get('recommended_action')}"
    if risk.get("risk_status") == "closed":
        return "Closed by passing evidence."
    return str(risk.get("recommended_action") or "Review this risk.")


def _integer_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _display(value: Any) -> Any:
    return "n/a" if value is None else value
