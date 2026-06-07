from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_review_checklist(review_summary: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = review_summary.get("metrics", {})
    decision = review_summary.get("decision", {})
    filenames = {str(artifact.get("filename") or "") for artifact in artifacts}
    items = [
        _item(
            "read_review_summary",
            "Read the review summary",
            "review-summary.md",
            "pass",
            "Start with the generated one-page decision summary.",
            required=True,
        ),
        _item(
            "verify_manifest",
            "Verify the generated manifest before sharing",
            "manifest.json",
            "pass",
            "Run bundle verification against the generated manifest before archiving or publishing.",
            required=True,
        ),
        _item(
            "review_gate",
            "Review the gate decision",
            "gate-result.md",
            "fail" if metrics.get("gate_status") == "fail" else "pass",
            "Gate failed." if metrics.get("gate_status") == "fail" else "Gate passed.",
            required=True,
        ),
        _item(
            "review_privacy_scan",
            "Review privacy scan before external sharing",
            "privacy-scan.md",
            "fail" if _int(metrics.get("privacy_findings")) > 0 else "pass",
            f"{_int(metrics.get('privacy_findings'))} privacy finding(s) need review."
            if _int(metrics.get("privacy_findings")) > 0
            else "No privacy findings were recorded.",
            required=True,
        ),
    ]
    _append_if_present(
        items,
        filenames,
        metrics,
        "quality-report.md",
        "review_quality",
        "Review evidence quality",
        "quality_failures",
        "quality_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "completeness-report.md",
        "review_completeness",
        "Review evidence completeness",
        "completeness_missing",
        "completeness_optional_missing",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "risk-register.md",
        "review_risk_register",
        "Review open and accepted risks",
        "open_risks",
        "accepted_risks",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "action-plan.md",
        "assign_action_plan",
        "Assign remediation actions",
        "checks_failed",
        "checks_warn",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "freshness-report.md",
        "review_freshness",
        "Review evidence freshness",
        "stale_timestamps",
        "invalid_timestamps",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "restore-report.md",
        "review_restore",
        "Review backup and restore assurance",
        "restore_failures",
        "restore_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "mail-report.md",
        "review_mail",
        "Review mail domain evidence",
        "mail_failures",
        "mail_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "tls-report.md",
        "review_tls",
        "Review TLS certificate evidence",
        "tls_failures",
        "tls_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "access-report.md",
        "review_access",
        "Review administrative access exposure",
        "access_failures",
        "access_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "monitoring-report.md",
        "review_monitoring",
        "Review monitoring and alert evidence",
        "monitoring_failures",
        "monitoring_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "runtime-report.md",
        "review_runtime",
        "Review runtime evidence",
        "runtime_failures",
        "runtime_warnings",
    )
    _append_if_present(
        items,
        filenames,
        metrics,
        "incident-report.md",
        "review_incident",
        "Review incident response readiness",
        "incident_failures",
        "incident_warnings",
    )
    _append_if_present(items, filenames, metrics, "scope-report.md", "review_scope", "Review scope boundaries", "scope_warnings")
    _append_if_present(items, filenames, metrics, "evidence-drift.md", "review_drift", "Review evidence drift", "drift_changes")
    _append_if_present(items, filenames, metrics, "service-catalog.md", "review_catalog", "Review service catalog gaps", "catalog_warnings")
    _append_if_present(
        items,
        filenames,
        metrics,
        "service-level-report.md",
        "review_service_levels",
        "Review service-level evidence",
        "service_level_failures",
        "service_level_warnings",
    )
    _append_if_present(items, filenames, metrics, "runbook-report.md", "review_runbooks", "Review runbook coverage", "runbook_warnings")
    required = [item for item in items if item["required"]]
    failed = [item for item in items if item["status"] == "fail"]
    warnings = [item for item in items if item["status"] == "warn"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_review_summary_generated_at": review_summary.get("generated_at"),
            "decision_status": decision.get("status", "unknown"),
            "recommendation": decision.get("recommendation", "unknown"),
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "items_total": len(items),
            "required_items": len(required),
            "pass_count": len([item for item in items if item["status"] == "pass"]),
            "warn_count": len(warnings),
            "fail_count": len(failed),
        },
        "items": items,
    }


def render_review_checklist_markdown(checklist: dict[str, Any]) -> str:
    summary = checklist.get("summary", {})
    metadata = checklist.get("metadata", {})
    lines = [
        "# OpenOps Review Checklist",
        "",
        f"- Generated: {format_markdown_code(checklist.get('generated_at', 'unknown'))}",
        f"- Decision: **{escape_markdown_text(str(metadata.get('decision_status', 'unknown')).upper())}**",
        f"- Recommendation: {format_markdown_code(metadata.get('recommendation', 'unknown'))}",
        f"- Checklist status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        "",
        "## Items",
        "",
        "| Done | Item | Status | Required | Artifact | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in checklist.get("items", []):
        lines.append(
            "| [ ] | "
            f"{escape_markdown_text(item.get('title') or '-')} | "
            f"{escape_markdown_text(item.get('status') or '-')} | "
            f"{escape_markdown_text('yes' if item.get('required') else 'no')} | "
            f"{format_markdown_code(item.get('artifact') or '-')} | "
            f"{escape_markdown_text(item.get('reason') or '-')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_review_checklist_csv(checklist: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "title", "status", "required", "artifact", "reason"],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in checklist.get("items", []):
        writer.writerow(
            {
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "status": item.get("status", ""),
                "required": item.get("required", False),
                "artifact": item.get("artifact", ""),
                "reason": item.get("reason", ""),
            }
        )
    return output.getvalue()


def _append_if_present(
    items: list[dict[str, Any]],
    filenames: set[str],
    metrics: dict[str, Any],
    artifact: str,
    item_id: str,
    title: str,
    *metric_names: str,
) -> None:
    if artifact not in filenames:
        return
    total = sum(_int(metrics.get(name)) for name in metric_names)
    fail_metric = any(_is_failure_metric(name) and _int(metrics.get(name)) > 0 for name in metric_names)
    status = "fail" if fail_metric else "warn" if total > 0 else "pass"
    reason = (
        f"{total} related warning or failure metric(s) need review."
        if total > 0
        else "No related warning or failure metrics were recorded."
    )
    items.append(_item(item_id, title, artifact, status, reason, required=total > 0))


def _item(
    item_id: str,
    title: str,
    artifact: str,
    status: str,
    reason: str,
    *,
    required: bool,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "title": title,
        "status": status,
        "required": required,
        "artifact": artifact,
        "reason": reason,
    }


def _int(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _is_failure_metric(name: str) -> bool:
    return name.endswith("_failures") or name in {
        "checks_failed",
        "open_risks",
        "invalid_timestamps",
        "quality_failures",
        "completeness_missing",
    }
