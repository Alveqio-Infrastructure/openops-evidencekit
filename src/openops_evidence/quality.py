from __future__ import annotations

import csv
from collections import Counter
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_evidence_quality_report(evidence: dict[str, Any]) -> dict[str, Any]:
    assets = evidence.get("assets") if isinstance(evidence.get("assets"), list) else []
    signals = evidence.get("signals") if isinstance(evidence.get("signals"), dict) else {}
    checks = [
        _metadata_check(evidence, "organization"),
        _metadata_check(evidence, "environment"),
        _signals_present_check(signals),
        _asset_ids_unique_check(assets),
        _asset_identity_check(assets),
        _asset_classification_check(assets),
        _backup_signal_check(assets, signals),
        _monitoring_signal_check(signals),
        _docs_signal_check(signals),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
            "assets_total": len(assets),
            "signals_total": len(signals),
        },
        "checks": checks,
    }


def render_quality_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Evidence Quality Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Checks: **{escape_markdown_text(summary.get('checks_total', 0))}**",
        f"- Failed: **{escape_markdown_text(summary.get('checks_failed', 0))}**",
        f"- Warnings: **{escape_markdown_text(summary.get('checks_warn', 0))}**",
        f"- Assets: **{escape_markdown_text(summary.get('assets_total', 0))}**",
        f"- Signal domains: **{escape_markdown_text(summary.get('signals_total', 0))}**",
        "",
        "## Checks",
        "",
        "| Check | Status | Severity | Path | Reason | Recommended action |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for check in report.get("checks", []):
        lines.append(
            "| "
            f"{escape_markdown_text(check.get('title') or '-')} | "
            f"{escape_markdown_text(check.get('status') or '-')} | "
            f"{escape_markdown_text(check.get('severity') or '-')} | "
            f"{format_markdown_code(check.get('path') or '-')} | "
            f"{escape_markdown_text(check.get('reason') or '-')} | "
            f"{escape_markdown_text(check.get('recommended_action') or '-')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_quality_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "title", "status", "severity", "path", "reason", "recommended_action"],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in report.get("checks", []):
        writer.writerow(
            {
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    return output.getvalue()


def _metadata_check(evidence: dict[str, Any], key: str) -> dict[str, Any]:
    value = evidence.get("metadata", {}).get(key)
    label = key.replace("_", " ")
    return _check(
        f"metadata_{key}_present",
        f"Metadata {label} is recorded",
        "pass" if isinstance(value, str) and value else "warn",
        "medium",
        f"metadata.{key}",
        f"Metadata {label} is recorded." if isinstance(value, str) and value else f"Metadata {label} is missing.",
        f"Record metadata.{key} so reviewers know which environment this evidence belongs to.",
    )


def _signals_present_check(signals: dict[str, Any]) -> dict[str, Any]:
    return _check(
        "signals_present",
        "Evidence contains signal domains",
        "pass" if signals else "fail",
        "critical",
        "signals",
        f"{len(signals)} signal domain(s) recorded." if signals else "No signal domains were recorded.",
        "Collect at least one operational signal domain before creating a readiness handoff.",
    )


def _asset_ids_unique_check(assets: list[Any]) -> dict[str, Any]:
    ids = [asset.get("id") for asset in assets if isinstance(asset, dict) and isinstance(asset.get("id"), str)]
    duplicates = sorted(item for item, count in Counter(ids).items() if item and count > 1)
    return _check(
        "asset_ids_unique",
        "Asset IDs are unique",
        "fail" if duplicates else "pass",
        "high",
        "assets[*].id",
        "Duplicate asset IDs: " + ", ".join(duplicates) if duplicates else "All non-empty asset IDs are unique.",
        "Give every asset a stable unique ID before using evidence in reports.",
    )


def _asset_identity_check(assets: list[Any]) -> dict[str, Any]:
    missing = [
        str(index)
        for index, asset in enumerate(assets)
        if not isinstance(asset, dict) or not isinstance(asset.get("id"), str) or not asset.get("id")
    ]
    return _check(
        "asset_identity_present",
        "Assets have stable IDs",
        "fail" if missing else "pass",
        "high",
        "assets[*].id",
        "Assets missing IDs at index: " + ", ".join(missing) if missing else "Every asset has a stable ID.",
        "Assign stable IDs to every asset so drift, catalog, and scope reports can correlate evidence.",
    )


def _asset_classification_check(assets: list[Any]) -> dict[str, Any]:
    unclassified = [
        str(asset.get("id") or index)
        for index, asset in enumerate(assets)
        if isinstance(asset, dict) and not asset.get("roles") and not asset.get("tags")
    ]
    return _check(
        "assets_classified",
        "Assets have roles or tags",
        "warn" if unclassified else "pass",
        "medium",
        "assets[*].roles",
        "Unclassified assets: " + ", ".join(unclassified) if unclassified else "Every asset has roles or tags.",
        "Add roles or tags so inventory and review reports can be filtered by operational responsibility.",
    )


def _backup_signal_check(assets: list[Any], signals: dict[str, Any]) -> dict[str, Any]:
    backup_assets = [
        asset
        for asset in assets
        if isinstance(asset, dict)
        and ("backup" in _string_list(asset.get("roles")) or str(asset.get("type") or "").startswith("backup"))
    ]
    backup = signals.get("backup") if isinstance(signals.get("backup"), dict) else {}
    missing = [key for key in ("last_success_at", "restore_test_at") if not backup.get(key)]
    status = "warn" if backup_assets and missing else "pass"
    return _check(
        "backup_assets_have_backup_signal",
        "Backup assets have backup recency and restore evidence",
        status,
        "high",
        "signals.backup",
        "Missing backup fields: " + ", ".join(missing)
        if status == "warn"
        else "Backup signal contains the expected recency and restore evidence or no backup assets were declared.",
        "Record backup.last_success_at and backup.restore_test_at when backup assets are in evidence.",
    )


def _monitoring_signal_check(signals: dict[str, Any]) -> dict[str, Any]:
    monitoring = signals.get("monitoring") if isinstance(signals.get("monitoring"), dict) else {}
    status = "warn" if monitoring and not monitoring.get("alert_channels") else "pass"
    return _check(
        "monitoring_alert_channels_present",
        "Monitoring signal includes alert routing",
        status,
        "medium",
        "signals.monitoring.alert_channels",
        "Monitoring signal has no alert_channels." if status == "warn" else "Monitoring alert routing is recorded or monitoring is not present.",
        "Record alert_channels so incident and monitoring reviews can prove alert routing.",
    )


def _docs_signal_check(signals: dict[str, Any]) -> dict[str, Any]:
    docs = signals.get("docs") if isinstance(signals.get("docs"), dict) else {}
    status = "warn" if docs and not docs.get("runbooks") else "pass"
    return _check(
        "docs_runbooks_present",
        "Documentation signal includes runbooks",
        status,
        "medium",
        "signals.docs.runbooks",
        "Documentation signal has no runbooks." if status == "warn" else "Runbook evidence is recorded or docs evidence is not present.",
        "Record docs.runbooks so runbook coverage and incident readiness can be reviewed.",
    )


def _check(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    path: str,
    reason: str,
    recommended_action: str,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
