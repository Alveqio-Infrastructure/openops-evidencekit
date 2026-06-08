from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_patch_report(evidence: dict[str, Any]) -> dict[str, Any]:
    patch = _patch_signal(evidence)
    packages = [_package_record(item) for item in _list_of_dicts(patch.get("packages"))]
    security_packages = [item for item in packages if item["security"]]
    reboot_required = patch.get("reboot_required") if isinstance(patch.get("reboot_required"), bool) else None
    checks = [
        _patch_signal_check(patch),
        _security_updates_check(security_packages),
        _updates_check(packages),
        _reboot_check(reboot_required),
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
            "source": patch.get("source") or "",
            "updates_total": len(packages),
            "security_updates_total": len(security_packages),
            "reboot_required": reboot_required,
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "packages": packages,
        "security_packages": security_packages,
    }


def render_patch_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Patch Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Source: **{escape_markdown_text(summary.get('source') or 'unknown')}**",
        f"- Updates: **{escape_markdown_text(summary.get('updates_total', 0))}**",
        f"- Security updates: **{escape_markdown_text(summary.get('security_updates_total', 0))}**",
        f"- Reboot required: **{escape_markdown_text(_display_bool(summary.get('reboot_required')))}**",
        "",
        "## Checks",
        "",
        "| Check | Status | Severity | Reason | Recommended action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in report.get("checks", []):
        lines.append(
            "| "
            f"{format_markdown_code(check.get('id') or '-')} {escape_markdown_text(check.get('title') or '')} | "
            f"{escape_markdown_text(check.get('status') or '-')} | "
            f"{escape_markdown_text(check.get('severity') or '-')} | "
            f"{escape_markdown_text(check.get('reason') or '-')} | "
            f"{escape_markdown_text(check.get('recommended_action') or '-')} |"
        )
    lines.extend(["", "## Security Updates", ""])
    _append_package_table(lines, report.get("security_packages", []))
    lines.extend(["", "## All Updates", ""])
    _append_package_table(lines, report.get("packages", []))
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `pass`: patch evidence exists and no pending package updates or reboot requirement were recorded.",
            "- `warn`: non-security updates or unknown reboot state need operator review.",
            "- `fail`: patch evidence is missing, security updates are pending, or reboot is required.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_patch_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "name",
            "current_version",
            "candidate_version",
            "architecture",
            "security",
            "status",
            "severity",
            "path",
            "reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in report.get("checks", []):
        writer.writerow(
            {
                "record_type": "check",
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "name": "",
                "current_version": "",
                "candidate_version": "",
                "architecture": "",
                "security": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for package in report.get("packages", []):
        writer.writerow(
            {
                "record_type": "package",
                "id": package.get("name", ""),
                "title": "",
                "name": package.get("name", ""),
                "current_version": package.get("current_version", ""),
                "candidate_version": package.get("candidate_version", ""),
                "architecture": package.get("architecture", ""),
                "security": package.get("security", ""),
                "status": "review",
                "severity": "high" if package.get("security") else "medium",
                "path": "signals.patch.packages",
                "reason": "Pending package update needs owner review.",
                "recommended_action": "Apply, schedule, or explicitly defer the update.",
            }
        )
    return output.getvalue()


def _patch_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    patch = signals.get("patch")
    return patch if isinstance(patch, dict) else {}


def _patch_signal_check(patch: dict[str, Any]) -> dict[str, str]:
    present = bool(patch)
    return _check(
        "patch_signal_present",
        "Patch signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.patch",
        "Patch evidence is present." if present else "signals.patch is missing or empty.",
        "Collect package update evidence from apt, package managers, or endpoint management.",
    )


def _security_updates_check(packages: list[dict[str, Any]]) -> dict[str, str]:
    return _check(
        "security_updates_applied",
        "Security updates are applied",
        "fail" if packages else "pass",
        "high",
        "signals.patch.security_packages",
        f"{len(packages)} security update(s) are pending." if packages else "No pending security updates were recorded.",
        "Apply pending security updates or record an approved maintenance exception.",
    )


def _updates_check(packages: list[dict[str, Any]]) -> dict[str, str]:
    return _check(
        "package_updates_reviewed",
        "Package updates are reviewed",
        "warn" if packages else "pass",
        "medium",
        "signals.patch.packages",
        f"{len(packages)} package update(s) are pending." if packages else "No pending package updates were recorded.",
        "Schedule maintenance or document why pending updates are deferred.",
    )


def _reboot_check(reboot_required: bool | None) -> dict[str, str]:
    if reboot_required is True:
        status = "fail"
        reason = "A reboot is required to complete patching."
    elif reboot_required is False:
        status = "pass"
        reason = "No reboot requirement was recorded."
    else:
        status = "warn"
        reason = "Reboot requirement evidence is missing."
    return _check(
        "reboot_requirement_reviewed",
        "Reboot requirement is reviewed",
        status,
        "medium",
        "signals.patch.reboot_required",
        reason,
        "Record reboot-required state and complete required reboots during maintenance windows.",
    )


def _package_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(item.get("name") or "unknown"),
        "suite": str(item.get("suite") or ""),
        "current_version": str(item.get("current_version") or ""),
        "candidate_version": str(item.get("candidate_version") or ""),
        "architecture": str(item.get("architecture") or ""),
        "security": bool(item.get("security")),
    }


def _append_package_table(lines: list[str], packages: list[dict[str, Any]]) -> None:
    if not packages:
        lines.append("No matching packages were found.")
        return
    lines.extend(["| Package | Current | Candidate | Architecture | Security |", "| --- | --- | --- | --- | --- |"])
    for package in packages:
        lines.append(
            "| "
            f"{format_markdown_code(package.get('name') or '-')} | "
            f"{escape_markdown_text(package.get('current_version') or '-')} | "
            f"{escape_markdown_text(package.get('candidate_version') or '-')} | "
            f"{escape_markdown_text(package.get('architecture') or '-')} | "
            f"{escape_markdown_text(_display_bool(package.get('security')))} |"
        )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _display_bool(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _check(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    path: str,
    reason: str,
    recommended_action: str,
) -> dict[str, str]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }
