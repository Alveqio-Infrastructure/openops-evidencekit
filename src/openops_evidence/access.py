from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SAFE_ENTRYPOINTS = {
    "bastion",
    "identity-aware-proxy",
    "iap",
    "jit",
    "jump-host",
    "netbird",
    "pam",
    "privileged-access-management",
    "sso",
    "tailscale",
    "vpn",
    "wireguard",
    "zero-trust",
}
RISKY_ENTRYPOINTS = {
    "direct",
    "direct-ssh",
    "exposed",
    "password",
    "password-login",
    "public",
    "public-admin",
    "public-rdp",
    "public-ssh",
    "rdp",
    "rdp-public",
    "ssh-public",
}


def create_access_report(evidence: dict[str, Any]) -> dict[str, Any]:
    access = _access_signal(evidence)
    entrypoints = [_entrypoint_record(value) for value in _entrypoint_values(access)]
    checks = [
        _access_signal_check(access),
        _public_ssh_check(access),
        _mfa_check(access),
        _entrypoints_present_check(entrypoints),
        _risky_entrypoints_check(entrypoints),
        _unknown_entrypoints_check(entrypoints),
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
            "ssh_public_exposed": access.get("ssh_public_exposed") if isinstance(access.get("ssh_public_exposed"), bool) else None,
            "mfa_required": access.get("mfa_required") if isinstance(access.get("mfa_required"), bool) else None,
            "entrypoints_total": len(entrypoints),
            "safe_entrypoints": len([entrypoint for entrypoint in entrypoints if entrypoint["status"] == "safe"]),
            "risky_entrypoints": len([entrypoint for entrypoint in entrypoints if entrypoint["status"] == "risky"]),
            "unknown_entrypoints": len([entrypoint for entrypoint in entrypoints if entrypoint["status"] == "unknown"]),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "entrypoints": entrypoints,
    }


def render_access_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Access Exposure Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Public SSH exposed: **{escape_markdown_text(_display_bool(summary.get('ssh_public_exposed')))}**",
        f"- MFA required: **{escape_markdown_text(_display_bool(summary.get('mfa_required')))}**",
        f"- Admin entrypoints: **{escape_markdown_text(summary.get('entrypoints_total', 0))}**",
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
    lines.extend(["", "## Admin Entrypoints", ""])
    entrypoints = report.get("entrypoints", [])
    if not entrypoints:
        lines.extend(["No administrative entrypoint evidence was found.", ""])
    else:
        lines.extend(
            [
                "| Entrypoint | Status | Reason |",
                "| --- | --- | --- |",
            ]
        )
        for entrypoint in entrypoints:
            lines.append(
                "| "
                f"{format_markdown_code(entrypoint.get('name') or '-')} | "
                f"{escape_markdown_text(entrypoint.get('status') or '-')} | "
                f"{escape_markdown_text(entrypoint.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: public SSH is closed, MFA is required, and admin entrypoints are reviewed.",
            "- `warn`: evidence is incomplete or entrypoints need manual classification.",
            "- `fail`: public SSH or risky direct administrative entrypoints are exposed, or MFA is not required.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_access_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "name",
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
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for entrypoint in report.get("entrypoints", []):
        writer.writerow(
            {
                "record_type": "entrypoint",
                "id": "",
                "title": "",
                "name": entrypoint.get("name", ""),
                "status": entrypoint.get("status", ""),
                "severity": "",
                "path": "signals.access.admin_entrypoints",
                "reason": entrypoint.get("reason", ""),
                "recommended_action": "",
            }
        )
    return output.getvalue()


def _access_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    access = signals.get("access")
    return access if isinstance(access, dict) else {}


def _entrypoint_values(access: dict[str, Any]) -> list[str]:
    entrypoints = access.get("admin_entrypoints")
    if not isinstance(entrypoints, list):
        return []
    return [str(entrypoint) for entrypoint in entrypoints if isinstance(entrypoint, str) and entrypoint]


def _entrypoint_record(value: str) -> dict[str, str]:
    normalized = _normalize_entrypoint(value)
    if normalized in SAFE_ENTRYPOINTS:
        return {
            "name": value,
            "status": "safe",
            "reason": "Entrypoint is a controlled administrative access layer.",
        }
    if normalized in RISKY_ENTRYPOINTS:
        return {
            "name": value,
            "status": "risky",
            "reason": "Entrypoint suggests direct or public administrative exposure.",
        }
    return {
        "name": value,
        "status": "unknown",
        "reason": "Entrypoint is not classified by EvidenceKit and needs review.",
    }


def _access_signal_check(access: dict[str, Any]) -> dict[str, Any]:
    present = bool(access)
    return _check(
        "access_signal_present",
        "Access signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.access",
        "Administrative access evidence is present." if present else "signals.access is missing or empty.",
        "Record administrative access evidence, including public SSH exposure, MFA, and entrypoints.",
    )


def _public_ssh_check(access: dict[str, Any]) -> dict[str, Any]:
    value = access.get("ssh_public_exposed")
    if value is False:
        status = "pass"
        reason = "Public SSH exposure is recorded as closed."
    elif value is True:
        status = "fail"
        reason = "Public SSH exposure is recorded as open."
    else:
        status = "warn"
        reason = "Public SSH exposure evidence is missing."
    return _check(
        "public_ssh_closed",
        "Public SSH exposure is closed",
        status,
        "critical",
        "signals.access.ssh_public_exposed",
        reason,
        "Move SSH behind VPN, SSO, bastion, or another controlled access layer and record the reviewed state.",
    )


def _mfa_check(access: dict[str, Any]) -> dict[str, Any]:
    value = access.get("mfa_required")
    if value is True:
        status = "pass"
        reason = "Administrative MFA is required."
    elif value is False:
        status = "fail"
        reason = "Administrative MFA is not required."
    else:
        status = "warn"
        reason = "Administrative MFA evidence is missing."
    return _check(
        "mfa_required",
        "Administrative MFA is required",
        status,
        "high",
        "signals.access.mfa_required",
        reason,
        "Require MFA for administrative entrypoints and record the reviewed state.",
    )


def _entrypoints_present_check(entrypoints: list[dict[str, str]]) -> dict[str, Any]:
    present = bool(entrypoints)
    return _check(
        "admin_entrypoints_recorded",
        "Administrative entrypoints are recorded",
        "pass" if present else "warn",
        "medium",
        "signals.access.admin_entrypoints",
        "Administrative entrypoints are recorded." if present else "No administrative entrypoints were recorded.",
        "Record administrative entrypoints such as VPN, SSO, bastion, PAM, or zero-trust access.",
    )


def _risky_entrypoints_check(entrypoints: list[dict[str, str]]) -> dict[str, Any]:
    risky = [entrypoint["name"] for entrypoint in entrypoints if entrypoint["status"] == "risky"]
    return _check(
        "risky_entrypoints_absent",
        "Risky administrative entrypoints are absent",
        "fail" if risky else "pass",
        "critical",
        "signals.access.admin_entrypoints",
        f"Risky entrypoints found: {', '.join(risky)}." if risky else "No risky entrypoints were found.",
        "Replace risky direct or public administrative entrypoints with controlled access paths.",
    )


def _unknown_entrypoints_check(entrypoints: list[dict[str, str]]) -> dict[str, Any]:
    unknown = [entrypoint["name"] for entrypoint in entrypoints if entrypoint["status"] == "unknown"]
    return _check(
        "entrypoints_classified",
        "Administrative entrypoints are classified",
        "warn" if unknown else "pass",
        "low",
        "signals.access.admin_entrypoints",
        f"Unclassified entrypoints need review: {', '.join(unknown)}." if unknown else "All recorded entrypoints are classified.",
        "Review unclassified entrypoints and document whether they are controlled access paths.",
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


def _normalize_entrypoint(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def _display_bool(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"
