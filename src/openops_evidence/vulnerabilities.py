from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_vulnerability_report(evidence: dict[str, Any]) -> dict[str, Any]:
    signal = _vulnerability_signal(evidence)
    findings = [_finding_record(item) for item in _list_of_dicts(signal.get("findings"))]
    severity_counts = _severity_counts(findings)
    critical_findings = [item for item in findings if item["severity"] == "critical"]
    high_findings = [item for item in findings if item["severity"] == "high"]
    critical_high = critical_findings + high_findings
    fixable_findings = [item for item in findings if item["fixed_version"]]
    checks = [
        _vulnerability_signal_check(signal),
        _critical_high_check(critical_high),
        _medium_low_check(findings, critical_high),
        _fix_versions_check(findings, fixable_findings),
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
            "scanner": signal.get("scanner") or "",
            "targets_total": _int_value(signal.get("targets_total")) or _targets_total(findings),
            "findings_total": len(findings),
            "critical_total": severity_counts["critical"],
            "high_total": severity_counts["high"],
            "medium_total": severity_counts["medium"],
            "low_total": severity_counts["low"],
            "unknown_total": severity_counts["unknown"],
            "fixable_total": len(fixable_findings),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "findings": findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "critical_high_findings": critical_high,
    }


def render_vulnerability_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Vulnerability Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Scanner: **{escape_markdown_text(summary.get('scanner') or 'unknown')}**",
        f"- Targets: **{escape_markdown_text(summary.get('targets_total', 0))}**",
        f"- Findings: **{escape_markdown_text(summary.get('findings_total', 0))}**",
        f"- Critical/High: **{escape_markdown_text(summary.get('critical_total', 0) + summary.get('high_total', 0))}**",
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
    lines.extend(["", "## Critical And High Findings", ""])
    _append_finding_table(lines, report.get("critical_high_findings", []))
    lines.extend(["", "## Fixable Findings", ""])
    _append_finding_table(lines, [item for item in report.get("findings", []) if item.get("fixed_version")])
    lines.extend(["", "## All Findings", ""])
    _append_finding_table(lines, report.get("findings", []))
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `pass`: vulnerability evidence exists and no findings were recorded.",
            "- `warn`: medium, low, or unknown findings need owner review.",
            "- `fail`: critical or high vulnerabilities are present, or vulnerability evidence is missing.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_vulnerability_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "target",
            "package",
            "installed_version",
            "fixed_version",
            "severity",
            "status",
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
                "target": "",
                "package": "",
                "installed_version": "",
                "fixed_version": "",
                "severity": check.get("severity", ""),
                "status": check.get("status", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for finding in report.get("findings", []):
        writer.writerow(
            {
                "record_type": "finding",
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "target": finding.get("target", ""),
                "package": finding.get("package", ""),
                "installed_version": finding.get("installed_version", ""),
                "fixed_version": finding.get("fixed_version", ""),
                "severity": finding.get("severity", ""),
                "status": "review",
                "path": "signals.vulnerabilities.findings",
                "reason": "Vulnerability finding needs owner review.",
                "recommended_action": "Upgrade, patch, rebuild, or record an approved exception.",
            }
        )
    return output.getvalue()


def _vulnerability_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    value = signals.get("vulnerabilities")
    return value if isinstance(value, dict) else {}


def _vulnerability_signal_check(signal: dict[str, Any]) -> dict[str, str]:
    present = bool(signal)
    return _check(
        "vulnerability_signal_present",
        "Vulnerability signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.vulnerabilities",
        "Vulnerability scan evidence is present." if present else "signals.vulnerabilities is missing or empty.",
        "Collect vulnerability evidence from Trivy or another scanner.",
    )


def _critical_high_check(findings: list[dict[str, Any]]) -> dict[str, str]:
    return _check(
        "critical_high_vulnerabilities_remediated",
        "Critical and high vulnerabilities are remediated",
        "fail" if findings else "pass",
        "critical",
        "signals.vulnerabilities.findings",
        f"{len(findings)} critical/high vulnerability finding(s) are present." if findings else "No critical or high vulnerabilities were recorded.",
        "Patch affected packages, rebuild images, or record approved risk treatment.",
    )


def _medium_low_check(findings: list[dict[str, Any]], critical_high: list[dict[str, Any]]) -> dict[str, str]:
    remaining = len(findings) - len(critical_high)
    return _check(
        "noncritical_vulnerabilities_reviewed",
        "Non-critical vulnerabilities are reviewed",
        "warn" if remaining else "pass",
        "medium",
        "signals.vulnerabilities.findings",
        f"{remaining} non-critical vulnerability finding(s) need review." if remaining else "No non-critical vulnerabilities were recorded.",
        "Assign owner review for remaining vulnerabilities and track remediation or acceptance.",
    )


def _fix_versions_check(findings: list[dict[str, Any]], fixable_findings: list[dict[str, Any]]) -> dict[str, str]:
    missing = len(findings) - len(fixable_findings)
    return _check(
        "fixed_versions_recorded",
        "Fixed versions are recorded where available",
        "warn" if missing else "pass",
        "medium",
        "signals.vulnerabilities.findings.fixed_version",
        f"{missing} finding(s) have no fixed version in scanner output." if missing else "All findings include fixed-version evidence.",
        "Confirm scanner database freshness and record upgrade, mitigation, or acceptance decisions.",
    )


def _finding_record(item: dict[str, Any]) -> dict[str, Any]:
    severity = str(item.get("severity") or "unknown").lower()
    return {
        "id": str(item.get("id") or "unknown"),
        "target": str(item.get("target") or ""),
        "package": str(item.get("package") or ""),
        "installed_version": str(item.get("installed_version") or ""),
        "fixed_version": str(item.get("fixed_version") or ""),
        "severity": severity if severity in {"critical", "high", "medium", "low", "unknown"} else "unknown",
        "title": str(item.get("title") or ""),
        "primary_url": str(item.get("primary_url") or ""),
    }


def _append_finding_table(lines: list[str], findings: list[dict[str, Any]]) -> None:
    if not findings:
        lines.append("No matching findings were found.")
        return
    lines.extend(["| ID | Severity | Target | Package | Installed | Fixed |", "| --- | --- | --- | --- | --- | --- |"])
    for finding in findings:
        lines.append(
            "| "
            f"{format_markdown_code(finding.get('id') or '-')} | "
            f"{escape_markdown_text(finding.get('severity') or '-')} | "
            f"{escape_markdown_text(finding.get('target') or '-')} | "
            f"{escape_markdown_text(finding.get('package') or '-')} | "
            f"{escape_markdown_text(finding.get('installed_version') or '-')} | "
            f"{escape_markdown_text(finding.get('fixed_version') or '-')} |"
        )


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        counts[finding.get("severity") if finding.get("severity") in counts else "unknown"] += 1
    return counts


def _targets_total(findings: list[dict[str, Any]]) -> int:
    return len({item.get("target") for item in findings if item.get("target")})


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


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
