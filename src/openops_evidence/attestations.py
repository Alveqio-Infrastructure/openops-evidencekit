from __future__ import annotations

import csv
import hashlib
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_review_attestation(
    manifest: dict[str, Any],
    manifest_path: str | Path,
    *,
    approver: str,
    role: str,
    statement: str,
    review_id: str = "",
    report: dict[str, Any] | None = None,
    gate: dict[str, Any] | None = None,
    scope_report: dict[str, Any] | None = None,
    evidence_drift: dict[str, Any] | None = None,
    privacy_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest_bytes = manifest_file.read_bytes()
    artifact_count = _int_or_zero(manifest.get("metadata", {}).get("artifact_count"))
    checks = _attestation_checks(
        report=report,
        gate=gate,
        scope_report=scope_report,
        evidence_drift=evidence_drift,
        privacy_scan=privacy_scan,
    )
    warnings = [check for check in checks if check["status"] == "warn"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "review_id": review_id,
            "approver": approver,
            "role": role,
            "statement": statement,
        },
        "summary": {
            "status": "warn" if warnings else "pass",
            "checks_total": len(checks),
            "checks_passed": len(checks) - len(warnings),
            "checks_warn": len(warnings),
            "artifact_count": artifact_count,
        },
        "manifest": {
            "path": manifest_file.name,
            "name": str(manifest.get("metadata", {}).get("name", "")),
            "artifact_count": artifact_count,
            "size_bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "checks": checks,
    }


def render_attestation_markdown(attestation: dict[str, Any]) -> str:
    metadata = attestation.get("metadata", {})
    summary = attestation.get("summary", {})
    manifest = attestation.get("manifest", {})
    lines = [
        "# OpenOps Review Attestation",
        "",
        f"- Generated: {format_markdown_code(attestation.get('generated_at', 'unknown'))}",
        f"- Review ID: {escape_markdown_text(metadata.get('review_id') or '-')}",
        f"- Approver: **{escape_markdown_text(metadata.get('approver', ''))}**",
        f"- Role: {escape_markdown_text(metadata.get('role', ''))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Manifest: {format_markdown_code(manifest.get('path', ''))}",
        f"- Manifest SHA-256: {format_markdown_code(manifest.get('sha256', ''))}",
        f"- Artifacts: **{escape_markdown_text(summary.get('artifact_count', 0))}**",
        "",
        "## Statement",
        "",
        escape_markdown_text(metadata.get("statement", "")),
        "",
        "## Checks",
        "",
        "| Check | Status | Observed |",
        "| --- | --- | --- |",
    ]
    for check in attestation.get("checks", []):
        lines.append(
            "| "
            f"{format_markdown_code(check.get('id', ''))} {escape_markdown_text(check.get('title', ''))} | "
            f"{escape_markdown_text(check.get('status', ''))} | "
            f"{escape_markdown_text(check.get('observed', ''))} |"
        )
    lines.extend(
        [
            "",
            "This attestation records a review assertion for the referenced manifest. It is not a compliance certification or legal advice.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_attestation_csv(attestation: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "title", "status", "observed"],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in attestation.get("checks", []):
        writer.writerow(
            {
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "status": check.get("status", ""),
                "observed": check.get("observed", ""),
            }
        )
    return output.getvalue()


def _attestation_checks(
    *,
    report: dict[str, Any] | None,
    gate: dict[str, Any] | None,
    scope_report: dict[str, Any] | None,
    evidence_drift: dict[str, Any] | None,
    privacy_scan: dict[str, Any] | None,
) -> list[dict[str, str]]:
    checks = [
        {
            "id": "manifest_recorded",
            "title": "Manifest hash is recorded",
            "status": "pass",
            "observed": "Manifest path, size, artifact count, and SHA-256 are recorded.",
        }
    ]
    if report is not None:
        summary = report.get("summary", {})
        status = str(summary.get("status", "unknown"))
        checks.append(
            {
                "id": "report_status",
                "title": "Readiness report status",
                "status": "pass" if status == "pass" else "warn",
                "observed": f"{status} score={summary.get('score', 'n/a')}",
            }
        )
    if gate is not None:
        summary = gate.get("summary", {})
        status = str(summary.get("status", "unknown"))
        checks.append(
            {
                "id": "gate_status",
                "title": "Gate status",
                "status": "pass" if status == "pass" else "warn",
                "observed": f"{status} failed_conditions={summary.get('conditions_failed', 'n/a')}",
            }
        )
    if scope_report is not None:
        summary = scope_report.get("summary", {})
        status = str(summary.get("status", "unknown"))
        checks.append(
            {
                "id": "scope_status",
                "title": "Scope report status",
                "status": "pass" if status == "pass" else "warn",
                "observed": (
                    f"{status} missing_assets={summary.get('missing_in_scope_assets', 'n/a')} "
                    f"unclassified_domains={summary.get('unclassified_evidence_domains', 'n/a')}"
                ),
            }
        )
    if evidence_drift is not None:
        summary = evidence_drift.get("summary", {})
        status = str(summary.get("status", "unknown"))
        checks.append(
            {
                "id": "evidence_drift_status",
                "title": "Evidence drift status",
                "status": "pass" if status == "pass" else "warn",
                "observed": (
                    f"{status} asset_changes={summary.get('asset_changes_count', 'n/a')} "
                    f"domain_changes={summary.get('domain_changes_count', 'n/a')}"
                ),
            }
        )
    if privacy_scan is not None:
        summary = privacy_scan.get("summary", {})
        findings = _int_or_zero(summary.get("findings_count"))
        checks.append(
            {
                "id": "privacy_scan_status",
                "title": "Privacy scan findings",
                "status": "pass" if findings == 0 else "warn",
                "observed": f"findings={findings}",
            }
        )
    return checks


def _int_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
