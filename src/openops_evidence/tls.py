from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_tls_report(evidence: dict[str, Any], *, warn_days: int = 30) -> dict[str, Any]:
    evaluated_at = _reference_time(evidence)
    certificates = [
        _certificate_record(item, index, warn_days=warn_days, now=evaluated_at)
        for index, item in enumerate(_tls_certificates(evidence))
    ]
    failed = [certificate for certificate in certificates if certificate["status"] == "fail"]
    warnings = [certificate for certificate in certificates if certificate["status"] == "warn"]
    passed = [certificate for certificate in certificates if certificate["status"] == "pass"]
    status = "fail" if failed else "warn" if warnings or not certificates else "pass"
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "evaluated_at": evaluated_at.isoformat(),
            "warn_days": warn_days,
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
        },
        "summary": {
            "status": status,
            "certificates_total": len(certificates),
            "certificates_passed": len(passed),
            "certificates_warn": len(warnings),
            "certificates_failed": len(failed),
            "expired_count": len([item for item in certificates if item["certificate_status"] == "expired"]),
            "expiring_soon_count": len(
                [item for item in certificates if item["certificate_status"] == "expiring_soon"]
            ),
            "invalid_count": len([item for item in certificates if item["certificate_status"] == "invalid"]),
            "unknown_count": len([item for item in certificates if item["certificate_status"] == "unknown"]),
        },
        "certificates": certificates,
    }


def render_tls_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps TLS Certificate Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Evaluated at: {format_markdown_code(metadata.get('evaluated_at', 'unknown'))}",
        f"- Warn days: **{escape_markdown_text(metadata.get('warn_days', '-'))}**",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Certificates: **{escape_markdown_text(summary.get('certificates_total', 0))}**",
        f"- Warnings: **{escape_markdown_text(summary.get('certificates_warn', 0))}**",
        f"- Failed: **{escape_markdown_text(summary.get('certificates_failed', 0))}**",
        "",
        "## Certificates",
        "",
    ]
    certificates = report.get("certificates", [])
    if not certificates:
        lines.extend(["No TLS certificate evidence was found.", ""])
    else:
        lines.extend(
            [
                "| Hostname | Port | Status | Not After | Days Remaining | Issuer | Reason | Recommended action |",
                "| --- | ---: | --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for certificate in certificates:
            lines.append(
                "| "
                f"{format_markdown_code(certificate.get('hostname') or '-')} | "
                f"{escape_markdown_text(certificate.get('port') or '-')} | "
                f"{escape_markdown_text(certificate.get('status') or '-')} | "
                f"{format_markdown_code(certificate.get('not_after') or '-')} | "
                f"{escape_markdown_text(_display(certificate.get('days_remaining')))} | "
                f"{escape_markdown_text(certificate.get('issuer') or '-')} | "
                f"{escape_markdown_text(certificate.get('reason') or '-')} | "
                f"{escape_markdown_text(certificate.get('recommended_action') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: certificate expiry is known and outside the warning window.",
            "- `warn`: certificate expiry is inside the configured warning window or no certificate evidence exists.",
            "- `fail`: certificate evidence is invalid or a certificate is already expired.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_tls_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "hostname",
            "port",
            "status",
            "certificate_status",
            "not_after",
            "days_remaining",
            "issuer",
            "reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for certificate in report.get("certificates", []):
        writer.writerow(
            {
                "hostname": certificate.get("hostname", ""),
                "port": certificate.get("port", ""),
                "status": certificate.get("status", ""),
                "certificate_status": certificate.get("certificate_status", ""),
                "not_after": certificate.get("not_after", ""),
                "days_remaining": certificate.get("days_remaining", ""),
                "issuer": certificate.get("issuer", ""),
                "reason": certificate.get("reason", ""),
                "recommended_action": certificate.get("recommended_action", ""),
            }
        )
    return output.getvalue()


def _tls_certificates(evidence: dict[str, Any]) -> list[Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return []
    tls = signals.get("tls")
    if not isinstance(tls, dict):
        return []
    certificates = tls.get("certificates")
    return certificates if isinstance(certificates, list) else []


def _certificate_record(item: Any, index: int, *, warn_days: int, now: datetime) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {
            "hostname": f"certificate-{index + 1}",
            "port": None,
            "status": "fail",
            "certificate_status": "invalid",
            "not_after": "",
            "days_remaining": None,
            "issuer": "",
            "reason": "TLS certificate entry is not an object.",
            "recommended_action": "Record hostname and not_after evidence for each TLS certificate.",
        }
    hostname = str(item.get("hostname") or item.get("subject") or f"certificate-{index + 1}")
    port = item.get("port") if isinstance(item.get("port"), int) else None
    issuer = _issuer(item.get("issuer"))
    not_after_raw = str(item.get("not_after") or "")
    not_after = _parse_datetime(not_after_raw)
    if not_after is None:
        return {
            "hostname": hostname,
            "port": port,
            "status": "fail",
            "certificate_status": "invalid" if not_after_raw else "unknown",
            "not_after": not_after_raw,
            "days_remaining": None,
            "issuer": issuer,
            "reason": "TLS certificate expiry evidence is missing or invalid.",
            "recommended_action": "Record a valid not_after timestamp from the certificate chain.",
        }
    days_remaining = (not_after - now).days
    if days_remaining < 0:
        status = "fail"
        certificate_status = "expired"
        reason = "TLS certificate is already expired."
        action = "Renew and deploy the certificate, then refresh evidence."
    elif days_remaining <= warn_days:
        status = "warn"
        certificate_status = "expiring_soon"
        reason = f"TLS certificate expires within {warn_days} day(s)."
        action = "Renew or schedule certificate rotation before expiry."
    else:
        status = "pass"
        certificate_status = "current"
        reason = "TLS certificate expiry is outside the warning window."
        action = "Keep certificate renewal automation and evidence current."
    return {
        "hostname": hostname,
        "port": port,
        "status": status,
        "certificate_status": certificate_status,
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "issuer": issuer,
        "reason": reason,
        "recommended_action": action,
    }


def _reference_time(evidence: dict[str, Any]) -> datetime:
    generated_at = evidence.get("generated_at")
    if isinstance(generated_at, str):
        parsed = _parse_datetime(generated_at)
        if parsed is not None:
            return parsed
    return datetime.now(UTC)


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _issuer(value: Any) -> str:
    if isinstance(value, str):
        return value
    return "" if value is None else str(value)


def _display(value: Any) -> str:
    return "unknown" if value is None else str(value)
