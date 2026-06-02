from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


ENFORCED_DMARC_POLICIES = {"quarantine", "reject"}
MONITORING_DMARC_POLICIES = {"none"}
_DMARC_POLICY_RE = re.compile(r"(?:^|;)\s*p\s*=\s*([a-zA-Z0-9_-]+)")


def create_mail_report(evidence: dict[str, Any]) -> dict[str, Any]:
    domains = [_domain_record(item, index) for index, item in enumerate(_mail_domains(evidence))]
    failed = [domain for domain in domains if domain["status"] == "fail"]
    warnings = [domain for domain in domains if domain["status"] == "warn"]
    passed = [domain for domain in domains if domain["status"] == "pass"]
    status = "fail" if failed else "warn" if warnings or not domains else "pass"
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
            "status": status,
            "domains_total": len(domains),
            "domains_passed": len(passed),
            "domains_warn": len(warnings),
            "domains_failed": len(failed),
            "spf_passed": len([domain for domain in domains if domain["spf"] is True]),
            "spf_missing": len([domain for domain in domains if domain["spf"] is not True]),
            "dkim_passed": len([domain for domain in domains if domain["dkim"] is True]),
            "dkim_missing": len([domain for domain in domains if domain["dkim"] is not True]),
            "dmarc_enforced": len([domain for domain in domains if domain["dmarc_status"] == "enforced"]),
            "dmarc_monitoring": len([domain for domain in domains if domain["dmarc_status"] == "monitoring"]),
            "dmarc_missing": len([domain for domain in domains if domain["dmarc_status"] == "missing"]),
            "dmarc_unknown": len([domain for domain in domains if domain["dmarc_status"] == "unknown"]),
        },
        "domains": domains,
    }


def render_mail_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Mail Domain Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Domains: **{escape_markdown_text(summary.get('domains_total', 0))}**",
        f"- Passed: **{escape_markdown_text(summary.get('domains_passed', 0))}**",
        f"- Warnings: **{escape_markdown_text(summary.get('domains_warn', 0))}**",
        f"- Failed: **{escape_markdown_text(summary.get('domains_failed', 0))}**",
        "",
        "## Domains",
        "",
    ]
    domains = report.get("domains", [])
    if not domains:
        lines.extend(["No mail domain evidence was found.", ""])
    else:
        lines.extend(
            [
                "| Domain | Status | SPF | DKIM | DMARC | Reason | Recommended action |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for domain in domains:
            lines.append(
                "| "
                f"{format_markdown_code(domain.get('domain') or '-')} | "
                f"{escape_markdown_text(domain.get('status') or '-')} | "
                f"{escape_markdown_text(_display_bool(domain.get('spf')))} | "
                f"{escape_markdown_text(_display_bool(domain.get('dkim')))} | "
                f"{escape_markdown_text(domain.get('dmarc_policy') or '-')} | "
                f"{escape_markdown_text(domain.get('reason') or '-')} | "
                f"{escape_markdown_text(domain.get('recommended_action') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: SPF and DKIM are present and DMARC is enforced with `quarantine` or `reject`.",
            "- `warn`: DMARC is present but only monitoring or the domain record is incomplete.",
            "- `fail`: SPF, DKIM, or usable DMARC evidence is missing.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_mail_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "domain",
            "status",
            "spf",
            "dkim",
            "dmarc",
            "dmarc_policy",
            "dmarc_status",
            "reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for domain in report.get("domains", []):
        writer.writerow(
            {
                "domain": domain.get("domain", ""),
                "status": domain.get("status", ""),
                "spf": domain.get("spf", ""),
                "dkim": domain.get("dkim", ""),
                "dmarc": domain.get("dmarc", ""),
                "dmarc_policy": domain.get("dmarc_policy", ""),
                "dmarc_status": domain.get("dmarc_status", ""),
                "reason": domain.get("reason", ""),
                "recommended_action": domain.get("recommended_action", ""),
            }
        )
    return output.getvalue()


def _mail_domains(evidence: dict[str, Any]) -> list[Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return []
    mail = signals.get("mail")
    if not isinstance(mail, dict):
        return []
    domains = mail.get("domains")
    return domains if isinstance(domains, list) else []


def _domain_record(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {
            "domain": f"domain-{index + 1}",
            "status": "fail",
            "spf": None,
            "dkim": None,
            "dmarc": "",
            "dmarc_policy": "missing",
            "dmarc_status": "missing",
            "reason": "Mail domain entry is not an object.",
            "recommended_action": "Record domain, SPF, DKIM, and DMARC evidence as an object.",
        }
    domain = str(item.get("domain") or f"domain-{index + 1}")
    spf = item.get("spf") if isinstance(item.get("spf"), bool) else None
    dkim = item.get("dkim") if isinstance(item.get("dkim"), bool) else None
    dmarc_raw = str(item.get("dmarc") or "")
    dmarc_policy = _dmarc_policy(dmarc_raw)
    dmarc_status = _dmarc_status(dmarc_policy)
    missing = []
    warnings = []
    if spf is not True:
        missing.append("SPF")
    if dkim is not True:
        missing.append("DKIM")
    if dmarc_status == "missing":
        missing.append("DMARC")
    elif dmarc_status == "unknown":
        warnings.append("DMARC policy is unknown")
    elif dmarc_status == "monitoring":
        warnings.append("DMARC is monitoring-only")
    if missing:
        status = "fail"
        reason = ", ".join(missing) + " evidence is missing or false."
        action = "Publish or record SPF, DKIM, and an enforced DMARC policy for this domain."
    elif warnings:
        status = "warn"
        reason = "; ".join(warnings) + "."
        action = "Move DMARC from monitoring to quarantine or reject after reviewing mail flows."
    else:
        status = "pass"
        reason = "SPF, DKIM, and enforced DMARC evidence are present."
        action = "Keep mail authentication evidence current."
    return {
        "domain": domain,
        "status": status,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc_raw,
        "dmarc_policy": dmarc_policy,
        "dmarc_status": dmarc_status,
        "reason": reason,
        "recommended_action": action,
    }


def _dmarc_policy(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        return "missing"
    match = _DMARC_POLICY_RE.search(normalized)
    if match:
        return match.group(1)
    return normalized


def _dmarc_status(policy: str) -> str:
    if policy in ENFORCED_DMARC_POLICIES:
        return "enforced"
    if policy in MONITORING_DMARC_POLICIES:
        return "monitoring"
    if policy == "missing":
        return "missing"
    return "unknown"


def _display_bool(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"
