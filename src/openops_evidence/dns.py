from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_dns_report(evidence: dict[str, Any]) -> dict[str, Any]:
    domains = [_domain_record(item, index) for index, item in enumerate(_dns_domains(evidence))]
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
            "domains_with_address_records": len([domain for domain in domains if domain["address_record_count"] > 0]),
            "domains_with_nameservers": len([domain for domain in domains if domain["nameserver_count"] > 0]),
            "domains_with_caa": len([domain for domain in domains if domain["caa_present"] is True]),
            "domains_with_dnssec": len([domain for domain in domains if domain["dnssec"] is True]),
        },
        "domains": domains,
    }


def render_dns_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps DNS Hygiene Report",
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
        lines.extend(["No DNS evidence was found.", ""])
    else:
        lines.extend(
            [
                "| Domain | Status | Address records | Nameservers | CAA | DNSSEC | Reason | Recommended action |",
                "| --- | --- | ---: | ---: | --- | --- | --- | --- |",
            ]
        )
        for domain in domains:
            lines.append(
                "| "
                f"{format_markdown_code(domain.get('domain') or '-')} | "
                f"{escape_markdown_text(domain.get('status') or '-')} | "
                f"{escape_markdown_text(domain.get('address_record_count', 0))} | "
                f"{escape_markdown_text(domain.get('nameserver_count', 0))} | "
                f"{escape_markdown_text(_display_bool(domain.get('caa_present')))} | "
                f"{escape_markdown_text(_display_bool(domain.get('dnssec')))} | "
                f"{escape_markdown_text(domain.get('reason') or '-')} | "
                f"{escape_markdown_text(domain.get('recommended_action') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: address records, nameservers, CAA, and DNSSEC evidence are present.",
            "- `warn`: core DNS resolution evidence exists, but CAA or DNSSEC evidence is missing.",
            "- `fail`: address records or nameserver evidence is missing or the domain entry is invalid.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_dns_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "domain",
            "status",
            "address_record_count",
            "nameserver_count",
            "caa_present",
            "dnssec",
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
                "address_record_count": domain.get("address_record_count", ""),
                "nameserver_count": domain.get("nameserver_count", ""),
                "caa_present": domain.get("caa_present", ""),
                "dnssec": domain.get("dnssec", ""),
                "reason": domain.get("reason", ""),
                "recommended_action": domain.get("recommended_action", ""),
            }
        )
    return output.getvalue()


def _dns_domains(evidence: dict[str, Any]) -> list[Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return []
    dns = signals.get("dns")
    if not isinstance(dns, dict):
        return []
    domains = dns.get("domains")
    return domains if isinstance(domains, list) else []


def _domain_record(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {
            "domain": f"domain-{index + 1}",
            "status": "fail",
            "address_record_count": 0,
            "nameserver_count": 0,
            "caa_present": None,
            "dnssec": None,
            "reason": "DNS domain entry is not an object.",
            "recommended_action": "Record domain, address record, nameserver, CAA, and DNSSEC evidence as an object.",
        }
    domain = str(item.get("domain") or item.get("hostname") or f"domain-{index + 1}")
    address_count = _record_count(item, "a") + _record_count(item, "aaaa") + _record_count(item, "cname")
    nameserver_count = _record_count(item, "nameservers") + _record_count(item, "ns")
    caa_present = _presence(item.get("caa") if "caa" in item else item.get("caa_records"))
    dnssec = item.get("dnssec") if isinstance(item.get("dnssec"), bool) else None
    missing = []
    warnings = []
    if address_count <= 0:
        missing.append("address records")
    if nameserver_count <= 0:
        missing.append("nameservers")
    if caa_present is not True:
        warnings.append("CAA evidence is missing")
    if dnssec is not True:
        warnings.append("DNSSEC evidence is missing or disabled")
    if missing:
        status = "fail"
        reason = ", ".join(missing) + " evidence is missing."
        action = "Record A, AAAA, or CNAME records plus authoritative nameserver evidence for this domain."
    elif warnings:
        status = "warn"
        reason = "; ".join(warnings) + "."
        action = "Review CAA and DNSSEC posture, then refresh DNS evidence."
    else:
        status = "pass"
        reason = "Address records, nameservers, CAA, and DNSSEC evidence are present."
        action = "Keep DNS evidence current and review it after provider or certificate authority changes."
    return {
        "domain": domain,
        "status": status,
        "address_record_count": address_count,
        "nameserver_count": nameserver_count,
        "caa_present": caa_present,
        "dnssec": dnssec,
        "reason": reason,
        "recommended_action": action,
    }


def _record_count(item: dict[str, Any], key: str) -> int:
    value = item.get(key)
    if isinstance(value, list):
        return len([entry for entry in value if entry not in ("", None)])
    if isinstance(value, str):
        return 1 if value.strip() else 0
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return max(int(value), 0)
    return 0


def _presence(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        return bool([entry for entry in value if entry not in ("", None)])
    if isinstance(value, str):
        return bool(value.strip())
    return None


def _display_bool(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"
