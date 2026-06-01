from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .policy import Check
from .reports import escape_markdown_text, format_markdown_code


def create_coverage_report(evidence: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    evidence_domains = _evidence_signal_domains(evidence)
    policy_domains = _policy_domains(checks)
    domains = [
        _domain_record(domain, evidence_domains, policy_domains)
        for domain in sorted(evidence_domains | set(policy_domains.keys()))
    ]
    covered = [item for item in domains if item["status"] == "covered"]
    unreviewed = [item for item in domains if item["status"] == "unreviewed_evidence"]
    missing = [item for item in domains if item["status"] == "missing_evidence"]
    evidence_total = len(evidence_domains)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "policy_check_count": len(checks),
        },
        "summary": {
            "status": "pass" if not unreviewed and not missing else "warn",
            "coverage_percent": round(100 * len(covered) / evidence_total) if evidence_total else 100,
            "evidence_domains_total": evidence_total,
            "policy_domains_total": len(policy_domains),
            "domains_total": len(domains),
            "covered_domains_count": len(covered),
            "unreviewed_evidence_domains_count": len(unreviewed),
            "missing_evidence_domains_count": len(missing),
            "checks_total": len(checks),
        },
        "domains": domains,
    }


def render_coverage_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Policy Coverage",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Coverage: **{escape_markdown_text(summary.get('coverage_percent', 0))}%**",
        f"- Evidence domains: **{escape_markdown_text(summary.get('evidence_domains_total', 0))}**",
        f"- Unreviewed evidence domains: **{escape_markdown_text(summary.get('unreviewed_evidence_domains_count', 0))}**",
        f"- Missing evidence domains: **{escape_markdown_text(summary.get('missing_evidence_domains_count', 0))}**",
        "",
        "| Domain | Status | Evidence | Checks | Required | Optional | Check IDs |",
        "| --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for domain in report.get("domains", []):
        lines.append(
            "| "
            f"{format_markdown_code(domain.get('domain', ''))} | "
            f"{escape_markdown_text(domain.get('status', ''))} | "
            f"{format_markdown_code(str(bool(domain.get('evidence_present'))).lower())} | "
            f"{escape_markdown_text(domain.get('check_count', 0))} | "
            f"{escape_markdown_text(domain.get('required_count', 0))} | "
            f"{escape_markdown_text(domain.get('optional_count', 0))} | "
            f"{escape_markdown_text(_join(domain.get('check_ids', [])) or '-')} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `covered`: evidence exists and at least one policy check evaluates that domain.",
            "- `unreviewed_evidence`: evidence exists but no policy check evaluates that domain.",
            "- `missing_evidence`: a policy check expects that domain, but evidence did not include it.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_coverage_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "domain",
            "status",
            "evidence_present",
            "policy_present",
            "check_count",
            "required_count",
            "optional_count",
            "check_ids",
            "paths",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for domain in report.get("domains", []):
        row = {key: domain.get(key) for key in writer.fieldnames}
        row["check_ids"] = _join(domain.get("check_ids", []))
        row["paths"] = _join(domain.get("paths", []))
        writer.writerow(row)
    return output.getvalue()


def _domain_record(
    domain: str,
    evidence_domains: set[str],
    policy_domains: dict[str, list[Check]],
) -> dict[str, Any]:
    checks = sorted(policy_domains.get(domain, []), key=lambda check: check.id)
    evidence_present = domain in evidence_domains
    policy_present = bool(checks)
    if evidence_present and policy_present:
        status = "covered"
    elif evidence_present:
        status = "unreviewed_evidence"
    else:
        status = "missing_evidence"
    return {
        "domain": domain,
        "status": status,
        "evidence_present": evidence_present,
        "policy_present": policy_present,
        "check_count": len(checks),
        "required_count": sum(1 for check in checks if check.required),
        "optional_count": sum(1 for check in checks if not check.required),
        "check_ids": [check.id for check in checks],
        "paths": sorted({check.path for check in checks}),
    }


def _evidence_signal_domains(evidence: dict[str, Any]) -> set[str]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return set()
    return {_clean_domain(str(key)) for key in signals.keys() if _clean_domain(str(key))}


def _policy_domains(checks: list[Check]) -> dict[str, list[Check]]:
    domains: dict[str, list[Check]] = {}
    for check in checks:
        domain = _path_domain(check.path)
        if not domain:
            continue
        domains.setdefault(domain, []).append(check)
    return domains


def _path_domain(path: str) -> str:
    parts = path.split(".")
    if len(parts) > 1 and parts[0] == "signals":
        return _clean_domain(parts[1])
    if parts:
        return _clean_domain(parts[0])
    return ""


def _clean_domain(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_")


def _join(value: list[str]) -> str:
    return ", ".join(str(item) for item in value)
