from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


DEFAULT_SLO_TARGETS = {
    "critical": 99.9,
    "high": 99.5,
    "medium": 99.0,
    "low": 95.0,
}


def create_service_level_report(evidence: dict[str, Any], catalog_document: dict[str, Any]) -> dict[str, Any]:
    service_levels = _service_level_records(evidence)
    services = [_service_record(service, service_levels) for service in catalog_document.get("services", [])]
    failed = [service for service in services if service["status"] == "fail"]
    warnings = [service for service in services if service["status"] == "warn"]
    passing = [service for service in services if service["status"] == "pass"]
    missing = [service for service in services if service["evidence_status"] == "missing"]
    status = "fail" if failed else "warn" if warnings else "pass"
    metadata = catalog_document.get("metadata", {}) if isinstance(catalog_document.get("metadata"), dict) else {}
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
            "catalog_name": metadata.get("name", ""),
            "catalog_owner": metadata.get("owner", ""),
        },
        "summary": {
            "status": status,
            "services_total": len(services),
            "services_passed": len(passing),
            "services_warn": len(warnings),
            "services_failed": len(failed),
            "services_missing_evidence": len(missing),
            "critical_services": len([service for service in services if service["criticality"] == "critical"]),
            "high_services": len([service for service in services if service["criticality"] == "high"]),
        },
        "services": services,
    }


def render_service_level_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Service Level Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Catalog: {escape_markdown_text(metadata.get('catalog_name') or '-')}",
        f"- Owner: {escape_markdown_text(metadata.get('catalog_owner') or '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Services: **{escape_markdown_text(summary.get('services_total', 0))}**",
        f"- Below target: **{escape_markdown_text(summary.get('services_failed', 0))}**",
        f"- Missing evidence: **{escape_markdown_text(summary.get('services_missing_evidence', 0))}**",
        "",
        "## Services",
        "",
    ]
    services = report.get("services", [])
    if not services:
        lines.extend(["No services were declared.", ""])
    else:
        lines.extend(
            [
                "| Service | Owner | Criticality | Status | Target | Observed | Window | Error Budget | Reason |",
                "| --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |",
            ]
        )
        for service in services:
            lines.append(
                "| "
                f"{format_markdown_code(service.get('id', ''))} {escape_markdown_text(service.get('name') or '')} | "
                f"{escape_markdown_text(service.get('owner') or '-')} | "
                f"{escape_markdown_text(service.get('criticality') or '-')} | "
                f"{escape_markdown_text(service.get('status') or '-')} | "
                f"{escape_markdown_text(_percent(service.get('target_percent')))} | "
                f"{escape_markdown_text(_percent(service.get('observed_percent')))} | "
                f"{escape_markdown_text(service.get('window') or '-')} | "
                f"{escape_markdown_text(_percent(service.get('error_budget_remaining_percent')))} | "
                f"{escape_markdown_text(service.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Evidence Shape",
            "",
            "Service-level evidence is read from `signals.monitoring.service_levels`.",
            "",
            "## Interpretation",
            "",
            "- `pass`: service-level evidence exists and observed availability meets or exceeds the target.",
            "- `warn`: service-level evidence is missing, invalid, or intentionally not configured for a lower-criticality service.",
            "- `fail`: observed availability is below the configured or default target.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_service_level_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "name",
            "owner",
            "criticality",
            "status",
            "evidence_status",
            "target_percent",
            "observed_percent",
            "window",
            "error_budget_remaining_percent",
            "reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for service in report.get("services", []):
        writer.writerow(
            {
                "id": service.get("id", ""),
                "name": service.get("name", ""),
                "owner": service.get("owner", ""),
                "criticality": service.get("criticality", ""),
                "status": service.get("status", ""),
                "evidence_status": service.get("evidence_status", ""),
                "target_percent": service.get("target_percent", ""),
                "observed_percent": service.get("observed_percent", ""),
                "window": service.get("window", ""),
                "error_budget_remaining_percent": service.get("error_budget_remaining_percent", ""),
                "reason": service.get("reason", ""),
                "recommended_action": service.get("recommended_action", ""),
            }
        )
    return output.getvalue()


def _service_record(service: dict[str, Any], service_levels: dict[str, dict[str, Any]]) -> dict[str, Any]:
    service_id = str(service.get("id", ""))
    criticality = str(service.get("criticality") or "medium")
    target = _target_percent(service, criticality)
    evidence = service_levels.get(service_id)
    if evidence is None:
        status = "warn"
        evidence_status = "missing"
        observed = None
        window = ""
        error_budget = None
        reason = "No service-level evidence was recorded for this service."
        action = "Add signals.monitoring.service_levels evidence for this service."
    else:
        observed = _number(evidence.get("uptime_percent") or evidence.get("availability_percent") or evidence.get("slo_percent"))
        window = str(evidence.get("window") or evidence.get("period") or "")
        error_budget = _number(evidence.get("error_budget_remaining_percent"))
        evidence_status = "present" if observed is not None else "invalid"
        if observed is None:
            status = "warn"
            reason = "Service-level evidence exists but no numeric uptime or availability percent was found."
            action = "Record uptime_percent, availability_percent, or slo_percent as a number from 0 to 100."
        elif observed < target:
            status = "fail"
            reason = f"Observed availability {observed:g}% is below target {target:g}%."
            action = "Review incidents, error budget burn, and remediation ownership for this service."
        else:
            status = "pass"
            reason = f"Observed availability {observed:g}% meets target {target:g}%."
            action = "Keep service-level evidence current for the next review."
    return {
        "id": service_id,
        "name": str(service.get("name", "")),
        "owner": str(service.get("owner", "")),
        "criticality": criticality,
        "status": status,
        "evidence_status": evidence_status,
        "target_percent": target,
        "observed_percent": observed,
        "window": window,
        "error_budget_remaining_percent": error_budget,
        "reason": reason,
        "recommended_action": action,
    }


def _service_level_records(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    monitoring = evidence.get("signals", {}).get("monitoring") if isinstance(evidence.get("signals"), dict) else None
    if not isinstance(monitoring, dict):
        return {}
    raw = monitoring.get("service_levels") or monitoring.get("slos") or monitoring.get("service_slos")
    if not isinstance(raw, list):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        service_id = item.get("service_id") or item.get("id") or item.get("service")
        if isinstance(service_id, str) and service_id:
            records[service_id] = item
    return records


def _target_percent(service: dict[str, Any], criticality: str) -> float:
    explicit = _number(
        service.get("slo_target_percent")
        or service.get("availability_target_percent")
        or service.get("target_percent")
    )
    if explicit is not None:
        return explicit
    return DEFAULT_SLO_TARGETS.get(criticality, DEFAULT_SLO_TARGETS["medium"])


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric if 0 <= numeric <= 100 else None
    return None


def _percent(value: Any) -> str:
    return "-" if value is None else f"{float(value):g}%"
