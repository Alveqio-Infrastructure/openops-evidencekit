from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


INCIDENT_RUNBOOK_KEYWORDS = ("incident", "escalation", "outage", "sev", "major-incident")
HIGH_IMPACT = {"critical", "high"}


def create_incident_report(
    evidence: dict[str, Any],
    *,
    catalog_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runbooks = _runbooks(evidence)
    incident_runbooks = [runbook for runbook in runbooks if _looks_like_incident_runbook(runbook.get("name", ""))]
    services = _service_records(catalog_document, incident_runbooks)
    missing_high_impact_contacts = [
        service for service in services if service["criticality"] in HIGH_IMPACT and service["contacts_total"] == 0
    ]
    missing_high_impact_incident_runbooks = [
        service for service in services if service["criticality"] in HIGH_IMPACT and not service["incident_runbooks"]
    ]
    checks = [
        _incident_runbook_check(incident_runbooks),
        _service_contacts_check(services, missing_high_impact_contacts),
        _service_incident_runbook_check(services, missing_high_impact_incident_runbooks),
        _alert_channels_check(evidence),
        _restore_drill_check(evidence),
        _controlled_access_check(evidence),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
    catalog_metadata = catalog_document.get("metadata", {}) if isinstance(catalog_document, dict) else {}
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
            "catalog_name": catalog_metadata.get("name", ""),
            "catalog_owner": catalog_metadata.get("owner", ""),
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "incident_runbooks_total": len(incident_runbooks),
            "services_total": len(services),
            "critical_services": len([service for service in services if service["criticality"] == "critical"]),
            "high_services": len([service for service in services if service["criticality"] == "high"]),
            "services_missing_contacts": len([service for service in services if service["contacts_total"] == 0]),
            "high_impact_services_missing_contacts": len(missing_high_impact_contacts),
            "high_impact_services_missing_incident_runbooks": len(missing_high_impact_incident_runbooks),
            "alert_channels_total": len(_alert_channels(evidence)),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "services": services,
        "incident_runbooks": incident_runbooks,
    }


def render_incident_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Incident Readiness Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Catalog: {escape_markdown_text(metadata.get('catalog_name') or '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Incident runbooks: **{escape_markdown_text(summary.get('incident_runbooks_total', 0))}**",
        f"- Services: **{escape_markdown_text(summary.get('services_total', 0))}**",
        f"- High-impact services missing contacts: **{escape_markdown_text(summary.get('high_impact_services_missing_contacts', 0))}**",
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
    lines.extend(["", "## Services", ""])
    services = report.get("services", [])
    if not services:
        lines.extend(["No service catalog was provided.", ""])
    else:
        lines.extend(
            [
                "| Service | Owner | Criticality | Contacts | Incident runbooks | Status | Reason |",
                "| --- | --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for service in services:
            lines.append(
                "| "
                f"{format_markdown_code(service.get('id') or '-')} {escape_markdown_text(service.get('name') or '')} | "
                f"{escape_markdown_text(service.get('owner') or '-')} | "
                f"{escape_markdown_text(service.get('criticality') or '-')} | "
                f"{escape_markdown_text(service.get('contacts_total', 0))} | "
                f"{escape_markdown_text(_join(service.get('incident_runbooks', [])) or '-')} | "
                f"{escape_markdown_text(service.get('status') or '-')} | "
                f"{escape_markdown_text(service.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(["## Incident Runbooks", ""])
    incident_runbooks = report.get("incident_runbooks", [])
    if not incident_runbooks:
        lines.extend(["No incident or escalation runbook evidence was found.", ""])
    else:
        lines.extend(["| Runbook | Path | Updated |", "| --- | --- | --- |"])
        for runbook in incident_runbooks:
            lines.append(
                "| "
                f"{format_markdown_code(runbook.get('name') or '-')} | "
                f"{escape_markdown_text(runbook.get('path') or '-')} | "
                f"{format_markdown_code(runbook.get('updated_at') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: incident runbooks, service contacts, alerts, restore proof, and controlled admin access are present.",
            "- `warn`: catalog or supporting evidence is incomplete and needs reviewer confirmation.",
            "- `fail`: high-impact services lack contacts or incident runbooks, alerts are unroutable, restore proof is missing, or access is unsafe.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_incident_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "name",
            "owner",
            "criticality",
            "status",
            "severity",
            "path",
            "contacts_total",
            "incident_runbooks",
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
                "owner": "",
                "criticality": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "contacts_total": "",
                "incident_runbooks": "",
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for service in report.get("services", []):
        writer.writerow(
            {
                "record_type": "service",
                "id": service.get("id", ""),
                "title": "",
                "name": service.get("name", ""),
                "owner": service.get("owner", ""),
                "criticality": service.get("criticality", ""),
                "status": service.get("status", ""),
                "severity": "",
                "path": "catalog.services",
                "contacts_total": service.get("contacts_total", ""),
                "incident_runbooks": _join(service.get("incident_runbooks", [])),
                "reason": service.get("reason", ""),
                "recommended_action": "",
            }
        )
    return output.getvalue()


def _runbooks(evidence: dict[str, Any]) -> list[dict[str, str]]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return []
    docs = signals.get("docs")
    if not isinstance(docs, dict):
        return []
    runbooks = docs.get("runbooks")
    if not isinstance(runbooks, list):
        return []
    records = []
    for runbook in runbooks:
        if not isinstance(runbook, dict):
            continue
        name = runbook.get("name")
        if isinstance(name, str) and name:
            records.append(
                {
                    "name": name,
                    "path": str(runbook.get("path") or ""),
                    "updated_at": str(runbook.get("updated_at") or ""),
                }
            )
    return records


def _service_records(catalog_document: dict[str, Any] | None, incident_runbooks: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not isinstance(catalog_document, dict) or not isinstance(catalog_document.get("services"), list):
        return []
    incident_names = {runbook["name"] for runbook in incident_runbooks}
    services = []
    for service in catalog_document["services"]:
        if not isinstance(service, dict):
            continue
        runbooks = _string_list(service.get("runbooks", []))
        matching_runbooks = [runbook for runbook in runbooks if runbook in incident_names or _looks_like_incident_runbook(runbook)]
        contacts = _string_list(service.get("contacts", []))
        criticality = str(service.get("criticality") or "medium")
        if criticality in HIGH_IMPACT and not contacts:
            status = "fail"
            reason = "High-impact service has no escalation contact."
        elif criticality in HIGH_IMPACT and not matching_runbooks:
            status = "fail"
            reason = "High-impact service has no incident or escalation runbook."
        elif not contacts or not matching_runbooks:
            status = "warn"
            reason = "Service incident response metadata is incomplete."
        else:
            status = "pass"
            reason = "Service has contacts and incident response runbook references."
        services.append(
            {
                "id": str(service.get("id") or ""),
                "name": str(service.get("name") or ""),
                "owner": str(service.get("owner") or ""),
                "criticality": criticality,
                "contacts_total": len(contacts),
                "contacts": contacts,
                "incident_runbooks": matching_runbooks,
                "status": status,
                "reason": reason,
            }
        )
    return services


def _incident_runbook_check(incident_runbooks: list[dict[str, str]]) -> dict[str, Any]:
    return _check(
        "incident_runbook_present",
        "Incident response runbook is present",
        "pass" if incident_runbooks else "fail",
        "critical",
        "signals.docs.runbooks",
        f"{len(incident_runbooks)} incident runbook(s) found." if incident_runbooks else "No incident or escalation runbook was found.",
        "Record an incident or escalation runbook in signals.docs.runbooks.",
    )


def _service_contacts_check(services: list[dict[str, Any]], missing_high_impact_contacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not services:
        return _check(
            "service_contacts_recorded",
            "Service escalation contacts are recorded",
            "warn",
            "medium",
            "catalog.services[*].contacts",
            "No service catalog was provided.",
            "Provide a service catalog with owner and escalation contact metadata.",
        )
    if missing_high_impact_contacts:
        status = "fail"
        reason = f"{len(missing_high_impact_contacts)} high-impact service(s) lack escalation contacts."
    else:
        missing_any = [service for service in services if service["contacts_total"] == 0]
        status = "warn" if missing_any else "pass"
        reason = f"{len(missing_any)} service(s) lack contacts." if missing_any else "Service contacts are recorded."
    return _check(
        "service_contacts_recorded",
        "Service escalation contacts are recorded",
        status,
        "high",
        "catalog.services[*].contacts",
        reason,
        "Record escalation contacts for each service, especially critical and high-impact services.",
    )


def _service_incident_runbook_check(services: list[dict[str, Any]], missing_high_impact: list[dict[str, Any]]) -> dict[str, Any]:
    if not services:
        return _check(
            "service_incident_runbooks_recorded",
            "Services reference incident runbooks",
            "warn",
            "medium",
            "catalog.services[*].runbooks",
            "No service catalog was provided.",
            "Reference incident or escalation runbooks from cataloged services.",
        )
    if missing_high_impact:
        status = "fail"
        reason = f"{len(missing_high_impact)} high-impact service(s) lack incident runbook references."
    else:
        missing_any = [service for service in services if not service["incident_runbooks"]]
        status = "warn" if missing_any else "pass"
        reason = f"{len(missing_any)} service(s) lack incident runbook references." if missing_any else "Services reference incident runbooks."
    return _check(
        "service_incident_runbooks_recorded",
        "Services reference incident runbooks",
        status,
        "high",
        "catalog.services[*].runbooks",
        reason,
        "Reference incident, escalation, outage, or major-incident runbooks from each high-impact service.",
    )


def _alert_channels_check(evidence: dict[str, Any]) -> dict[str, Any]:
    channels = _alert_channels(evidence)
    return _check(
        "alert_channels_recorded",
        "Alert channels are recorded",
        "pass" if channels else "fail",
        "critical",
        "signals.monitoring.alert_channels",
        f"Alert channels recorded: {', '.join(channels)}." if channels else "No alert channels were recorded.",
        "Record at least one alert channel so incidents can reach responders.",
    )


def _restore_drill_check(evidence: dict[str, Any]) -> dict[str, Any]:
    backup = _backup_signal(evidence)
    restore_tests = backup.get("restore_tests") if backup else None
    single_restore = backup.get("restore_test_at") if backup else None
    recorded = (isinstance(restore_tests, list) and bool(restore_tests)) or isinstance(single_restore, str)
    return _check(
        "restore_drill_recorded",
        "Restore drill evidence is recorded",
        "pass" if recorded else "fail",
        "high",
        "signals.backup.restore_test_at",
        "Restore drill evidence is recorded." if recorded else "No restore drill evidence was recorded.",
        "Run and record a restore drill so incident recovery is demonstrable.",
    )


def _controlled_access_check(evidence: dict[str, Any]) -> dict[str, Any]:
    access = _access_signal(evidence)
    ssh_public = access.get("ssh_public_exposed")
    mfa_required = access.get("mfa_required")
    if ssh_public is False and mfa_required is True:
        status = "pass"
        reason = "Administrative access is recorded as private and MFA-protected."
    elif ssh_public is True or mfa_required is False:
        status = "fail"
        reason = "Administrative access is public or lacks MFA."
    else:
        status = "warn"
        reason = "Administrative access evidence is incomplete."
    return _check(
        "controlled_admin_access",
        "Incident responders use controlled admin access",
        status,
        "high",
        "signals.access",
        reason,
        "Keep emergency administration behind controlled access and MFA.",
    )


def _alert_channels(evidence: dict[str, Any]) -> list[str]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return []
    monitoring = signals.get("monitoring")
    if not isinstance(monitoring, dict):
        return []
    channels = monitoring.get("alert_channels")
    if not isinstance(channels, list):
        return []
    return [str(channel) for channel in channels if isinstance(channel, str) and channel]


def _backup_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    backup = signals.get("backup")
    return backup if isinstance(backup, dict) else {}


def _access_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    access = signals.get("access")
    return access if isinstance(access, dict) else {}


def _looks_like_incident_runbook(name: str) -> bool:
    normalized = name.strip().lower().replace("_", "-").replace(" ", "-")
    return any(keyword in normalized for keyword in INCIDENT_RUNBOOK_KEYWORDS)


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
    return [str(item) for item in value if isinstance(item, str) and item]


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values)
