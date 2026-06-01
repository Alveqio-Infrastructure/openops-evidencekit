from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


CRITICALITIES = {"critical", "high", "medium", "low"}


def validate_catalog_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Service catalog must be a table/object."]
    metadata = document.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be a table/object when present.")
    services = document.get("services")
    if not isinstance(services, list):
        errors.append("services must be a list.")
        return errors
    if not services:
        errors.append("services must contain at least one service.")
    seen: set[str] = set()
    for index, service in enumerate(services):
        prefix = f"services[{index}]"
        if not isinstance(service, dict):
            errors.append(f"{prefix} must be a table/object.")
            continue
        service_id = service.get("id")
        if not isinstance(service_id, str) or not service_id:
            errors.append(f"{prefix}.id must be a non-empty string.")
        elif service_id in seen:
            errors.append(f"{prefix}.id duplicates another services entry: {service_id}")
        else:
            seen.add(service_id)
        for key in ("name", "owner"):
            if not isinstance(service.get(key), str) or not service.get(key):
                errors.append(f"{prefix}.{key} must be a non-empty string.")
        criticality = service.get("criticality", "medium")
        if criticality not in CRITICALITIES:
            errors.append(f"{prefix}.criticality must be one of: critical, high, low, medium.")
        coverage_lists = []
        for key in ("assets", "domains", "runbooks", "contacts"):
            value = service.get(key, [])
            if not isinstance(value, list):
                errors.append(f"{prefix}.{key} must be a list when present.")
                continue
            if any(not isinstance(item, str) or not item for item in value):
                errors.append(f"{prefix}.{key} must contain only non-empty strings.")
            if key != "contacts":
                coverage_lists.extend(value)
        if not coverage_lists:
            errors.append(f"{prefix} must declare at least one asset, domain, or runbook.")
    return errors


def create_service_catalog_report(evidence: dict[str, Any], catalog_document: dict[str, Any]) -> dict[str, Any]:
    services = [_service_record(service, evidence) for service in catalog_document.get("services", [])]
    evidence_assets = _asset_records(evidence)
    catalog_asset_ids = {asset_id for service in services for asset_id in service["assets"]}
    unassigned_assets = [
        _asset_summary(asset)
        for asset_id, asset in sorted(evidence_assets.items())
        if asset_id not in catalog_asset_ids
    ]
    services_warn = [service for service in services if service["status"] == "warn"]
    missing_catalog_assets = {asset_id for service in services for asset_id in service["missing_assets"]}
    missing_domains = {domain for service in services for domain in service["missing_domains"]}
    missing_runbooks = {runbook for service in services for runbook in service["missing_runbooks"]}
    status = "warn" if services_warn or unassigned_assets else "pass"
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
            "services_passed": len([service for service in services if service["status"] == "pass"]),
            "services_warn": len(services_warn),
            "critical_services": len([service for service in services if service["criticality"] == "critical"]),
            "high_services": len([service for service in services if service["criticality"] == "high"]),
            "catalog_assets_total": len(catalog_asset_ids),
            "evidence_assets_total": len(evidence_assets),
            "missing_catalog_assets_count": len(missing_catalog_assets),
            "unassigned_evidence_assets_count": len(unassigned_assets),
            "missing_domains_count": len(missing_domains),
            "missing_runbooks_count": len(missing_runbooks),
        },
        "services": services,
        "unassigned_assets": unassigned_assets,
    }


def render_service_catalog_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Service Catalog Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Catalog: {escape_markdown_text(metadata.get('catalog_name') or '-')}",
        f"- Owner: {escape_markdown_text(metadata.get('catalog_owner') or '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Services: **{escape_markdown_text(summary.get('services_total', 0))}**",
        f"- Services with gaps: **{escape_markdown_text(summary.get('services_warn', 0))}**",
        f"- Missing catalog assets: **{escape_markdown_text(summary.get('missing_catalog_assets_count', 0))}**",
        f"- Unassigned evidence assets: **{escape_markdown_text(summary.get('unassigned_evidence_assets_count', 0))}**",
        f"- Missing domains: **{escape_markdown_text(summary.get('missing_domains_count', 0))}**",
        f"- Missing runbooks: **{escape_markdown_text(summary.get('missing_runbooks_count', 0))}**",
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
                "| Service | Owner | Criticality | Status | Assets | Domains | Runbooks | Gaps |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for service in services:
            gaps = _gap_summary(service)
            lines.append(
                "| "
                f"{format_markdown_code(service.get('id', ''))} {escape_markdown_text(service.get('name') or '')} | "
                f"{escape_markdown_text(service.get('owner') or '-')} | "
                f"{escape_markdown_text(service.get('criticality') or '-')} | "
                f"{escape_markdown_text(service.get('status') or '-')} | "
                f"{escape_markdown_text(_join(service.get('assets', [])) or '-')} | "
                f"{escape_markdown_text(_join(service.get('domains', [])) or '-')} | "
                f"{escape_markdown_text(_join(service.get('runbooks', [])) or '-')} | "
                f"{escape_markdown_text(gaps or '-')} |"
            )
        lines.append("")
    lines.extend(["## Unassigned Evidence Assets", ""])
    unassigned = report.get("unassigned_assets", [])
    if not unassigned:
        lines.extend(["No evidence assets were left unassigned.", ""])
    else:
        lines.extend(["| Asset | Type | Hostname | Roles | Tags |", "| --- | --- | --- | --- | --- |"])
        for asset in unassigned:
            lines.append(
                "| "
                f"{format_markdown_code(asset.get('id', ''))} | "
                f"{escape_markdown_text(asset.get('type') or '-')} | "
                f"{escape_markdown_text(asset.get('hostname') or '-')} | "
                f"{escape_markdown_text(_join(asset.get('roles', [])) or '-')} | "
                f"{escape_markdown_text(_join(asset.get('tags', [])) or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: every declared asset, evidence domain, and runbook for the service was found.",
            "- `warn`: at least one declared asset, evidence domain, or runbook is missing.",
            "- Unassigned evidence assets are collected assets that no catalog service owns yet.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_service_catalog_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "name",
            "owner",
            "criticality",
            "status",
            "assets",
            "present_assets",
            "missing_assets",
            "domains",
            "present_domains",
            "missing_domains",
            "runbooks",
            "present_runbooks",
            "missing_runbooks",
            "contacts",
            "type",
            "hostname",
            "roles",
            "tags",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for service in report.get("services", []):
        writer.writerow(
            {
                "record_type": "service",
                "id": service.get("id", ""),
                "name": service.get("name", ""),
                "owner": service.get("owner", ""),
                "criticality": service.get("criticality", ""),
                "status": service.get("status", ""),
                "assets": _join(service.get("assets", [])),
                "present_assets": _join(service.get("present_assets", [])),
                "missing_assets": _join(service.get("missing_assets", [])),
                "domains": _join(service.get("domains", [])),
                "present_domains": _join(service.get("present_domains", [])),
                "missing_domains": _join(service.get("missing_domains", [])),
                "runbooks": _join(service.get("runbooks", [])),
                "present_runbooks": _join(service.get("present_runbooks", [])),
                "missing_runbooks": _join(service.get("missing_runbooks", [])),
                "contacts": _join(service.get("contacts", [])),
                "type": "",
                "hostname": "",
                "roles": "",
                "tags": "",
            }
        )
    for asset in report.get("unassigned_assets", []):
        writer.writerow(
            {
                "record_type": "unassigned_asset",
                "id": asset.get("id", ""),
                "name": "",
                "owner": "",
                "criticality": "",
                "status": "unassigned",
                "assets": "",
                "present_assets": "",
                "missing_assets": "",
                "domains": "",
                "present_domains": "",
                "missing_domains": "",
                "runbooks": "",
                "present_runbooks": "",
                "missing_runbooks": "",
                "contacts": "",
                "type": asset.get("type", ""),
                "hostname": asset.get("hostname", ""),
                "roles": _join(asset.get("roles", [])),
                "tags": _join(asset.get("tags", [])),
            }
        )
    return output.getvalue()


def _service_record(service: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    evidence_assets = _asset_records(evidence)
    evidence_domains = _signal_domains(evidence)
    runbooks = _runbook_names(evidence)
    assets = _string_list(service.get("assets", []))
    domains = [_clean_name(item) for item in _string_list(service.get("domains", []))]
    expected_runbooks = _string_list(service.get("runbooks", []))
    missing_assets = [asset_id for asset_id in assets if asset_id not in evidence_assets]
    missing_domains = [domain for domain in domains if domain not in evidence_domains]
    missing_runbooks = [runbook for runbook in expected_runbooks if runbook not in runbooks]
    return {
        "id": str(service.get("id", "")),
        "name": str(service.get("name", "")),
        "owner": str(service.get("owner", "")),
        "criticality": str(service.get("criticality", "medium")),
        "status": "warn" if missing_assets or missing_domains or missing_runbooks else "pass",
        "contacts": _string_list(service.get("contacts", [])),
        "assets": assets,
        "present_assets": [asset_id for asset_id in assets if asset_id in evidence_assets],
        "missing_assets": missing_assets,
        "domains": domains,
        "present_domains": [domain for domain in domains if domain in evidence_domains],
        "missing_domains": missing_domains,
        "runbooks": expected_runbooks,
        "present_runbooks": [runbook for runbook in expected_runbooks if runbook in runbooks],
        "missing_runbooks": missing_runbooks,
    }


def _asset_records(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(asset.get("id", "")): asset
        for asset in evidence.get("assets", [])
        if isinstance(asset, dict) and str(asset.get("id", ""))
    }


def _asset_summary(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(asset.get("id", "")),
        "type": str(asset.get("type", "")),
        "hostname": str(asset.get("hostname", "")),
        "roles": _string_list(asset.get("roles", [])),
        "tags": _string_list(asset.get("tags", [])),
    }


def _signal_domains(evidence: dict[str, Any]) -> set[str]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return set()
    return {_clean_name(str(name)) for name in signals.keys()}


def _runbook_names(evidence: dict[str, Any]) -> set[str]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return set()
    docs = signals.get("docs")
    if not isinstance(docs, dict):
        return set()
    runbooks = docs.get("runbooks")
    if not isinstance(runbooks, list):
        return set()
    names = set()
    for runbook in runbooks:
        if isinstance(runbook, dict) and isinstance(runbook.get("name"), str) and runbook["name"]:
            names.add(runbook["name"])
    return names


def _gap_summary(service: dict[str, Any]) -> str:
    parts = []
    if service.get("missing_assets"):
        parts.append(f"missing assets: {_join(service['missing_assets'])}")
    if service.get("missing_domains"):
        parts.append(f"missing domains: {_join(service['missing_domains'])}")
    if service.get("missing_runbooks"):
        parts.append(f"missing runbooks: {_join(service['missing_runbooks'])}")
    return "; ".join(parts)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _clean_name(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_")


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values)
