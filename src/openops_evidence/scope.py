from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SCOPE_STATUSES = {"in_scope", "out_of_scope"}
RECORD_STATUSES = {
    "present_in_scope",
    "present_out_of_scope",
    "missing_in_scope",
    "missing_optional",
    "out_of_scope_not_seen",
    "unclassified_evidence",
}


def validate_scope_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Scope must be a table/object."]
    metadata = document.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be a table/object when present.")
    assets = document.get("assets", [])
    domains = document.get("domains", [])
    if not isinstance(assets, list):
        errors.append("assets must be a list when present.")
        assets = []
    if not isinstance(domains, list):
        errors.append("domains must be a list when present.")
        domains = []
    if not assets and not domains:
        errors.append("scope must declare at least one asset or domain.")
    _validate_scope_items(assets, "assets", "id", errors)
    _validate_scope_items(domains, "domains", "name", errors)
    return errors


def create_scope_report(evidence: dict[str, Any], scope_document: dict[str, Any]) -> dict[str, Any]:
    assets = _asset_records(evidence, scope_document)
    domains = _domain_records(evidence, scope_document)
    missing_assets = [asset for asset in assets if asset["status"] == "missing_in_scope"]
    unclassified_assets = [asset for asset in assets if asset["status"] == "unclassified_evidence"]
    out_of_scope_assets = [asset for asset in assets if asset["status"] == "present_out_of_scope"]
    missing_required_domains = [domain for domain in domains if domain["status"] == "missing_in_scope"]
    unclassified_domains = [domain for domain in domains if domain["status"] == "unclassified_evidence"]
    out_of_scope_domains = [domain for domain in domains if domain["status"] == "present_out_of_scope"]
    status = (
        "warn"
        if missing_assets
        or unclassified_assets
        or out_of_scope_assets
        or missing_required_domains
        or unclassified_domains
        or out_of_scope_domains
        else "pass"
    )
    declared_assets = [asset for asset in assets if asset["declared"]]
    declared_domains = [domain for domain in domains if domain["declared"]]
    metadata = scope_document.get("metadata", {}) if isinstance(scope_document.get("metadata"), dict) else {}
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
            "scope_name": metadata.get("name", ""),
            "scope_owner": metadata.get("owner", ""),
        },
        "summary": {
            "status": status,
            "assets_declared": len(declared_assets),
            "evidence_assets": len([asset for asset in assets if asset["present"]]),
            "in_scope_assets": len([asset for asset in declared_assets if asset["scope_status"] == "in_scope"]),
            "out_of_scope_assets": len([asset for asset in declared_assets if asset["scope_status"] == "out_of_scope"]),
            "missing_in_scope_assets": len(missing_assets),
            "unclassified_evidence_assets": len(unclassified_assets),
            "out_of_scope_evidence_assets": len(out_of_scope_assets),
            "domains_declared": len(declared_domains),
            "evidence_domains": len([domain for domain in domains if domain["present"]]),
            "in_scope_domains": len([domain for domain in declared_domains if domain["scope_status"] == "in_scope"]),
            "out_of_scope_domains": len([domain for domain in declared_domains if domain["scope_status"] == "out_of_scope"]),
            "missing_required_domains": len(missing_required_domains),
            "unclassified_evidence_domains": len(unclassified_domains),
            "out_of_scope_evidence_domains": len(out_of_scope_domains),
        },
        "assets": assets,
        "domains": domains,
    }


def render_scope_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Scope Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Scope: {escape_markdown_text(metadata.get('scope_name') or '-')}",
        f"- Owner: {escape_markdown_text(metadata.get('scope_owner') or '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Missing in-scope assets: **{escape_markdown_text(summary.get('missing_in_scope_assets', 0))}**",
        f"- Unclassified evidence assets: **{escape_markdown_text(summary.get('unclassified_evidence_assets', 0))}**",
        f"- Missing required domains: **{escape_markdown_text(summary.get('missing_required_domains', 0))}**",
        f"- Unclassified evidence domains: **{escape_markdown_text(summary.get('unclassified_evidence_domains', 0))}**",
        "",
        "## Assets",
        "",
    ]
    assets = report.get("assets", [])
    if not assets:
        lines.extend(["No assets were declared or found in evidence.", ""])
    else:
        lines.extend(
            [
                "| Asset | Scope | Status | Type | Hostname | Owner | Reason |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for asset in assets:
            lines.append(
                "| "
                f"{format_markdown_code(asset.get('id', ''))} | "
                f"{escape_markdown_text(asset.get('scope_status', ''))} | "
                f"{escape_markdown_text(asset.get('status', ''))} | "
                f"{escape_markdown_text(asset.get('type') or '-')} | "
                f"{escape_markdown_text(asset.get('hostname') or '-')} | "
                f"{escape_markdown_text(asset.get('owner') or '-')} | "
                f"{escape_markdown_text(asset.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(["## Evidence Domains", ""])
    domains = report.get("domains", [])
    if not domains:
        lines.extend(["No evidence domains were declared or found.", ""])
    else:
        lines.extend(
            [
                "| Domain | Scope | Required | Status | Kind | Items | Fields | Reason |",
                "| --- | --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for domain in domains:
            lines.append(
                "| "
                f"{format_markdown_code(domain.get('name', ''))} | "
                f"{escape_markdown_text(domain.get('scope_status', ''))} | "
                f"{format_markdown_code(str(bool(domain.get('required'))).lower())} | "
                f"{escape_markdown_text(domain.get('status', ''))} | "
                f"{escape_markdown_text(domain.get('kind') or '-')} | "
                f"{escape_markdown_text(domain.get('item_count', 0))} | "
                f"{escape_markdown_text(_join(domain.get('fields', [])) or '-')} | "
                f"{escape_markdown_text(domain.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `present_in_scope`: evidence exists and the scope declares it as included.",
            "- `present_out_of_scope`: evidence exists even though the scope declares it as excluded.",
            "- `missing_in_scope`: scope declares it as included and required, but evidence is missing.",
            "- `unclassified_evidence`: evidence exists without a matching scope declaration.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_scope_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "scope_status",
            "status",
            "present",
            "declared",
            "required",
            "type",
            "hostname",
            "kind",
            "item_count",
            "fields",
            "owner",
            "reason",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for asset in report.get("assets", []):
        writer.writerow(
            {
                "record_type": "asset",
                "id": asset.get("id", ""),
                "scope_status": asset.get("scope_status", ""),
                "status": asset.get("status", ""),
                "present": asset.get("present", False),
                "declared": asset.get("declared", False),
                "required": "",
                "type": asset.get("type", ""),
                "hostname": asset.get("hostname", ""),
                "kind": "",
                "item_count": "",
                "fields": "",
                "owner": asset.get("owner", ""),
                "reason": asset.get("reason", ""),
            }
        )
    for domain in report.get("domains", []):
        writer.writerow(
            {
                "record_type": "domain",
                "id": domain.get("name", ""),
                "scope_status": domain.get("scope_status", ""),
                "status": domain.get("status", ""),
                "present": domain.get("present", False),
                "declared": domain.get("declared", False),
                "required": domain.get("required", False),
                "type": "",
                "hostname": "",
                "kind": domain.get("kind", ""),
                "item_count": domain.get("item_count", 0),
                "fields": _join(domain.get("fields", [])),
                "owner": domain.get("owner", ""),
                "reason": domain.get("reason", ""),
            }
        )
    return output.getvalue()


def _asset_records(evidence: dict[str, Any], scope_document: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_assets = {
        str(asset.get("id", "")): asset
        for asset in evidence.get("assets", [])
        if isinstance(asset, dict) and str(asset.get("id", ""))
    }
    declared_assets = _scope_index(scope_document.get("assets", []), "id")
    records = [
        _declared_asset_record(asset_id, item, evidence_assets.get(asset_id))
        for asset_id, item in sorted(declared_assets.items())
    ]
    for asset_id, asset in sorted(evidence_assets.items()):
        if asset_id not in declared_assets:
            records.append(_unclassified_asset_record(asset_id, asset))
    return records


def _declared_asset_record(asset_id: str, item: dict[str, Any], evidence_asset: dict[str, Any] | None) -> dict[str, Any]:
    scope_status = _scope_status(item)
    present = evidence_asset is not None
    if present:
        status = "present_in_scope" if scope_status == "in_scope" else "present_out_of_scope"
    else:
        status = "missing_in_scope" if scope_status == "in_scope" else "out_of_scope_not_seen"
    source = evidence_asset or item
    return {
        "id": asset_id,
        "scope_status": scope_status,
        "status": status,
        "present": present,
        "declared": True,
        "type": str(source.get("type", "")),
        "hostname": str(source.get("hostname", "")),
        "owner": str(item.get("owner", "")),
        "reason": str(item.get("reason", "")),
    }


def _unclassified_asset_record(asset_id: str, asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": asset_id,
        "scope_status": "unclassified",
        "status": "unclassified_evidence",
        "present": True,
        "declared": False,
        "type": str(asset.get("type", "")),
        "hostname": str(asset.get("hostname", "")),
        "owner": "",
        "reason": "",
    }


def _domain_records(evidence: dict[str, Any], scope_document: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_domains = _evidence_domains(evidence)
    declared_domains = _scope_index(scope_document.get("domains", []), "name", normalize=True)
    records = [
        _declared_domain_record(name, item, evidence_domains.get(name))
        for name, item in sorted(declared_domains.items())
    ]
    for name, domain in sorted(evidence_domains.items()):
        if name not in declared_domains:
            records.append(_unclassified_domain_record(name, domain))
    return records


def _declared_domain_record(name: str, item: dict[str, Any], evidence_domain: dict[str, Any] | None) -> dict[str, Any]:
    scope_status = _scope_status(item)
    required = bool(item.get("required", scope_status == "in_scope"))
    present = evidence_domain is not None
    if present:
        status = "present_in_scope" if scope_status == "in_scope" else "present_out_of_scope"
    elif scope_status == "out_of_scope":
        status = "out_of_scope_not_seen"
    else:
        status = "missing_in_scope" if required else "missing_optional"
    source = evidence_domain or {}
    return {
        "name": name,
        "scope_status": scope_status,
        "status": status,
        "present": present,
        "declared": True,
        "required": required,
        "kind": source.get("kind", ""),
        "item_count": source.get("item_count", 0),
        "fields": source.get("fields", []),
        "owner": str(item.get("owner", "")),
        "reason": str(item.get("reason", "")),
    }


def _unclassified_domain_record(name: str, domain: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "scope_status": "unclassified",
        "status": "unclassified_evidence",
        "present": True,
        "declared": False,
        "required": False,
        "kind": domain.get("kind", ""),
        "item_count": domain.get("item_count", 0),
        "fields": domain.get("fields", []),
        "owner": "",
        "reason": "",
    }


def _evidence_domains(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    return {_clean_name(str(name)): _signal_domain(str(name), value) for name, value in signals.items()}


def _signal_domain(name: str, value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        kind = "object"
        fields = sorted(str(key) for key in value.keys())
        item_count = len(fields)
    elif isinstance(value, list):
        kind = "array"
        fields = []
        item_count = len(value)
    else:
        kind = "scalar"
        fields = []
        item_count = 1 if value is not None else 0
    return {"name": _clean_name(name), "kind": kind, "item_count": item_count, "fields": fields}


def _scope_index(items: Any, key: str, *, normalize: bool = False) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        if not isinstance(value, str) or not value:
            continue
        indexed[_clean_name(value) if normalize else value] = item
    return indexed


def _scope_status(item: dict[str, Any]) -> str:
    value = item.get("status", "in_scope")
    return value if value in SCOPE_STATUSES else "in_scope"


def _validate_scope_items(items: list[Any], section: str, key: str, errors: list[str]) -> None:
    seen: set[str] = set()
    for index, item in enumerate(items):
        prefix = f"{section}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a table/object.")
            continue
        value = item.get(key)
        if not isinstance(value, str) or not value:
            errors.append(f"{prefix}.{key} must be a non-empty string.")
        else:
            normalized = _clean_name(value) if key == "name" else value
            if normalized in seen:
                errors.append(f"{prefix}.{key} duplicates another {section} entry: {value}")
            seen.add(normalized)
        status = item.get("status", "in_scope")
        if status not in SCOPE_STATUSES:
            errors.append(f"{prefix}.status must be one of: in_scope, out_of_scope.")
        if "required" in item and not isinstance(item["required"], bool):
            errors.append(f"{prefix}.required must be a boolean when present.")
        for optional in ("type", "hostname", "owner", "reason"):
            if optional in item and not isinstance(item[optional], str):
                errors.append(f"{prefix}.{optional} must be a string when present.")


def _clean_name(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_")


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values)
