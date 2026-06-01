from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_evidence_inventory(evidence: dict[str, Any]) -> dict[str, Any]:
    assets = [_inventory_asset(asset) for asset in evidence.get("assets", []) if isinstance(asset, dict)]
    signals = [_signal_domain(name, value) for name, value in sorted(evidence.get("signals", {}).items())]
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
            "assets_total": len(assets),
            "asset_type_count": len({asset["type"] for asset in assets}),
            "hostnames_total": len([asset for asset in assets if asset["hostname"]]),
            "role_count": len({role for asset in assets for role in asset["roles"]}),
            "tag_count": len({tag for asset in assets for tag in asset["tags"]}),
            "signal_domain_count": len(signals),
        },
        "assets": assets,
        "signal_domains": signals,
    }


def render_inventory_markdown(inventory: dict[str, Any]) -> str:
    summary = inventory.get("summary", {})
    metadata = inventory.get("metadata", {})
    lines = [
        "# OpenOps Evidence Inventory",
        "",
        f"- Generated: {format_markdown_code(inventory.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Organization: {escape_markdown_text(metadata.get('organization') or '-')}",
        f"- Environment: {escape_markdown_text(metadata.get('environment') or '-')}",
        f"- Assets: **{escape_markdown_text(summary.get('assets_total', 0))}**",
        f"- Signal domains: **{escape_markdown_text(summary.get('signal_domain_count', 0))}**",
        "",
        "## Assets",
        "",
    ]
    assets = inventory.get("assets", [])
    if not assets:
        lines.extend(["No assets were recorded.", ""])
    else:
        lines.extend(
            [
                "| ID | Type | Hostname | Roles | Tags |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for asset in assets:
            lines.append(
                "| "
                f"{format_markdown_code(asset.get('id', ''))} | "
                f"{escape_markdown_text(asset.get('type', ''))} | "
                f"{escape_markdown_text(asset.get('hostname', '') or '-')} | "
                f"{escape_markdown_text(_join(asset.get('roles', [])) or '-')} | "
                f"{escape_markdown_text(_join(asset.get('tags', [])) or '-')} |"
            )
        lines.append("")
    lines.extend(["## Signal Domains", ""])
    signals = inventory.get("signal_domains", [])
    if not signals:
        lines.extend(["No signal domains were recorded.", ""])
    else:
        lines.extend(
            [
                "| Domain | Kind | Items | Fields |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for signal in signals:
            lines.append(
                "| "
                f"{format_markdown_code(signal.get('name', ''))} | "
                f"{escape_markdown_text(signal.get('kind', ''))} | "
                f"{signal.get('item_count', 0)} | "
                f"{escape_markdown_text(_join(signal.get('fields', [])) or '-')} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_inventory_csv(inventory: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "type",
            "hostname",
            "roles",
            "tags",
            "signal_kind",
            "item_count",
            "fields",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for asset in inventory.get("assets", []):
        writer.writerow(
            {
                "record_type": "asset",
                "id": asset.get("id", ""),
                "type": asset.get("type", ""),
                "hostname": asset.get("hostname", ""),
                "roles": _join(asset.get("roles", [])),
                "tags": _join(asset.get("tags", [])),
                "signal_kind": "",
                "item_count": "",
                "fields": "",
            }
        )
    for signal in inventory.get("signal_domains", []):
        writer.writerow(
            {
                "record_type": "signal",
                "id": signal.get("name", ""),
                "type": "",
                "hostname": "",
                "roles": "",
                "tags": "",
                "signal_kind": signal.get("kind", ""),
                "item_count": signal.get("item_count", 0),
                "fields": _join(signal.get("fields", [])),
            }
        )
    return output.getvalue()


def _inventory_asset(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(asset.get("id", "")),
        "type": str(asset.get("type", "")),
        "hostname": str(asset.get("hostname", "")),
        "roles": _string_list(asset.get("roles", [])),
        "tags": _string_list(asset.get("tags", [])),
    }


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
    return {
        "name": str(name),
        "kind": kind,
        "item_count": item_count,
        "fields": fields,
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _join(value: list[str]) -> str:
    return ", ".join(value)
