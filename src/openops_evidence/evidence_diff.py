from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def compare_evidence(base: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    base_assets = _asset_records(base)
    current_assets = _asset_records(current)
    base_domains = _domain_records(base)
    current_domains = _domain_records(current)
    asset_changes = _compare_records(
        base_assets,
        current_assets,
        name_key="id",
        diff_keys=("type", "hostname", "roles", "tags", "sha256"),
    )
    domain_changes = _compare_records(
        base_domains,
        current_domains,
        name_key="name",
        diff_keys=("kind", "item_count", "fields", "sha256"),
    )
    status = "warn" if asset_changes or domain_changes else "pass"
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "base_generated_at": base.get("generated_at"),
            "current_generated_at": current.get("generated_at"),
            "base_source": base.get("metadata", {}).get("source", ""),
            "current_source": current.get("metadata", {}).get("source", ""),
            "base_environment": base.get("metadata", {}).get("environment", ""),
            "current_environment": current.get("metadata", {}).get("environment", ""),
        },
        "summary": {
            "status": status,
            "base_assets": len(base_assets),
            "current_assets": len(current_assets),
            "asset_changes_count": len(asset_changes),
            "asset_added_count": _count_changes(asset_changes, "added"),
            "asset_removed_count": _count_changes(asset_changes, "removed"),
            "asset_changed_count": _count_changes(asset_changes, "changed"),
            "base_domains": len(base_domains),
            "current_domains": len(current_domains),
            "domain_changes_count": len(domain_changes),
            "domain_added_count": _count_changes(domain_changes, "added"),
            "domain_removed_count": _count_changes(domain_changes, "removed"),
            "domain_changed_count": _count_changes(domain_changes, "changed"),
        },
        "asset_changes": asset_changes,
        "domain_changes": domain_changes,
    }


def render_evidence_diff_markdown(diff: dict[str, Any]) -> str:
    summary = diff.get("summary", {})
    metadata = diff.get("metadata", {})
    lines = [
        "# OpenOps Evidence Drift",
        "",
        f"- Generated: {format_markdown_code(diff.get('generated_at', 'unknown'))}",
        f"- Base evidence: {format_markdown_code(metadata.get('base_generated_at', 'unknown'))}",
        f"- Current evidence: {format_markdown_code(metadata.get('current_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Asset changes: **{escape_markdown_text(summary.get('asset_changes_count', 0))}**",
        f"- Signal domain changes: **{escape_markdown_text(summary.get('domain_changes_count', 0))}**",
        "",
    ]
    lines.extend(_asset_change_section(diff.get("asset_changes", [])))
    lines.extend(_domain_change_section(diff.get("domain_changes", [])))
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `added`: present only in current evidence.",
            "- `removed`: present only in base evidence.",
            "- `changed`: present in both files, but stable summary fields or fingerprints changed.",
            "- Signal domain fingerprints are SHA-256 hashes of canonical JSON values; raw values are not embedded in the drift report.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_evidence_diff_csv(diff: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "change_type",
            "changed_fields",
            "before_type",
            "after_type",
            "before_hostname",
            "after_hostname",
            "before_kind",
            "after_kind",
            "before_item_count",
            "after_item_count",
            "before_fields",
            "after_fields",
            "before_sha256",
            "after_sha256",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for change in diff.get("asset_changes", []):
        before = change.get("before") or {}
        after = change.get("after") or {}
        writer.writerow(
            {
                "record_type": "asset",
                "id": change.get("id", ""),
                "change_type": change.get("change_type", ""),
                "changed_fields": _join(change.get("changed_fields", [])),
                "before_type": before.get("type", ""),
                "after_type": after.get("type", ""),
                "before_hostname": before.get("hostname", ""),
                "after_hostname": after.get("hostname", ""),
                "before_kind": "",
                "after_kind": "",
                "before_item_count": "",
                "after_item_count": "",
                "before_fields": "",
                "after_fields": "",
                "before_sha256": before.get("sha256", ""),
                "after_sha256": after.get("sha256", ""),
            }
        )
    for change in diff.get("domain_changes", []):
        before = change.get("before") or {}
        after = change.get("after") or {}
        writer.writerow(
            {
                "record_type": "domain",
                "id": change.get("name", ""),
                "change_type": change.get("change_type", ""),
                "changed_fields": _join(change.get("changed_fields", [])),
                "before_type": "",
                "after_type": "",
                "before_hostname": "",
                "after_hostname": "",
                "before_kind": before.get("kind", ""),
                "after_kind": after.get("kind", ""),
                "before_item_count": before.get("item_count", ""),
                "after_item_count": after.get("item_count", ""),
                "before_fields": _join(before.get("fields", [])),
                "after_fields": _join(after.get("fields", [])),
                "before_sha256": before.get("sha256", ""),
                "after_sha256": after.get("sha256", ""),
            }
        )
    return output.getvalue()


def _compare_records(
    base: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    *,
    name_key: str,
    diff_keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    base_ids = set(base)
    current_ids = set(current)
    for item_id in sorted(current_ids - base_ids):
        changes.append(
            {
                name_key: item_id,
                "change_type": "added",
                "before": None,
                "after": current[item_id],
                "changed_fields": [],
            }
        )
    for item_id in sorted(base_ids - current_ids):
        changes.append(
            {
                name_key: item_id,
                "change_type": "removed",
                "before": base[item_id],
                "after": None,
                "changed_fields": [],
            }
        )
    for item_id in sorted(base_ids & current_ids):
        changed_fields = [key for key in diff_keys if base[item_id].get(key) != current[item_id].get(key)]
        if changed_fields:
            changes.append(
                {
                    name_key: item_id,
                    "change_type": "changed",
                    "before": base[item_id],
                    "after": current[item_id],
                    "changed_fields": ["value" if field == "sha256" else field for field in changed_fields],
                }
            )
    return changes


def _asset_records(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for asset in evidence.get("assets", []):
        if not isinstance(asset, dict):
            continue
        asset_id = str(asset.get("id", ""))
        if not asset_id:
            continue
        record = {
            "id": asset_id,
            "type": str(asset.get("type", "")),
            "hostname": str(asset.get("hostname", "")),
            "roles": _string_list(asset.get("roles", [])),
            "tags": _string_list(asset.get("tags", [])),
        }
        record["sha256"] = _sha256_json(record)
        records[asset_id] = record
    return records


def _domain_records(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    return {str(name): _domain_record(str(name), value) for name, value in signals.items()}


def _domain_record(name: str, value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        kind = "object"
        fields = sorted(str(key) for key in value)
        item_count = len(fields)
    elif isinstance(value, list):
        kind = "array"
        fields = _list_fields(value)
        item_count = len(value)
    else:
        kind = "scalar"
        fields = []
        item_count = 1 if value is not None else 0
    return {
        "name": name,
        "kind": kind,
        "item_count": item_count,
        "fields": fields,
        "sha256": _sha256_json(value),
    }


def _asset_change_section(changes: list[dict[str, Any]]) -> list[str]:
    lines = ["## Asset Changes", ""]
    if not changes:
        return [*lines, "None.", ""]
    lines.extend(
        [
            "| Asset | Change | Changed Fields | Before | After |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        before = change.get("before") or {}
        after = change.get("after") or {}
        lines.append(
            "| "
            f"{format_markdown_code(change.get('id', ''))} | "
            f"{escape_markdown_text(change.get('change_type', ''))} | "
            f"{escape_markdown_text(_join(change.get('changed_fields', [])) or '-')} | "
            f"{escape_markdown_text(_asset_label(before) or '-')} | "
            f"{escape_markdown_text(_asset_label(after) or '-')} |"
        )
    lines.append("")
    return lines


def _domain_change_section(changes: list[dict[str, Any]]) -> list[str]:
    lines = ["## Signal Domain Changes", ""]
    if not changes:
        return [*lines, "None.", ""]
    lines.extend(
        [
            "| Domain | Change | Changed Fields | Before | After |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for change in changes:
        before = change.get("before") or {}
        after = change.get("after") or {}
        lines.append(
            "| "
            f"{format_markdown_code(change.get('name', ''))} | "
            f"{escape_markdown_text(change.get('change_type', ''))} | "
            f"{escape_markdown_text(_join(change.get('changed_fields', [])) or '-')} | "
            f"{escape_markdown_text(_domain_label(before) or '-')} | "
            f"{escape_markdown_text(_domain_label(after) or '-')} |"
        )
    lines.append("")
    return lines


def _asset_label(record: dict[str, Any]) -> str:
    if not record:
        return ""
    return f"{record.get('type') or '-'} {record.get('hostname') or '-'}"


def _domain_label(record: dict[str, Any]) -> str:
    if not record:
        return ""
    fields = _join(record.get("fields", [])) or "-"
    return f"{record.get('kind') or '-'} items={record.get('item_count', 0)} fields={fields}"


def _list_fields(values: list[Any]) -> list[str]:
    fields: set[str] = set()
    for value in values:
        if isinstance(value, dict):
            fields.update(str(key) for key in value)
    return sorted(fields)


def _count_changes(changes: list[dict[str, Any]], change_type: str) -> int:
    return sum(1 for change in changes if change.get("change_type") == change_type)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(str(item) for item in value)


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _join(values: list[Any]) -> str:
    return ", ".join(str(value) for value in values)
