from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


TIMESTAMP_KEYS = {
    "checked_at",
    "created_at",
    "expires_at",
    "generated_at",
    "inventory_updated_at",
    "last_alert_test_at",
    "last_success_at",
    "not_after",
    "not_before",
    "restore_test_at",
    "updated_at",
    "valid_until",
}


def create_freshness_report(
    evidence: dict[str, Any],
    *,
    max_age_days: int | None = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    timestamps = [
        _timestamp_record(path, value, max_age_days=max_age_days, now=current_time)
        for path, value in _timestamp_values(evidence)
    ]
    stale = [item for item in timestamps if item["status"] == "stale"]
    invalid = [item for item in timestamps if item["status"] == "invalid"]
    current = [item for item in timestamps if item["status"] == "current"]
    future = [item for item in timestamps if item["status"] == "future"]
    ages = [item["age_days"] for item in timestamps if isinstance(item.get("age_days"), int)]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
            "max_age_days": max_age_days,
            "evaluated_at": current_time.isoformat(),
        },
        "summary": {
            "status": "warn" if stale or invalid else "pass",
            "timestamps_total": len(timestamps),
            "current_count": len(current),
            "stale_count": len(stale),
            "future_count": len(future),
            "invalid_count": len(invalid),
            "oldest_age_days": max(ages) if ages else None,
            "newest_age_days": min(ages) if ages else None,
        },
        "timestamps": timestamps,
    }


def render_freshness_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Evidence Freshness Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Evaluated at: {format_markdown_code(metadata.get('evaluated_at', 'unknown'))}",
        f"- Max age days: {escape_markdown_text(metadata.get('max_age_days') if metadata.get('max_age_days') is not None else '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Timestamps: **{escape_markdown_text(summary.get('timestamps_total', 0))}**",
        f"- Current: **{escape_markdown_text(summary.get('current_count', 0))}**",
        f"- Stale: **{escape_markdown_text(summary.get('stale_count', 0))}**",
        f"- Future: **{escape_markdown_text(summary.get('future_count', 0))}**",
        f"- Invalid: **{escape_markdown_text(summary.get('invalid_count', 0))}**",
        "",
        "## Timestamps",
        "",
    ]
    timestamps = report.get("timestamps", [])
    if not timestamps:
        lines.extend(["No timestamp-like evidence fields were found.", ""])
    else:
        lines.extend(
            [
                "| Path | Status | Value | Age days | Future days | Reason |",
                "| --- | --- | --- | ---: | ---: | --- |",
            ]
        )
        for item in timestamps:
            lines.append(
                "| "
                f"{format_markdown_code(item.get('path', ''))} | "
                f"{escape_markdown_text(item.get('status') or '-')} | "
                f"{format_markdown_code(item.get('value') or '-')} | "
                f"{escape_markdown_text(item.get('age_days') if item.get('age_days') is not None else '-')} | "
                f"{escape_markdown_text(item.get('future_days') if item.get('future_days') is not None else '-')} | "
                f"{escape_markdown_text(item.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `current`: timestamp is valid and no older than `max_age_days`.",
            "- `stale`: timestamp is valid but older than `max_age_days`.",
            "- `future`: timestamp is valid and lies in the future.",
            "- `invalid`: timestamp-like field exists but could not be parsed as ISO 8601.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_freshness_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "path",
            "status",
            "value",
            "age_days",
            "future_days",
            "max_age_days",
            "timestamp_valid",
            "reason",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in report.get("timestamps", []):
        writer.writerow(
            {
                "path": item.get("path", ""),
                "status": item.get("status", ""),
                "value": item.get("value", ""),
                "age_days": item.get("age_days") if item.get("age_days") is not None else "",
                "future_days": item.get("future_days") if item.get("future_days") is not None else "",
                "max_age_days": item.get("max_age_days") if item.get("max_age_days") is not None else "",
                "timestamp_valid": item.get("timestamp_valid", False),
                "reason": item.get("reason", ""),
            }
        )
    return output.getvalue()


def _timestamp_record(path: str, value: Any, *, max_age_days: int | None, now: datetime) -> dict[str, Any]:
    value_text = value if isinstance(value, str) else ""
    parsed = _parse_iso_datetime(value_text) if value_text else None
    if parsed is None:
        return {
            "path": path,
            "status": "invalid",
            "value": str(value) if value is not None else "",
            "age_days": None,
            "future_days": None,
            "max_age_days": max_age_days,
            "timestamp_valid": False,
            "reason": "Timestamp value could not be parsed as ISO 8601.",
        }
    if parsed > now:
        return {
            "path": path,
            "status": "future",
            "value": value_text,
            "age_days": None,
            "future_days": max(0, (parsed - now).days),
            "max_age_days": max_age_days,
            "timestamp_valid": True,
            "reason": "Timestamp is in the future.",
        }
    age_days = max(0, (now - parsed).days)
    stale = max_age_days is not None and age_days > max_age_days
    return {
        "path": path,
        "status": "stale" if stale else "current",
        "value": value_text,
        "age_days": age_days,
        "future_days": None,
        "max_age_days": max_age_days,
        "timestamp_valid": True,
        "reason": f"Timestamp is older than {max_age_days} day(s)." if stale else "Timestamp is current.",
    }


def _timestamp_values(document: Any, path: str = "") -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    if isinstance(document, dict):
        for key, value in sorted(document.items()):
            child_path = f"{path}.{key}" if path else str(key)
            if _is_timestamp_key(str(key)):
                values.append((child_path, value))
            if isinstance(value, (dict, list)):
                values.extend(_timestamp_values(value, child_path))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            if isinstance(value, (dict, list)):
                values.extend(_timestamp_values(value, child_path))
    return values


def _is_timestamp_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in TIMESTAMP_KEYS or lowered.endswith("_at") or lowered.endswith("_time") or lowered.endswith("_until")


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
