from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_runbook_report(
    evidence: dict[str, Any],
    *,
    catalog_document: dict[str, Any] | None = None,
    max_age_days: int | None = None,
) -> dict[str, Any]:
    observed = _observed_runbooks(evidence)
    expectations = _service_expectations(catalog_document)
    expected_names = {name for service in expectations for name in service["runbooks"]}
    referenced_by = _referenced_by(expectations)
    runbook_names = set(observed) | expected_names
    runbooks = [
        _runbook_record(
            name,
            observed.get(name),
            expected=name in expected_names,
            referenced_by=referenced_by.get(name, []),
            max_age_days=max_age_days,
        )
        for name in sorted(runbook_names)
    ]
    services = [_service_record(service, observed) for service in expectations]
    missing = [runbook for runbook in runbooks if runbook["status"] == "missing"]
    stale = [runbook for runbook in runbooks if runbook["status"] == "stale"]
    unreferenced = [runbook for runbook in runbooks if runbook["status"] == "unreferenced"]
    invalid_timestamps = [runbook for runbook in runbooks if runbook["timestamp_valid"] is False]
    services_with_missing = [service for service in services if service["missing_runbooks"]]
    status = "warn" if missing or stale or unreferenced or invalid_timestamps or services_with_missing else "pass"
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
            "max_age_days": max_age_days,
        },
        "summary": {
            "status": status,
            "runbooks_total": len(runbooks),
            "observed_runbooks": len(observed),
            "expected_runbooks": len(expected_names),
            "missing_runbooks_count": len(missing),
            "stale_runbooks_count": len(stale),
            "unreferenced_runbooks_count": len(unreferenced),
            "invalid_timestamp_count": len(invalid_timestamps),
            "services_total": len(services),
            "services_with_missing_runbooks": len(services_with_missing),
        },
        "runbooks": runbooks,
        "services": services,
    }


def render_runbook_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Runbook Coverage Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Catalog: {escape_markdown_text(metadata.get('catalog_name') or '-')}",
        f"- Max age days: {escape_markdown_text(metadata.get('max_age_days') if metadata.get('max_age_days') is not None else '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Observed runbooks: **{escape_markdown_text(summary.get('observed_runbooks', 0))}**",
        f"- Expected runbooks: **{escape_markdown_text(summary.get('expected_runbooks', 0))}**",
        f"- Missing runbooks: **{escape_markdown_text(summary.get('missing_runbooks_count', 0))}**",
        f"- Stale runbooks: **{escape_markdown_text(summary.get('stale_runbooks_count', 0))}**",
        f"- Unreferenced runbooks: **{escape_markdown_text(summary.get('unreferenced_runbooks_count', 0))}**",
        "",
        "## Runbooks",
        "",
    ]
    runbooks = report.get("runbooks", [])
    if not runbooks:
        lines.extend(["No runbook evidence was found and no catalog runbooks were expected.", ""])
    else:
        lines.extend(
            [
                "| Runbook | Status | Path | Updated | Age days | Referenced by | Reason |",
                "| --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for runbook in runbooks:
            lines.append(
                "| "
                f"{format_markdown_code(runbook.get('name', ''))} | "
                f"{escape_markdown_text(runbook.get('status') or '-')} | "
                f"{escape_markdown_text(runbook.get('path') or '-')} | "
                f"{format_markdown_code(runbook.get('updated_at') or '-')} | "
                f"{escape_markdown_text(runbook.get('age_days') if runbook.get('age_days') is not None else '-')} | "
                f"{escape_markdown_text(_join(runbook.get('referenced_by', [])) or '-')} | "
                f"{escape_markdown_text(runbook.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(["## Services", ""])
    services = report.get("services", [])
    if not services:
        lines.extend(["No service catalog expectations were provided.", ""])
    else:
        lines.extend(
            [
                "| Service | Owner | Status | Expected | Present | Missing |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for service in services:
            lines.append(
                "| "
                f"{format_markdown_code(service.get('id', ''))} {escape_markdown_text(service.get('name') or '')} | "
                f"{escape_markdown_text(service.get('owner') or '-')} | "
                f"{escape_markdown_text(service.get('status') or '-')} | "
                f"{escape_markdown_text(_join(service.get('runbooks', [])) or '-')} | "
                f"{escape_markdown_text(_join(service.get('present_runbooks', [])) or '-')} | "
                f"{escape_markdown_text(_join(service.get('missing_runbooks', [])) or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `current`: observed runbook is present and within the configured age threshold.",
            "- `stale`: observed runbook is older than `max_age_days`.",
            "- `missing`: service catalog expects a runbook that was not observed.",
            "- `unreferenced`: observed runbook exists but no catalog service references it.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_runbook_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "name",
            "owner",
            "status",
            "path",
            "updated_at",
            "age_days",
            "expected",
            "observed",
            "referenced_by",
            "runbooks",
            "present_runbooks",
            "missing_runbooks",
            "reason",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for runbook in report.get("runbooks", []):
        writer.writerow(
            {
                "record_type": "runbook",
                "id": runbook.get("name", ""),
                "name": runbook.get("name", ""),
                "owner": "",
                "status": runbook.get("status", ""),
                "path": runbook.get("path", ""),
                "updated_at": runbook.get("updated_at", ""),
                "age_days": runbook.get("age_days") if runbook.get("age_days") is not None else "",
                "expected": runbook.get("expected", False),
                "observed": runbook.get("observed", False),
                "referenced_by": _join(runbook.get("referenced_by", [])),
                "runbooks": "",
                "present_runbooks": "",
                "missing_runbooks": "",
                "reason": runbook.get("reason", ""),
            }
        )
    for service in report.get("services", []):
        writer.writerow(
            {
                "record_type": "service",
                "id": service.get("id", ""),
                "name": service.get("name", ""),
                "owner": service.get("owner", ""),
                "status": service.get("status", ""),
                "path": "",
                "updated_at": "",
                "age_days": "",
                "expected": "",
                "observed": "",
                "referenced_by": "",
                "runbooks": _join(service.get("runbooks", [])),
                "present_runbooks": _join(service.get("present_runbooks", [])),
                "missing_runbooks": _join(service.get("missing_runbooks", [])),
                "reason": "",
            }
        )
    return output.getvalue()


def _observed_runbooks(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    docs = signals.get("docs")
    if not isinstance(docs, dict):
        return {}
    runbooks = docs.get("runbooks")
    if not isinstance(runbooks, list):
        return {}
    observed = {}
    for runbook in runbooks:
        if not isinstance(runbook, dict):
            continue
        name = runbook.get("name")
        if isinstance(name, str) and name:
            observed[name] = {
                "name": name,
                "path": str(runbook.get("path", "")),
                "updated_at": str(runbook.get("updated_at", "")),
            }
    return observed


def _service_expectations(catalog_document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(catalog_document, dict):
        return []
    services = catalog_document.get("services")
    if not isinstance(services, list):
        return []
    expectations = []
    for service in services:
        if not isinstance(service, dict):
            continue
        service_id = service.get("id")
        runbooks = _string_list(service.get("runbooks", []))
        if not isinstance(service_id, str) or not service_id or not runbooks:
            continue
        expectations.append(
            {
                "id": service_id,
                "name": str(service.get("name", "")),
                "owner": str(service.get("owner", "")),
                "runbooks": runbooks,
            }
        )
    return expectations


def _service_record(service: dict[str, Any], observed: dict[str, dict[str, Any]]) -> dict[str, Any]:
    runbooks = service["runbooks"]
    missing = [name for name in runbooks if name not in observed]
    return {
        "id": service["id"],
        "name": service.get("name", ""),
        "owner": service.get("owner", ""),
        "status": "warn" if missing else "pass",
        "runbooks": runbooks,
        "present_runbooks": [name for name in runbooks if name in observed],
        "missing_runbooks": missing,
    }


def _runbook_record(
    name: str,
    observed: dict[str, Any] | None,
    *,
    expected: bool,
    referenced_by: list[str],
    max_age_days: int | None,
) -> dict[str, Any]:
    if observed is None:
        return {
            "name": name,
            "status": "missing",
            "path": "",
            "updated_at": "",
            "age_days": None,
            "timestamp_valid": None,
            "expected": expected,
            "observed": False,
            "referenced_by": referenced_by,
            "reason": "Expected by service catalog but not found in evidence.",
        }
    updated_at = str(observed.get("updated_at", ""))
    parsed = _parse_iso_datetime(updated_at)
    age_days = _age_days(parsed) if parsed is not None else None
    timestamp_valid = parsed is not None if updated_at else None
    stale = max_age_days is not None and age_days is not None and age_days > max_age_days
    if stale:
        status = "stale"
        reason = f"Runbook is older than {max_age_days} day(s)."
    elif timestamp_valid is False:
        status = "warn"
        reason = "Runbook updated_at timestamp could not be parsed."
    elif not expected and referenced_by == []:
        status = "unreferenced"
        reason = "Runbook exists but no catalog service references it."
    else:
        status = "current"
        reason = "Runbook is present."
    return {
        "name": name,
        "status": status,
        "path": str(observed.get("path", "")),
        "updated_at": updated_at,
        "age_days": age_days,
        "timestamp_valid": timestamp_valid,
        "expected": expected,
        "observed": True,
        "referenced_by": referenced_by,
        "reason": reason,
    }


def _referenced_by(services: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for service in services:
        service_id = str(service.get("id", ""))
        for runbook in service.get("runbooks", []):
            result.setdefault(str(runbook), []).append(service_id)
    return {name: sorted(ids) for name, ids in result.items()}


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_days(value: datetime) -> int:
    return max(0, (datetime.now(UTC) - value).days)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values)
