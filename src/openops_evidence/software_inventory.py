from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_software_inventory_report(evidence: dict[str, Any]) -> dict[str, Any]:
    signal = _software_signal(evidence)
    components = [_component_record(item) for item in _list_of_dicts(signal.get("components"))]
    missing_versions = [item for item in components if not item["version"]]
    missing_purls = [item for item in components if not item["purl"]]
    missing_licenses = [item for item in components if not item["licenses"]]
    checks = [
        _software_signal_check(signal),
        _components_present_check(components),
        _versions_recorded_check(missing_versions),
        _purls_recorded_check(missing_purls),
        _licenses_recorded_check(missing_licenses),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
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
            "status": "fail" if failed else "warn" if warnings else "pass",
            "source": signal.get("source") or "",
            "bom_format": signal.get("bom_format") or "",
            "spec_version": signal.get("spec_version") or "",
            "components_total": len(components),
            "missing_versions": len(missing_versions),
            "missing_purls": len(missing_purls),
            "missing_licenses": len(missing_licenses),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "components": components,
        "missing_version_components": missing_versions,
        "missing_purl_components": missing_purls,
        "missing_license_components": missing_licenses,
    }


def render_software_inventory_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Software Inventory Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Source: **{escape_markdown_text(summary.get('source') or 'unknown')}**",
        f"- Components: **{escape_markdown_text(summary.get('components_total', 0))}**",
        f"- Missing versions: **{escape_markdown_text(summary.get('missing_versions', 0))}**",
        f"- Missing package URLs: **{escape_markdown_text(summary.get('missing_purls', 0))}**",
        f"- Missing licenses: **{escape_markdown_text(summary.get('missing_licenses', 0))}**",
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
    lines.extend(["", "## Components", ""])
    _append_component_table(lines, report.get("components", []))
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `pass`: SBOM evidence exists and components include version, package URL, and license metadata.",
            "- `warn`: component metadata is incomplete and needs owner review.",
            "- `fail`: software inventory evidence is missing or no components were recorded.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_software_inventory_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["record_type", "id", "title", "name", "version", "type", "purl", "licenses", "status", "severity", "path", "reason", "recommended_action"],
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
                "version": "",
                "type": "",
                "purl": "",
                "licenses": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for component in report.get("components", []):
        writer.writerow(
            {
                "record_type": "component",
                "id": component.get("bom_ref") or component.get("purl") or component.get("name", ""),
                "title": "",
                "name": component.get("name", ""),
                "version": component.get("version", ""),
                "type": component.get("type", ""),
                "purl": component.get("purl", ""),
                "licenses": ";".join(component.get("licenses", [])),
                "status": "review",
                "severity": "medium" if not component.get("version") or not component.get("purl") else "info",
                "path": "signals.software_inventory.components",
                "reason": "Software component metadata recorded.",
                "recommended_action": "Review ownership, vulnerability impact, and license metadata.",
            }
        )
    return output.getvalue()


def _software_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    value = signals.get("software_inventory")
    return value if isinstance(value, dict) else {}


def _software_signal_check(signal: dict[str, Any]) -> dict[str, str]:
    present = bool(signal)
    return _check(
        "software_inventory_signal_present",
        "Software inventory signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.software_inventory",
        "Software inventory evidence is present." if present else "signals.software_inventory is missing or empty.",
        "Collect SBOM evidence, for example from CycloneDX JSON.",
    )


def _components_present_check(components: list[dict[str, Any]]) -> dict[str, str]:
    return _check(
        "software_components_recorded",
        "Software components are recorded",
        "pass" if components else "fail",
        "critical",
        "signals.software_inventory.components",
        f"{len(components)} component(s) were recorded." if components else "No software components were recorded.",
        "Generate an SBOM for the application, image, or host under review.",
    )


def _versions_recorded_check(components: list[dict[str, Any]]) -> dict[str, str]:
    return _warn_count_check("software_versions_recorded", "Component versions are recorded", components, "signals.software_inventory.components.version", "Add component versions to the SBOM output.")


def _purls_recorded_check(components: list[dict[str, Any]]) -> dict[str, str]:
    return _warn_count_check("software_purls_recorded", "Package URLs are recorded", components, "signals.software_inventory.components.purl", "Generate SBOMs with package URL support enabled.")


def _licenses_recorded_check(components: list[dict[str, Any]]) -> dict[str, str]:
    return _warn_count_check("software_licenses_recorded", "Component licenses are recorded", components, "signals.software_inventory.components.licenses", "Record license identifiers or names for owner review.")


def _warn_count_check(check_id: str, title: str, items: list[dict[str, Any]], path: str, action: str) -> dict[str, str]:
    return _check(
        check_id,
        title,
        "warn" if items else "pass",
        "medium",
        path,
        f"{len(items)} component(s) need metadata review." if items else "No matching metadata gaps were recorded.",
        action,
    )


def _component_record(item: dict[str, Any]) -> dict[str, Any]:
    licenses = item.get("licenses") if isinstance(item.get("licenses"), list) else []
    return {
        "bom_ref": str(item.get("bom_ref") or ""),
        "type": str(item.get("type") or ""),
        "name": str(item.get("name") or "unknown"),
        "version": str(item.get("version") or ""),
        "group": str(item.get("group") or ""),
        "purl": str(item.get("purl") or ""),
        "licenses": [str(value) for value in licenses if isinstance(value, str) and value],
    }


def _append_component_table(lines: list[str], components: list[dict[str, Any]]) -> None:
    if not components:
        lines.append("No software components were found.")
        return
    lines.extend(["| Name | Version | Type | Package URL | Licenses |", "| --- | --- | --- | --- | --- |"])
    for component in components:
        lines.append(
            "| "
            f"{format_markdown_code(component.get('name') or '-')} | "
            f"{escape_markdown_text(component.get('version') or '-')} | "
            f"{escape_markdown_text(component.get('type') or '-')} | "
            f"{escape_markdown_text(component.get('purl') or '-')} | "
            f"{escape_markdown_text(', '.join(component.get('licenses') or []) or '-')} |"
        )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _check(check_id: str, title: str, status: str, severity: str, path: str, reason: str, recommended_action: str) -> dict[str, str]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }
