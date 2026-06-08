from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


RISKY_PORTS = {
    21: "FTP is commonly unsafe on public networks.",
    22: "SSH should normally be restricted to a VPN, bastion, or allowlist.",
    23: "Telnet is unsafe on public networks.",
    25: "SMTP exposure should be intentional and mail-scoped.",
    110: "POP3 should not be exposed without a clear mail requirement.",
    143: "IMAP should not be exposed without a clear mail requirement.",
    389: "LDAP should normally be internal or protected.",
    445: "SMB should not be exposed to public networks.",
    1433: "SQL Server should normally be internal or protected.",
    1521: "Oracle database listeners should normally be internal or protected.",
    2049: "NFS should normally be internal or protected.",
    2375: "Docker API without TLS is high risk.",
    3306: "MySQL should normally be internal or protected.",
    3389: "RDP should normally be restricted to a VPN, bastion, or allowlist.",
    5432: "PostgreSQL should normally be internal or protected.",
    5900: "VNC should normally be restricted to a VPN or allowlist.",
    6379: "Redis should normally be internal or protected.",
    9200: "Elasticsearch should normally be internal or protected.",
    11211: "Memcached should normally be internal or protected.",
    27017: "MongoDB should normally be internal or protected.",
}


def create_exposure_report(evidence: dict[str, Any]) -> dict[str, Any]:
    exposure = _exposure_signal(evidence)
    open_ports = [_port_record(item) for item in _list_of_dicts(exposure.get("open_ports"))]
    risky_ports = [item for item in open_ports if item["risk"] == "risky"]
    checks = [
        _exposure_signal_check(exposure),
        _open_ports_check(open_ports),
        _risky_ports_check(risky_ports),
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
            "scanner": exposure.get("scanner") or "",
            "hosts_total": _int_value(exposure.get("hosts_total")) or _hosts_total(open_ports),
            "open_ports_total": len(open_ports),
            "risky_ports_total": len(risky_ports),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "open_ports": open_ports,
        "risky_ports": risky_ports,
    }


def render_exposure_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Exposure Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Scanner: **{escape_markdown_text(summary.get('scanner') or 'unknown')}**",
        f"- Hosts: **{escape_markdown_text(summary.get('hosts_total', 0))}**",
        f"- Open ports: **{escape_markdown_text(summary.get('open_ports_total', 0))}**",
        f"- Risky ports: **{escape_markdown_text(summary.get('risky_ports_total', 0))}**",
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
    lines.extend(["", "## Open Ports", ""])
    _append_port_table(lines, report.get("open_ports", []))
    lines.extend(["", "## Risky Ports", ""])
    _append_port_table(lines, report.get("risky_ports", []))
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `pass`: exposure evidence exists and no open ports were recorded.",
            "- `warn`: open ports exist and need owner review.",
            "- `fail`: exposure evidence is missing or risky administrative/data ports are exposed.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_exposure_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "host",
            "port",
            "protocol",
            "service",
            "risk",
            "status",
            "severity",
            "path",
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
                "host": "",
                "port": "",
                "protocol": "",
                "service": "",
                "risk": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for port in report.get("open_ports", []):
        writer.writerow(
            {
                "record_type": "open_port",
                "id": port.get("id", ""),
                "title": "",
                "host": port.get("host", ""),
                "port": port.get("port", ""),
                "protocol": port.get("protocol", ""),
                "service": port.get("service", ""),
                "risk": port.get("risk", ""),
                "status": "review",
                "severity": "high" if port.get("risk") == "risky" else "medium",
                "path": "signals.exposure.open_ports",
                "reason": port.get("reason", ""),
                "recommended_action": "Confirm business need and restrict exposure where possible.",
            }
        )
    return output.getvalue()


def _exposure_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    exposure = signals.get("exposure")
    return exposure if isinstance(exposure, dict) else {}


def _exposure_signal_check(exposure: dict[str, Any]) -> dict[str, Any]:
    present = bool(exposure)
    return _check(
        "exposure_signal_present",
        "Exposure signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.exposure",
        "Network exposure evidence is present." if present else "signals.exposure is missing or empty.",
        "Collect perimeter scan evidence, for example from Nmap XML.",
    )


def _open_ports_check(open_ports: list[dict[str, Any]]) -> dict[str, Any]:
    return _check(
        "open_ports_reviewed",
        "Open ports are reviewed",
        "warn" if open_ports else "pass",
        "medium",
        "signals.exposure.open_ports",
        f"{len(open_ports)} open port(s) need owner review." if open_ports else "No open ports were recorded.",
        "Document intended public services and remove or restrict unneeded exposure.",
    )


def _risky_ports_check(risky_ports: list[dict[str, Any]]) -> dict[str, Any]:
    return _check(
        "risky_ports_closed",
        "Risky administrative and data ports are closed",
        "fail" if risky_ports else "pass",
        "high",
        "signals.exposure.open_ports",
        f"{len(risky_ports)} risky port(s) are exposed." if risky_ports else "No risky administrative or data ports were recorded.",
        "Move administrative and data services behind VPN, bastion, private network, or explicit allowlists.",
    )


def _port_record(item: dict[str, Any]) -> dict[str, Any]:
    port = _int_value(item.get("port"))
    reason = RISKY_PORTS.get(port, "Open port should be tied to a documented public service.")
    risk = "risky" if port in RISKY_PORTS else "review"
    host = str(item.get("host") or "unknown")
    protocol = str(item.get("protocol") or "tcp")
    return {
        "id": f"{host}:{port}/{protocol}",
        "host": host,
        "port": port,
        "protocol": protocol,
        "service": str(item.get("service") or ""),
        "product": str(item.get("product") or ""),
        "risk": risk,
        "reason": reason,
    }


def _append_port_table(lines: list[str], ports: list[dict[str, Any]]) -> None:
    if not ports:
        lines.append("No matching ports were found.")
        return
    lines.extend(["| Host | Port | Protocol | Service | Risk | Reason |", "| --- | ---: | --- | --- | --- | --- |"])
    for port in ports:
        lines.append(
            "| "
            f"{format_markdown_code(port.get('host') or '-')} | "
            f"{escape_markdown_text(port.get('port') or '-')} | "
            f"{escape_markdown_text(port.get('protocol') or '-')} | "
            f"{escape_markdown_text(port.get('service') or '-')} | "
            f"{escape_markdown_text(port.get('risk') or '-')} | "
            f"{escape_markdown_text(port.get('reason') or '-')} |"
        )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _hosts_total(open_ports: list[dict[str, Any]]) -> int:
    return len({item.get("host") for item in open_ports if item.get("host")})


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _check(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    path: str,
    reason: str,
    recommended_action: str,
) -> dict[str, str]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }
