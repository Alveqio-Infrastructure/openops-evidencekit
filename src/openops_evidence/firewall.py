from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_firewall_report(evidence: dict[str, Any]) -> dict[str, Any]:
    firewall = _firewall_signal(evidence)
    rules = [_rule_record(item) for item in _list_of_dicts(firewall.get("rules"))]
    public_admin_rules = [rule for rule in rules if _is_public_admin_rule(rule)]
    checks = [
        _firewall_signal_check(firewall),
        _firewall_active_check(firewall),
        _default_incoming_check(firewall),
        _public_admin_rules_check(public_admin_rules),
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
            "source": firewall.get("source") or "",
            "firewall_status": firewall.get("status") or "unknown",
            "default_incoming": firewall.get("default_incoming") or "",
            "rules_total": len(rules),
            "public_admin_rules_total": len(public_admin_rules),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "rules": rules,
        "public_admin_rules": public_admin_rules,
    }


def render_firewall_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Firewall Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Firewall: **{escape_markdown_text(summary.get('firewall_status') or 'unknown')}**",
        f"- Default incoming: **{escape_markdown_text(summary.get('default_incoming') or 'unknown')}**",
        f"- Rules: **{escape_markdown_text(summary.get('rules_total', 0))}**",
        f"- Public admin rules: **{escape_markdown_text(summary.get('public_admin_rules_total', 0))}**",
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
    lines.extend(["", "## Public Admin Rules", ""])
    _append_rule_table(lines, report.get("public_admin_rules", []))
    lines.extend(["", "## Rules", ""])
    _append_rule_table(lines, report.get("rules", []))
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `pass`: firewall evidence exists, firewall is active, default incoming is deny, and no public admin allow rules were recorded.",
            "- `warn`: public admin allow rules need review.",
            "- `fail`: firewall evidence is missing, firewall is inactive, or default incoming traffic is not denied.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_firewall_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["record_type", "id", "title", "to", "action", "from", "status", "severity", "path", "reason", "recommended_action"],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in report.get("checks", []):
        writer.writerow(
            {
                "record_type": "check",
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "to": "",
                "action": "",
                "from": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for rule in report.get("rules", []):
        writer.writerow(
            {
                "record_type": "rule",
                "id": rule.get("id", ""),
                "title": "",
                "to": rule.get("to", ""),
                "action": rule.get("action", ""),
                "from": rule.get("from", ""),
                "status": "review" if rule.get("public_admin") else "recorded",
                "severity": "high" if rule.get("public_admin") else "info",
                "path": "signals.firewall.rules",
                "reason": "Firewall rule needs review." if rule.get("public_admin") else "Firewall rule recorded.",
                "recommended_action": "Restrict administrative access to VPN, bastion, or allowlists." if rule.get("public_admin") else "",
            }
        )
    return output.getvalue()


def _firewall_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    firewall = signals.get("firewall")
    return firewall if isinstance(firewall, dict) else {}


def _firewall_signal_check(firewall: dict[str, Any]) -> dict[str, str]:
    present = bool(firewall)
    return _check(
        "firewall_signal_present",
        "Firewall signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.firewall",
        "Firewall evidence is present." if present else "signals.firewall is missing or empty.",
        "Collect firewall evidence, for example from UFW status output.",
    )


def _firewall_active_check(firewall: dict[str, Any]) -> dict[str, str]:
    active = str(firewall.get("status") or "").lower() == "active"
    return _check(
        "firewall_active",
        "Firewall is active",
        "pass" if active else "fail",
        "critical",
        "signals.firewall.status",
        "Firewall status is active." if active else "Firewall status is not active.",
        "Enable the firewall or document the compensating network control.",
    )


def _default_incoming_check(firewall: dict[str, Any]) -> dict[str, str]:
    default = str(firewall.get("default_incoming") or "").lower()
    allowed = default in {"deny", "reject"}
    return _check(
        "default_incoming_denied",
        "Default incoming traffic is denied",
        "pass" if allowed else "fail",
        "high",
        "signals.firewall.default_incoming",
        f"Default incoming policy is {default or 'unknown'}." if allowed else f"Default incoming policy is {default or 'unknown'}, not deny/reject.",
        "Set default incoming policy to deny or reject and explicitly allow required services.",
    )


def _public_admin_rules_check(rules: list[dict[str, Any]]) -> dict[str, str]:
    return _check(
        "public_admin_rules_restricted",
        "Public administrative firewall rules are restricted",
        "warn" if rules else "pass",
        "high",
        "signals.firewall.public_admin_rules",
        f"{len(rules)} public administrative allow rule(s) need review." if rules else "No public administrative allow rules were recorded.",
        "Restrict SSH, RDP, VNC, and management APIs to VPN, bastion, or allowlists.",
    )


def _rule_record(item: dict[str, Any]) -> dict[str, Any]:
    rule = {
        "id": str(item.get("id") or f"{item.get('to', '')} {item.get('action', '')} {item.get('from', '')}".strip()),
        "to": str(item.get("to") or ""),
        "action": str(item.get("action") or "").upper(),
        "from": str(item.get("from") or ""),
    }
    rule["public_admin"] = _is_public_admin_rule(rule)
    return rule


def _is_public_admin_rule(rule: dict[str, Any]) -> bool:
    if str(rule.get("action") or "").upper() != "ALLOW":
        return False
    from_value = str(rule.get("from") or "").lower()
    if "anywhere" not in from_value and from_value not in {"any", "0.0.0.0/0", "::/0"}:
        return False
    to_value = str(rule.get("to") or "").lower()
    return any(token in to_value for token in ("22", "3389", "5900", "2375"))


def _append_rule_table(lines: list[str], rules: list[dict[str, Any]]) -> None:
    if not rules:
        lines.append("No matching firewall rules were found.")
        return
    lines.extend(["| To | Action | From | Public admin |", "| --- | --- | --- | --- |"])
    for rule in rules:
        lines.append(
            "| "
            f"{format_markdown_code(rule.get('to') or '-')} | "
            f"{escape_markdown_text(rule.get('action') or '-')} | "
            f"{escape_markdown_text(rule.get('from') or '-')} | "
            f"{escape_markdown_text('yes' if rule.get('public_admin') else 'no')} |"
        )


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


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
