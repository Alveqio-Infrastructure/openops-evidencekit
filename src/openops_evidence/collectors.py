from __future__ import annotations

import json
import os
import platform
import socket
import ssl
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .io import load_json, read_text


def collect_local() -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": "local",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": socket.gethostname(),
                "type": "host",
                "hostname": socket.gethostname(),
                "roles": [],
                "tags": ["local"],
            }
        ],
        "signals": {
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "python_version": platform.python_version(),
                "cwd": os.getcwd(),
            }
        },
    }


def collect_fixture(path: str) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("Fixture evidence must be a JSON object")
    return data


def collect_restic_snapshots(path: str) -> dict[str, Any]:
    snapshots = load_json(path)
    if not isinstance(snapshots, list):
        raise ValueError("restic snapshots input must be the JSON list produced by 'restic snapshots --json'")
    parsed_times = []
    hosts = set()
    paths = set()
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        if isinstance(snapshot.get("hostname"), str):
            hosts.add(snapshot["hostname"])
        for item in snapshot.get("paths", []):
            if isinstance(item, str):
                paths.add(item)
        snapshot_time = snapshot.get("time")
        if isinstance(snapshot_time, str):
            parsed = _parse_iso_datetime(snapshot_time)
            if parsed is not None:
                parsed_times.append(parsed)
    latest = max(parsed_times).isoformat() if parsed_times else None
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"restic-snapshots:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": "restic-repository",
                "type": "backup-repository",
                "roles": ["backup"],
                "tags": ["restic"],
            }
        ],
        "signals": {
            "backup": {
                "tool": "restic",
                "last_success_at": latest,
                "snapshot_count": len(snapshots),
                "protected_hosts": sorted(hosts),
                "protected_paths": sorted(paths),
                "repository_count": 1,
            }
        },
    }


def collect_borg_archives(path: str) -> dict[str, Any]:
    payload = load_json(path)
    if isinstance(payload, dict):
        archives = payload.get("archives", [])
        repository = payload.get("repository", {})
    elif isinstance(payload, list):
        archives = payload
        repository = {}
    else:
        raise ValueError("Borg input must be a JSON object or list produced by 'borg list --json'")
    if not isinstance(archives, list):
        raise ValueError("Borg input must contain an archives list")
    archive_rows = [item for item in archives if isinstance(item, dict)]
    parsed_times = []
    hosts = set()
    archive_names = []
    for archive in archive_rows:
        if isinstance(archive.get("hostname"), str):
            hosts.add(archive["hostname"])
        if isinstance(archive.get("host"), str):
            hosts.add(archive["host"])
        if isinstance(archive.get("name"), str):
            archive_names.append(archive["name"])
        for key in ("time", "start", "start_time"):
            archive_time = archive.get(key)
            if isinstance(archive_time, str):
                parsed = _parse_iso_datetime(archive_time)
                if parsed is not None:
                    parsed_times.append(parsed)
                    break
    repository_id = repository.get("id") if isinstance(repository, dict) else None
    latest = max(parsed_times).isoformat() if parsed_times else None
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"borg-archives:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": str(repository_id or "borg-repository"),
                "type": "backup-repository",
                "roles": ["backup"],
                "tags": ["borg"],
            }
        ],
        "signals": {
            "backup": {
                "tool": "borg",
                "last_success_at": latest,
                "archive_count": len(archive_rows),
                "archive_names": sorted(archive_names),
                "protected_hosts": sorted(hosts),
                "repository_count": 1,
                "repository_id": repository_id,
            }
        },
    }


def collect_uptime_kuma_export(path: str) -> dict[str, Any]:
    export = load_json(path)
    if not isinstance(export, dict):
        raise ValueError("Uptime Kuma export must be a JSON object")
    monitors = export.get("monitorList") or export.get("monitors") or []
    if isinstance(monitors, dict):
        monitors = list(monitors.values())
    if not isinstance(monitors, list):
        raise ValueError("Uptime Kuma export must contain monitorList or monitors")
    monitor_rows = [item for item in monitors if isinstance(item, dict)]
    enabled = [item for item in monitor_rows if item.get("active") is not False]
    notification_ids = set()
    for item in monitor_rows:
        for key in ("notificationIDList", "notification_ids", "notifications"):
            value = item.get(key)
            if isinstance(value, list):
                notification_ids.update(str(entry) for entry in value)
            elif isinstance(value, dict):
                notification_ids.update(str(entry) for entry in value)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"uptime-kuma-export:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": f"uptime-kuma-monitor-{item.get('id', index)}",
                "type": "monitor",
                "hostname": item.get("hostname") or item.get("url") or item.get("name"),
                "roles": ["monitoring"],
                "tags": [str(item.get("type", "unknown"))],
            }
            for index, item in enumerate(monitor_rows, start=1)
        ],
        "signals": {
            "monitoring": {
                "system": "uptime-kuma",
                "targets": len(enabled),
                "monitors_total": len(monitor_rows),
                "monitors_enabled": len(enabled),
                "alert_channels": sorted(notification_ids),
            }
        },
    }


def collect_prometheus_targets(path: str) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError("Prometheus targets input must be a JSON object")
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise ValueError("Prometheus targets input must contain a data object")
    active_targets = data.get("activeTargets", [])
    if not isinstance(active_targets, list):
        raise ValueError("Prometheus targets input must contain activeTargets")
    rows = [item for item in active_targets if isinstance(item, dict)]
    up = [item for item in rows if item.get("health") == "up"]
    down = [item for item in rows if item.get("health") == "down"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"prometheus-targets:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": str(item.get("scrapeUrl") or item.get("labels", {}).get("instance") or f"prometheus-target-{index}"),
                "type": "monitor-target",
                "hostname": str(item.get("labels", {}).get("instance") or item.get("scrapeUrl") or ""),
                "roles": ["monitoring"],
                "tags": ["prometheus", str(item.get("health", "unknown"))],
            }
            for index, item in enumerate(rows, start=1)
        ],
        "signals": {
            "monitoring": {
                "system": "prometheus",
                "targets": len(up),
                "targets_total": len(rows),
                "targets_up": len(up),
                "targets_down": len(down),
                "down_targets": [
                    item.get("labels", {}).get("instance") or item.get("scrapeUrl") or item.get("discoveredLabels", {}).get("__address__")
                    for item in down
                ],
            }
        },
    }


def collect_systemd_timers(path: str) -> dict[str, Any]:
    payload = load_json(path)
    if isinstance(payload, dict):
        timers = payload.get("timers") or payload.get("data") or []
    elif isinstance(payload, list):
        timers = payload
    else:
        raise ValueError("systemd timer input must be a JSON object or list")
    if not isinstance(timers, list):
        raise ValueError("systemd timer input must contain a timer list")
    timer_rows = [item for item in timers if isinstance(item, dict)]
    active = []
    waiting = []
    failed = []
    units = []
    for timer in timer_rows:
        unit = _first_string(timer, "unit", "UNIT", "name", "Name") or "unknown.timer"
        units.append(unit)
        active_state = str(_first_value(timer, "active", "ACTIVE", "ActiveState") or "").lower()
        sub_state = str(_first_value(timer, "sub", "SUB", "SubState") or "").lower()
        if active_state == "active":
            active.append(unit)
        if sub_state == "waiting":
            waiting.append(unit)
        if active_state == "failed" or sub_state == "failed":
            failed.append(unit)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"systemd-timers:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": unit,
                "type": "systemd-timer",
                "roles": ["runtime"],
                "tags": ["systemd"],
            }
            for unit in sorted(units)
        ],
        "signals": {
            "runtime": {
                "systemd": {
                    "timers_total": len(timer_rows),
                    "timers_active": len(active),
                    "timers_waiting": len(waiting),
                    "timers_failed": len(failed),
                    "failed_timers": sorted(failed),
                    "units": sorted(units),
                }
            }
        },
    }


def collect_docker_containers(path: str) -> dict[str, Any]:
    payload = _load_json_or_json_lines(path)
    if isinstance(payload, dict):
        containers = payload.get("containers") or payload.get("data") or []
    elif isinstance(payload, list):
        containers = payload
    else:
        raise ValueError("Docker input must be a JSON object, JSON list, or JSON lines file")
    if not isinstance(containers, list):
        raise ValueError("Docker input must contain a container list")
    container_rows = [item for item in containers if isinstance(item, dict)]
    running = []
    exited = []
    missing_restart_policy = []
    images = set()
    assets = []
    for index, container in enumerate(container_rows, start=1):
        name = _container_name(container, index)
        image = _container_image(container)
        if image:
            images.add(image)
        is_running = _container_running(container)
        if is_running:
            running.append(name)
        else:
            exited.append(name)
        restart_policy = _container_restart_policy(container)
        if is_running and restart_policy in {"", "no", "none", "null"}:
            missing_restart_policy.append(name)
        assets.append(
            {
                "id": name,
                "type": "container",
                "roles": ["runtime"],
                "tags": ["docker", "running" if is_running else "stopped"],
            }
        )
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"docker-containers:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": assets,
        "signals": {
            "runtime": {
                "docker": {
                    "containers_total": len(container_rows),
                    "containers_running": len(running),
                    "containers_exited": len(exited),
                    "running_containers": sorted(running),
                    "exited_containers": sorted(exited),
                    "restart_policy_missing": sorted(missing_restart_policy),
                    "images": sorted(images),
                }
            }
        },
    }


def collect_apt_upgrades(path: str) -> dict[str, Any]:
    packages = [_apt_upgrade_record(line) for line in read_text(path).splitlines()]
    packages = [item for item in packages if item is not None]
    security_updates = [item for item in packages if item["security"]]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"apt-upgrades:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": item["name"],
                "type": "package",
                "roles": ["patching"],
                "tags": ["apt", "security" if item["security"] else "update"],
            }
            for item in packages
        ],
        "signals": {
            "patch": {
                "source": "apt",
                "updates_total": len(packages),
                "security_updates_total": len(security_updates),
                "reboot_required": None,
                "packages": packages,
                "security_packages": [item["name"] for item in security_updates],
            }
        },
    }


def collect_ufw_status(path: str) -> dict[str, Any]:
    text = read_text(path)
    status = "unknown"
    default_incoming = ""
    default_outgoing = ""
    rules: list[dict[str, Any]] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("-") or value.lower().startswith("to "):
            continue
        lower = value.lower()
        if lower.startswith("status:"):
            status = value.split(":", 1)[1].strip().lower()
            continue
        if lower.startswith("default:"):
            default_incoming, default_outgoing = _parse_ufw_defaults(value)
            continue
        rule = _parse_ufw_rule(value)
        if rule is not None:
            rules.append(rule)
    public_admin_rules = [rule for rule in rules if _is_public_admin_rule(rule)]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"ufw-status:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": rule["to"],
                "type": "firewall-rule",
                "roles": ["firewall"],
                "tags": ["ufw", rule["action"].lower()],
            }
            for rule in rules
        ],
        "signals": {
            "firewall": {
                "source": "ufw",
                "status": status,
                "default_incoming": default_incoming,
                "default_outgoing": default_outgoing,
                "rules_total": len(rules),
                "rules": rules,
                "public_admin_rules": [rule["id"] for rule in public_admin_rules],
            }
        },
    }


def collect_trivy_json(path: str) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError("Trivy input must be a JSON object")
    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy input must contain a Results list")
    vulnerabilities: list[dict[str, Any]] = []
    targets = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "unknown")
        targets.add(target)
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            vulnerabilities.append(_trivy_vulnerability_record(target, item))
    severity_counts = _severity_counts(vulnerabilities)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"trivy-json:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": target,
                "type": "scan-target",
                "roles": ["vulnerability"],
                "tags": ["trivy"],
            }
            for target in sorted(targets)
        ],
        "signals": {
            "vulnerabilities": {
                "scanner": "trivy",
                "targets_total": len(targets),
                "findings_total": len(vulnerabilities),
                "critical_total": severity_counts["critical"],
                "high_total": severity_counts["high"],
                "medium_total": severity_counts["medium"],
                "low_total": severity_counts["low"],
                "unknown_total": severity_counts["unknown"],
                "findings": vulnerabilities,
            }
        },
    }


def collect_nmap_xml(path: str) -> dict[str, Any]:
    tree = ET.parse(path)
    root = tree.getroot()
    open_ports: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    hosts = set()
    for host_index, host in enumerate(root.findall("host"), start=1):
        state = host.find("status")
        if state is not None and state.get("state") not in {None, "up"}:
            continue
        host_id = _nmap_host_id(host, host_index)
        hosts.add(host_id)
        assets.append(
            {
                "id": host_id,
                "type": "endpoint",
                "hostname": host_id,
                "roles": ["exposure"],
                "tags": ["nmap"],
            }
        )
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = _safe_int(port.get("portid"))
            service = port.find("service")
            open_ports.append(
                {
                    "host": host_id,
                    "port": port_id,
                    "protocol": port.get("protocol") or "tcp",
                    "service": service.get("name") if service is not None else "",
                    "product": service.get("product") if service is not None else "",
                }
            )
    risky_ports = [_exposure_port_name(item) for item in open_ports if _is_risky_port(item.get("port"))]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"nmap-xml:{path}",
            "collector": "openops-evidencekit",
        },
        "assets": assets,
        "signals": {
            "exposure": {
                "scanner": "nmap",
                "hosts_total": len(hosts),
                "open_ports_total": len(open_ports),
                "open_ports": open_ports,
                "risky_ports": risky_ports,
            }
        },
    }


def collect_docs_directory(
    directory: str,
    required: list[str] | None = None,
    max_age_days: int | None = None,
) -> dict[str, Any]:
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(
            f"Documentation directory does not exist or is not a directory: {directory}"
        )
    required_paths = [_normalize_required_path(item) for item in (required or [])]
    documents = _documentation_files(root)
    documents_by_path = {document["path"]: document for document in documents}
    missing_required = [path for path in required_paths if path not in documents_by_path]
    stale_documents = _stale_documents(documents, max_age_days)
    inventory_updated_at = _inventory_updated_at(documents)
    runbooks = _runbook_documents(documents)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"docs-directory:{root.name}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": document["path"],
                "type": "document",
                "roles": ["documentation"],
                "tags": _document_tags(document, stale_documents),
            }
            for document in documents
        ],
        "signals": {
            "docs": {
                "documents_total": len(documents),
                "required_total": len(required_paths),
                "required_present": len(required_paths) - len(missing_required),
                "required_missing": len(missing_required),
                "missing_required": missing_required,
                "max_age_days": max_age_days,
                "stale_count": len(stale_documents),
                "stale_documents": stale_documents,
                "inventory_updated_at": inventory_updated_at,
                "runbooks": runbooks,
                "documents": documents,
            }
        },
    }


def collect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
            cert = wrapped.getpeercert()
    not_after = cert.get("notAfter")
    parsed_not_after = None
    if isinstance(not_after, str):
        parsed_not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        parsed_not_after = parsed_not_after.replace(tzinfo=UTC).isoformat()
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": f"tls:{hostname}:{port}",
            "collector": "openops-evidencekit",
        },
        "assets": [
            {
                "id": hostname,
                "type": "endpoint",
                "hostname": hostname,
                "roles": ["tls"],
                "tags": [],
            }
        ],
        "signals": {
            "tls": {
                "certificates": [
                    {
                        "hostname": hostname,
                        "port": port,
                        "not_after": parsed_not_after,
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                    }
                ]
            }
        },
    }


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _load_json_or_json_lines(path: str) -> Any:
    text = read_text(path).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON line {line_number} in {path}: {exc}") from exc
        return rows


def _apt_upgrade_record(line: str) -> dict[str, Any] | None:
    value = line.strip()
    if not value or value.lower().startswith("listing...") or "/" not in value:
        return None
    head, _, tail = value.partition(" ")
    name, _, suite = head.partition("/")
    parts = tail.split()
    if len(parts) < 2 or not name:
        return None
    candidate = parts[0]
    architecture = parts[1]
    current = ""
    marker = "[upgradable from:"
    if marker in value:
        current = value.split(marker, 1)[1].rstrip("]").strip()
    lower = value.lower()
    return {
        "name": name,
        "suite": suite,
        "candidate_version": candidate,
        "current_version": current,
        "architecture": architecture,
        "security": "security" in lower,
    }


def _parse_ufw_defaults(line: str) -> tuple[str, str]:
    body = line.split(":", 1)[1].strip().lower()
    incoming = ""
    outgoing = ""
    for segment in body.split(","):
        value = segment.strip()
        if "(incoming)" in value:
            incoming = value.split("(", 1)[0].strip()
        elif "(outgoing)" in value:
            outgoing = value.split("(", 1)[0].strip()
    return incoming, outgoing


def _parse_ufw_rule(line: str) -> dict[str, str] | None:
    parts = line.split()
    action_index = next((index for index, part in enumerate(parts) if part.upper() in {"ALLOW", "DENY", "REJECT", "LIMIT"}), None)
    if action_index is None or action_index == 0:
        return None
    to_value = " ".join(parts[:action_index])
    action = parts[action_index].upper()
    from_value = " ".join(parts[action_index + 1 :]) or "unknown"
    return {
        "id": f"{to_value} {action} {from_value}",
        "to": to_value,
        "action": action,
        "from": from_value,
    }


def _is_public_admin_rule(rule: dict[str, str]) -> bool:
    if rule.get("action") != "ALLOW":
        return False
    from_value = rule.get("from", "").lower()
    if "anywhere" not in from_value and from_value not in {"any", "0.0.0.0/0", "::/0"}:
        return False
    to_value = rule.get("to", "").lower()
    return any(token in to_value for token in ("22", "3389", "5900", "2375"))


def _trivy_vulnerability_record(target: str, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("VulnerabilityID") or item.get("ID") or "unknown"),
        "target": target,
        "package": str(item.get("PkgName") or ""),
        "installed_version": str(item.get("InstalledVersion") or ""),
        "fixed_version": str(item.get("FixedVersion") or ""),
        "severity": str(item.get("Severity") or "UNKNOWN").lower(),
        "title": str(item.get("Title") or item.get("Description") or ""),
        "primary_url": str(item.get("PrimaryURL") or ""),
    }


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _first_value(document: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in document:
            return document[key]
    return None


def _first_string(document: dict[str, Any], *keys: str) -> str | None:
    value = _first_value(document, *keys)
    return value if isinstance(value, str) and value else None


def _container_name(container: dict[str, Any], index: int) -> str:
    value = _first_string(container, "Names", "Name", "name")
    if value is None and isinstance(container.get("Config"), dict):
        value = _first_string(container["Config"], "Hostname")
    if value is None:
        value = f"container-{index}"
    return value.lstrip("/")


def _container_image(container: dict[str, Any]) -> str | None:
    value = _first_string(container, "Image", "image")
    if value is None and isinstance(container.get("Config"), dict):
        value = _first_string(container["Config"], "Image")
    return value


def _container_running(container: dict[str, Any]) -> bool:
    state = container.get("State")
    if isinstance(state, dict):
        return bool(state.get("Running"))
    if isinstance(state, str):
        return state.lower() == "running"
    status = _first_string(container, "Status", "status")
    return bool(status and status.lower().startswith("up"))


def _container_restart_policy(container: dict[str, Any]) -> str:
    value = _first_value(container, "RestartPolicy", "restart_policy")
    if value is None and isinstance(container.get("HostConfig"), dict):
        policy = container["HostConfig"].get("RestartPolicy")
        if isinstance(policy, dict):
            value = policy.get("Name")
    return str(value or "").lower()


def _nmap_host_id(host: ET.Element, index: int) -> str:
    for address in host.findall("address"):
        value = address.get("addr")
        if value:
            return value
    hostname = host.find("./hostnames/hostname")
    if hostname is not None and hostname.get("name"):
        return str(hostname.get("name"))
    return f"nmap-host-{index}"


def _safe_int(value: str | None) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _is_risky_port(port: Any) -> bool:
    return port in {21, 22, 23, 25, 110, 143, 389, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


def _exposure_port_name(item: dict[str, Any]) -> str:
    host = item.get("host") or "unknown"
    protocol = item.get("protocol") or "tcp"
    port = item.get("port")
    return f"{host}:{port}/{protocol}"


def _documentation_files(root: Path) -> list[dict[str, Any]]:
    documents = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {
            ".md",
            ".markdown",
            ".txt",
            ".rst",
        }:
            continue
        relative_path = path.relative_to(root).as_posix()
        updated_at = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
        documents.append(
            {
                "path": relative_path,
                "name": path.stem,
                "updated_at": updated_at,
                "size_bytes": path.stat().st_size,
            }
        )
    return documents


def _normalize_required_path(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"Required documentation paths must be relative: {path}")
    normalized = candidate.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        raise ValueError(
            f"Required documentation paths must stay inside the documentation directory: {path}"
        )
    return normalized


def _stale_documents(documents: list[dict[str, Any]], max_age_days: int | None) -> list[str]:
    if max_age_days is None:
        return []
    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
    stale = []
    for document in documents:
        updated_at = _parse_iso_datetime(str(document.get("updated_at", "")))
        if updated_at is not None and updated_at < cutoff:
            stale.append(str(document["path"]))
    return sorted(stale)


def _inventory_updated_at(documents: list[dict[str, Any]]) -> str | None:
    inventory_documents = [
        document
        for document in documents
        if "inventory" in str(document.get("path", "")).lower()
    ]
    if not inventory_documents:
        return None
    return max(str(document["updated_at"]) for document in inventory_documents)


def _runbook_documents(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    runbooks = []
    for document in documents:
        path = str(document.get("path", ""))
        if not (path.lower().startswith("runbooks/") or "runbook" in path.lower()):
            continue
        runbooks.append(
            {
                "name": str(document.get("name", "")),
                "path": path,
                "updated_at": str(document.get("updated_at", "")),
            }
        )
    return runbooks


def _document_tags(document: dict[str, Any], stale_documents: list[str]) -> list[str]:
    tags = ["present"]
    path = str(document["path"])
    if path in stale_documents:
        tags.append("stale")
    return tags
