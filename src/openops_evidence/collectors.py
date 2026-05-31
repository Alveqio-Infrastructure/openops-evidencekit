from __future__ import annotations

import json
import os
import platform
import socket
import ssl
from datetime import UTC, datetime
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
