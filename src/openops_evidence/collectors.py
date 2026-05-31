from __future__ import annotations

import os
import platform
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from .io import load_json


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
