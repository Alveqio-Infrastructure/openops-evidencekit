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
