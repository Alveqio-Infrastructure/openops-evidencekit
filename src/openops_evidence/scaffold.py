from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

from .policy import Check


_PATH_SEGMENT_RE = re.compile(r"^([^\[\]]+)(?:\[(\*|-?\d+)\])?$")


@dataclass(frozen=True)
class PathSegment:
    name: str
    is_array: bool = False


def create_evidence_scaffold(
    checks: Iterable[Check],
    *,
    source: str = "policy-scaffold",
    organization: str = "",
    environment: str = "",
    policy_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    check_list = list(checks)
    signals: dict[str, Any] = {}
    skipped_paths: set[str] = set()
    signal_paths: set[str] = set()

    for check in check_list:
        segments = _signal_segments(check.path)
        if segments is None:
            skipped_paths.add(check.path)
            continue
        signal_paths.add(check.path)
        if check.operator == "missing":
            continue
        _assign_placeholder(signals, segments)

    metadata: dict[str, Any] = {
        "source": source,
        "organization": organization,
        "environment": environment,
        "scaffold": True,
        "policy_check_count": len(check_list),
        "policy_signal_path_count": len(signal_paths),
    }
    if policy_metadata:
        _copy_policy_metadata(metadata, policy_metadata)
    if skipped_paths:
        metadata["skipped_policy_paths"] = sorted(skipped_paths)

    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": metadata,
        "assets": [],
        "signals": signals,
    }


def _copy_policy_metadata(target: dict[str, Any], policy_metadata: dict[str, Any]) -> None:
    for key in ("name", "version"):
        value = policy_metadata.get(key)
        if isinstance(value, (str, int, float)):
            target[f"policy_{key}"] = str(value)


def _signal_segments(path: str) -> list[PathSegment] | None:
    segments = _parse_path(path)
    if not segments:
        return None
    root = segments[0]
    if root.name != "signals" or root.is_array:
        return None
    return segments[1:]


def _parse_path(path: str) -> list[PathSegment]:
    segments: list[PathSegment] = []
    for raw_segment in path.split("."):
        if not raw_segment:
            return []
        match = _PATH_SEGMENT_RE.match(raw_segment)
        if match is None:
            return []
        segments.append(PathSegment(match.group(1), is_array=match.group(2) is not None))
    return segments


def _assign_placeholder(root: dict[str, Any], segments: list[PathSegment]) -> None:
    if not segments:
        return
    current = root
    for index, segment in enumerate(segments):
        is_last = index == len(segments) - 1
        if segment.is_array:
            value = current.get(segment.name)
            if not isinstance(value, list):
                value = []
                current[segment.name] = value
            if is_last:
                return
            if not value or not isinstance(value[0], dict):
                value[:] = [{}]
            current = value[0]
            continue
        if is_last:
            current.setdefault(segment.name, None)
            return
        value = current.get(segment.name)
        if not isinstance(value, dict):
            value = {}
            current[segment.name] = value
        current = value
