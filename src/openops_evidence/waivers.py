from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def validate_waiver_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Waiver document must be a table/object."]
    metadata = document.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be a table/object when present.")
    waivers = document.get("waivers")
    if not isinstance(waivers, list):
        return [*errors, "waivers must be a list."]
    seen: set[str] = set()
    for index, waiver in enumerate(waivers):
        prefix = f"waivers[{index}]"
        if not isinstance(waiver, dict):
            errors.append(f"{prefix} must be a table/object.")
            continue
        check_id = _required_string(waiver, "check_id", errors, prefix)
        if check_id:
            if check_id in seen:
                errors.append(f"{prefix}.check_id duplicates another waiver: {check_id}")
            seen.add(check_id)
        _required_string(waiver, "owner", errors, prefix)
        _required_string(waiver, "reason", errors, prefix)
        expires_at = _required_string(waiver, "expires_at", errors, prefix)
        if expires_at and _parse_datetime(expires_at) is None:
            errors.append(f"{prefix}.expires_at must be an ISO 8601 timestamp string.")
    return errors


def waiver_index(document: dict[str, Any], *, now: datetime | None = None) -> dict[str, dict[str, Any]]:
    current_time = now or datetime.now(UTC)
    indexed = {}
    for waiver in document.get("waivers", []):
        if not isinstance(waiver, dict):
            continue
        expires_at = _parse_datetime(waiver.get("expires_at"))
        check_id = waiver.get("check_id")
        if not isinstance(check_id, str) or not check_id or expires_at is None:
            continue
        indexed[check_id] = {
            "check_id": check_id,
            "owner": str(waiver.get("owner") or ""),
            "reason": str(waiver.get("reason") or ""),
            "expires_at": expires_at.isoformat(),
            "status": "active" if expires_at > current_time else "expired",
        }
    return indexed


def _required_string(
    item: dict[str, Any],
    key: str,
    errors: list[str],
    prefix: str,
) -> str | None:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{prefix}.{key} must be a non-empty string.")
        return None
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
