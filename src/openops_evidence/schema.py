from __future__ import annotations

from datetime import datetime
from typing import Any


def validate_evidence(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Evidence must be a JSON object."]
    _require_string(document, "schema_version", errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_list(document, "assets", errors)
    _require_mapping(document, "signals", errors)
    for index, asset in enumerate(document.get("assets", [])):
        if not isinstance(asset, dict):
            errors.append(f"assets[{index}] must be an object.")
            continue
        _require_string(asset, "id", errors, prefix=f"assets[{index}].")
        _require_string(asset, "type", errors, prefix=f"assets[{index}].")
        if "roles" in asset and not isinstance(asset["roles"], list):
            errors.append(f"assets[{index}].roles must be a list when present.")
        if "tags" in asset and not isinstance(asset["tags"], list):
            errors.append(f"assets[{index}].tags must be a list when present.")
    return errors


def validate_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Report must be a JSON object."]
    _require_string(document, "schema_version", errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "results", errors)
    return errors


def _require_string(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{prefix}{key} must be a non-empty string.")


def _require_datetime(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    value = document.get(key)
    if not isinstance(value, str):
        errors.append(f"{prefix}{key} must be an ISO 8601 timestamp string.")
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{prefix}{key} must be an ISO 8601 timestamp string.")


def _require_mapping(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    if not isinstance(document.get(key), dict):
        errors.append(f"{prefix}{key} must be an object.")


def _require_list(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    if not isinstance(document.get(key), list):
        errors.append(f"{prefix}{key} must be a list.")
