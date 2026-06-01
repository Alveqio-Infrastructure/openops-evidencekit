from __future__ import annotations

from datetime import datetime
from typing import Any


SUPPORTED_SCHEMA_MAJOR_MINOR = "0.1"


def validate_evidence(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Evidence must be a JSON object."]
    _require_supported_schema_version(document, errors)
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
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "results", errors)
    return errors


def validate_bundle_manifest(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Bundle manifest must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_list(document, "artifacts", errors)
    for index, artifact in enumerate(document.get("artifacts", [])):
        if not isinstance(artifact, dict):
            errors.append(f"artifacts[{index}] must be an object.")
            continue
        prefix = f"artifacts[{index}]."
        _require_string(artifact, "path", errors, prefix=prefix)
        _require_string(artifact, "filename", errors, prefix=prefix)
        _require_string(artifact, "role", errors, prefix=prefix)
        _require_string(artifact, "media_type", errors, prefix=prefix)
        _require_string(artifact, "sha256", errors, prefix=prefix)
        sha256 = artifact.get("sha256")
        if isinstance(sha256, str) and sha256 and not _is_sha256_hex(sha256):
            errors.append(f"{prefix}sha256 must be a lowercase SHA-256 hex digest.")
        if not isinstance(artifact.get("size_bytes"), int) or artifact.get("size_bytes", -1) < 0:
            errors.append(f"{prefix}size_bytes must be a non-negative integer.")
    return errors


def validate_bundle_verification(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Bundle verification must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "results", errors)
    for index, result in enumerate(document.get("results", [])):
        if not isinstance(result, dict):
            errors.append(f"results[{index}] must be an object.")
            continue
        prefix = f"results[{index}]."
        _require_string(result, "path", errors, prefix=prefix)
        _require_string(result, "status", errors, prefix=prefix)
    return errors


def validate_bundle_signature(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Bundle signature must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "manifest", errors)
    _require_mapping(document, "signature", errors)
    manifest = document.get("manifest", {})
    if isinstance(manifest, dict):
        _require_string(manifest, "path", errors, prefix="manifest.")
        sha256 = manifest.get("sha256")
        _require_string(manifest, "sha256", errors, prefix="manifest.")
        if isinstance(sha256, str) and sha256 and not _is_sha256_hex(sha256):
            errors.append("manifest.sha256 must be a lowercase SHA-256 hex digest.")
        if not isinstance(manifest.get("size_bytes"), int) or manifest.get("size_bytes", -1) < 0:
            errors.append("manifest.size_bytes must be a non-negative integer.")
    signature = document.get("signature", {})
    if isinstance(signature, dict):
        _require_string(signature, "algorithm", errors, prefix="signature.")
        if signature.get("algorithm") != "hmac-sha256":
            errors.append("signature.algorithm must be hmac-sha256.")
        value = signature.get("value")
        _require_string(signature, "value", errors, prefix="signature.")
        if isinstance(value, str) and value and not _is_sha256_hex(value):
            errors.append("signature.value must be a lowercase SHA-256 hex digest.")
    return errors


def validate_report_comparison(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Report comparison must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "regressions", errors)
    _require_list(document, "improvements", errors)
    _require_list(document, "neutral_changes", errors)
    _require_list(document, "added", errors)
    _require_list(document, "removed", errors)
    return errors


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _require_string(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{prefix}{key} must be a non-empty string.")


def _require_supported_schema_version(document: dict[str, Any], errors: list[str], prefix: str = "") -> None:
    _require_string(document, "schema_version", errors, prefix=prefix)
    value = document.get("schema_version")
    if not isinstance(value, str) or not value:
        return
    parts = value.split(".")
    if len(parts) < 2 or not all(part.isdigit() for part in parts):
        errors.append(
            f"{prefix}schema_version must be {SUPPORTED_SCHEMA_MAJOR_MINOR} or "
            f"{SUPPORTED_SCHEMA_MAJOR_MINOR}.x."
        )
        return
    if ".".join(parts[:2]) != SUPPORTED_SCHEMA_MAJOR_MINOR:
        errors.append(
            f"{prefix}schema_version {value!r} is not supported; expected "
            f"{SUPPORTED_SCHEMA_MAJOR_MINOR} or {SUPPORTED_SCHEMA_MAJOR_MINOR}.x."
        )


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
