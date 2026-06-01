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
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_int_range(summary, "score", errors, minimum=0, maximum=100, prefix="summary.")
        _require_enum(summary, "status", {"pass", "fail"}, errors, prefix="summary.")
        for key in ("checks_total", "checks_passed", "checks_failed", "checks_warn"):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, result in enumerate(document.get("results", [])):
        if not isinstance(result, dict):
            errors.append(f"results[{index}] must be an object.")
            continue
        prefix = f"results[{index}]."
        _require_string(result, "id", errors, prefix=prefix)
        _require_string(result, "title", errors, prefix=prefix)
        _require_enum(result, "status", {"pass", "fail", "warn"}, errors, prefix=prefix)
        _require_enum(result, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        if not isinstance(result.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        _require_string_type(result, "path", errors, prefix=prefix)
        _require_string_type(result, "operator", errors, prefix=prefix)
    return errors


def validate_action_plan(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Action plan must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "items", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "action_required"}, errors, prefix="summary.")
        for key in (
            "items_total",
            "action_required_count",
            "waived_count",
            "expired_waiver_count",
            "fail_count",
            "warn_count",
            "pass_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, item in enumerate(document.get("items", [])):
        if not isinstance(item, dict):
            errors.append(f"items[{index}] must be an object.")
            continue
        prefix = f"items[{index}]."
        _require_enum(item, "priority", {"P0", "P1", "P2", "P3"}, errors, prefix=prefix)
        _require_string(item, "id", errors, prefix=prefix)
        _require_string(item, "title", errors, prefix=prefix)
        _require_enum(item, "status", {"pass", "fail", "warn"}, errors, prefix=prefix)
        _require_enum(item, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        if not isinstance(item.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        _require_string_type(item, "path", errors, prefix=prefix)
        _require_string_type(item, "operator", errors, prefix=prefix)
        _require_int_range(item, "observed_count", errors, minimum=0, prefix=prefix)
        if "waived" in item and not isinstance(item["waived"], bool):
            errors.append(f"{prefix}waived must be a boolean when present.")
        if "waiver" in item and item["waiver"] is not None:
            _require_mapping(item, "waiver", errors, prefix=prefix)
        _require_string(item, "recommended_action", errors, prefix=prefix)
    return errors


def validate_policy_matrix(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Policy matrix must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "checks", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        for key in (
            "check_count",
            "required_count",
            "optional_count",
            "path_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, check in enumerate(document.get("checks", [])):
        if not isinstance(check, dict):
            errors.append(f"checks[{index}] must be an object.")
            continue
        prefix = f"checks[{index}]."
        _require_string(check, "id", errors, prefix=prefix)
        _require_string(check, "title", errors, prefix=prefix)
        _require_string_type(check, "path", errors, prefix=prefix)
        _require_string_type(check, "operator", errors, prefix=prefix)
        _require_enum(check, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        _require_enum(check, "mode", {"any", "all", "none"}, errors, prefix=prefix)
        if not isinstance(check.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        _require_string_type(check, "remediation", errors, prefix=prefix)
    return errors


def validate_privacy_scan(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Privacy scan must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "findings", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "fail"}, errors, prefix="summary.")
        for key in (
            "files_scanned",
            "files_skipped",
            "findings_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, finding in enumerate(document.get("findings", [])):
        if not isinstance(finding, dict):
            errors.append(f"findings[{index}] must be an object.")
            continue
        prefix = f"findings[{index}]."
        _require_string(finding, "path", errors, prefix=prefix)
        _require_int_range(finding, "line", errors, minimum=1, prefix=prefix)
        _require_string(finding, "kind", errors, prefix=prefix)
        _require_enum(finding, "severity", {"high", "medium", "low"}, errors, prefix=prefix)
        _require_string(finding, "excerpt", errors, prefix=prefix)
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


def _require_enum(
    document: dict[str, Any],
    key: str,
    allowed: set[str],
    errors: list[str],
    prefix: str = "",
) -> None:
    value = document.get(key)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        errors.append(f"{prefix}{key} must be one of: {choices}.")


def _require_int_range(
    document: dict[str, Any],
    key: str,
    errors: list[str],
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    prefix: str = "",
) -> None:
    value = document.get(key)
    if not isinstance(value, int):
        errors.append(f"{prefix}{key} must be an integer.")
        return
    if minimum is not None and value < minimum:
        errors.append(f"{prefix}{key} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        errors.append(f"{prefix}{key} must be at most {maximum}.")


def _require_string_type(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    if not isinstance(document.get(key), str):
        errors.append(f"{prefix}{key} must be a string.")


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
