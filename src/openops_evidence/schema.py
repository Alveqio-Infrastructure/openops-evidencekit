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


def validate_risk_register(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Risk register must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "risks", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "action_required"}, errors, prefix="summary.")
        for key in (
            "risks_total",
            "open_count",
            "accepted_count",
            "closed_count",
            "expired_acceptance_count",
            "fail_count",
            "warn_count",
            "pass_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, risk in enumerate(document.get("risks", [])):
        if not isinstance(risk, dict):
            errors.append(f"risks[{index}] must be an object.")
            continue
        prefix = f"risks[{index}]."
        _require_enum(risk, "priority", {"P0", "P1", "P2", "P3"}, errors, prefix=prefix)
        _require_string(risk, "id", errors, prefix=prefix)
        _require_string(risk, "title", errors, prefix=prefix)
        _require_enum(risk, "risk_status", {"open", "accepted", "closed"}, errors, prefix=prefix)
        _require_enum(risk, "source_status", {"fail", "warn", "pass"}, errors, prefix=prefix)
        _require_enum(risk, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        if not isinstance(risk.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        for key in (
            "path",
            "operator",
            "owner",
            "waiver_status",
            "waiver_expires_at",
            "acceptance_reason",
            "recommended_action",
        ):
            _require_string_type(risk, key, errors, prefix=prefix)
        _require_int_range(risk, "observed_count", errors, minimum=0, prefix=prefix)
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


def validate_inventory(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Inventory must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "assets", errors)
    _require_list(document, "signal_domains", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        for key in (
            "assets_total",
            "asset_type_count",
            "hostnames_total",
            "role_count",
            "tag_count",
            "signal_domain_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, asset in enumerate(document.get("assets", [])):
        if not isinstance(asset, dict):
            errors.append(f"assets[{index}] must be an object.")
            continue
        prefix = f"assets[{index}]."
        _require_string(asset, "id", errors, prefix=prefix)
        _require_string(asset, "type", errors, prefix=prefix)
        _require_string_type(asset, "hostname", errors, prefix=prefix)
        _require_list(asset, "roles", errors, prefix=prefix)
        _require_list(asset, "tags", errors, prefix=prefix)
    for index, signal in enumerate(document.get("signal_domains", [])):
        if not isinstance(signal, dict):
            errors.append(f"signal_domains[{index}] must be an object.")
            continue
        prefix = f"signal_domains[{index}]."
        _require_string(signal, "name", errors, prefix=prefix)
        _require_enum(signal, "kind", {"object", "array", "scalar"}, errors, prefix=prefix)
        _require_int_range(signal, "item_count", errors, minimum=0, prefix=prefix)
        _require_list(signal, "fields", errors, prefix=prefix)
    return errors


def validate_evidence_drift(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Evidence drift report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "asset_changes", errors)
    _require_list(document, "domain_changes", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in (
            "base_assets",
            "current_assets",
            "asset_changes_count",
            "asset_added_count",
            "asset_removed_count",
            "asset_changed_count",
            "base_domains",
            "current_domains",
            "domain_changes_count",
            "domain_added_count",
            "domain_removed_count",
            "domain_changed_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, change in enumerate(document.get("asset_changes", [])):
        _validate_drift_change(change, errors, f"asset_changes[{index}].", "id")
    for index, change in enumerate(document.get("domain_changes", [])):
        _validate_drift_change(change, errors, f"domain_changes[{index}].", "name")
    return errors


def validate_review_attestation(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Review attestation must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_mapping(document, "manifest", errors)
    _require_list(document, "checks", errors)
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        _require_string(metadata, "approver", errors, prefix="metadata.")
        _require_string(metadata, "role", errors, prefix="metadata.")
        _require_string(metadata, "statement", errors, prefix="metadata.")
        _require_string_type(metadata, "review_id", errors, prefix="metadata.")
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in ("checks_total", "checks_passed", "checks_warn", "artifact_count"):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    manifest = document.get("manifest")
    if isinstance(manifest, dict):
        _require_string(manifest, "path", errors, prefix="manifest.")
        _require_string_type(manifest, "name", errors, prefix="manifest.")
        _require_int_range(manifest, "artifact_count", errors, minimum=0, prefix="manifest.")
        _require_int_range(manifest, "size_bytes", errors, minimum=0, prefix="manifest.")
        _require_string(manifest, "sha256", errors, prefix="manifest.")
        sha256 = manifest.get("sha256")
        if isinstance(sha256, str) and sha256 and not _is_sha256_hex(sha256):
            errors.append("manifest.sha256 must be a lowercase SHA-256 hex digest.")
    for index, check in enumerate(document.get("checks", [])):
        if not isinstance(check, dict):
            errors.append(f"checks[{index}] must be an object.")
            continue
        prefix = f"checks[{index}]."
        _require_string(check, "id", errors, prefix=prefix)
        _require_string(check, "title", errors, prefix=prefix)
        _require_enum(check, "status", {"pass", "warn"}, errors, prefix=prefix)
        _require_string_type(check, "observed", errors, prefix=prefix)
    return errors


def validate_review_summary(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Review summary must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "decision", errors)
    _require_mapping(document, "metrics", errors)
    _require_list(document, "highlights", errors)
    _require_list(document, "next_steps", errors)
    decision = document.get("decision")
    if isinstance(decision, dict):
        _require_enum(decision, "status", {"pass", "warn", "fail"}, errors, prefix="decision.")
        _require_enum(
            decision,
            "recommendation",
            {"ready_for_handoff", "review_required", "blocked"},
            errors,
            prefix="decision.",
        )
        _require_string(decision, "reason", errors, prefix="decision.")
    metrics = document.get("metrics")
    if isinstance(metrics, dict):
        for key in ("report_status", "gate_status"):
            _require_string(metrics, key, errors, prefix="metrics.")
        if "readiness_score" not in metrics:
            errors.append("metrics.readiness_score is required.")
        elif metrics["readiness_score"] is not None:
            _require_int_range(metrics, "readiness_score", errors, minimum=0, maximum=100, prefix="metrics.")
        for key in (
            "checks_failed",
            "checks_warn",
            "open_risks",
            "accepted_risks",
            "expired_acceptances",
            "stale_timestamps",
            "invalid_timestamps",
            "restore_failures",
            "restore_warnings",
            "mail_failures",
            "mail_warnings",
            "tls_failures",
            "tls_warnings",
            "access_failures",
            "access_warnings",
            "monitoring_failures",
            "monitoring_warnings",
            "privacy_findings",
            "scope_warnings",
            "drift_changes",
            "catalog_warnings",
            "runbook_warnings",
        ):
            _require_int_range(metrics, key, errors, minimum=0, prefix="metrics.")
    return errors


def validate_scope_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Scope report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "assets", errors)
    _require_list(document, "domains", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in (
            "assets_declared",
            "evidence_assets",
            "in_scope_assets",
            "out_of_scope_assets",
            "missing_in_scope_assets",
            "unclassified_evidence_assets",
            "out_of_scope_evidence_assets",
            "domains_declared",
            "evidence_domains",
            "in_scope_domains",
            "out_of_scope_domains",
            "missing_required_domains",
            "unclassified_evidence_domains",
            "out_of_scope_evidence_domains",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, asset in enumerate(document.get("assets", [])):
        if not isinstance(asset, dict):
            errors.append(f"assets[{index}] must be an object.")
            continue
        prefix = f"assets[{index}]."
        _require_string(asset, "id", errors, prefix=prefix)
        _require_enum(asset, "scope_status", {"in_scope", "out_of_scope", "unclassified"}, errors, prefix=prefix)
        _require_enum(
            asset,
            "status",
            {
                "present_in_scope",
                "present_out_of_scope",
                "missing_in_scope",
                "out_of_scope_not_seen",
                "unclassified_evidence",
            },
            errors,
            prefix=prefix,
        )
        for key in ("present", "declared"):
            if not isinstance(asset.get(key), bool):
                errors.append(f"{prefix}{key} must be a boolean.")
        for key in ("type", "hostname", "owner", "reason"):
            _require_string_type(asset, key, errors, prefix=prefix)
    for index, domain in enumerate(document.get("domains", [])):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object.")
            continue
        prefix = f"domains[{index}]."
        _require_string(domain, "name", errors, prefix=prefix)
        _require_enum(domain, "scope_status", {"in_scope", "out_of_scope", "unclassified"}, errors, prefix=prefix)
        _require_enum(
            domain,
            "status",
            {
                "present_in_scope",
                "present_out_of_scope",
                "missing_in_scope",
                "missing_optional",
                "out_of_scope_not_seen",
                "unclassified_evidence",
            },
            errors,
            prefix=prefix,
        )
        for key in ("present", "declared", "required"):
            if not isinstance(domain.get(key), bool):
                errors.append(f"{prefix}{key} must be a boolean.")
        _require_string_type(domain, "kind", errors, prefix=prefix)
        _require_int_range(domain, "item_count", errors, minimum=0, prefix=prefix)
        _require_list(domain, "fields", errors, prefix=prefix)
        for key in ("owner", "reason"):
            _require_string_type(domain, key, errors, prefix=prefix)
    return errors


def validate_service_catalog_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Service catalog report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "services", errors)
    _require_list(document, "unassigned_assets", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in (
            "services_total",
            "services_passed",
            "services_warn",
            "critical_services",
            "high_services",
            "catalog_assets_total",
            "evidence_assets_total",
            "missing_catalog_assets_count",
            "unassigned_evidence_assets_count",
            "missing_domains_count",
            "missing_runbooks_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, service in enumerate(document.get("services", [])):
        if not isinstance(service, dict):
            errors.append(f"services[{index}] must be an object.")
            continue
        prefix = f"services[{index}]."
        _require_string(service, "id", errors, prefix=prefix)
        _require_string(service, "name", errors, prefix=prefix)
        _require_string(service, "owner", errors, prefix=prefix)
        _require_enum(service, "criticality", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        _require_enum(service, "status", {"pass", "warn"}, errors, prefix=prefix)
        for key in (
            "contacts",
            "assets",
            "present_assets",
            "missing_assets",
            "domains",
            "present_domains",
            "missing_domains",
            "runbooks",
            "present_runbooks",
            "missing_runbooks",
        ):
            _require_list(service, key, errors, prefix=prefix)
    for index, asset in enumerate(document.get("unassigned_assets", [])):
        if not isinstance(asset, dict):
            errors.append(f"unassigned_assets[{index}] must be an object.")
            continue
        prefix = f"unassigned_assets[{index}]."
        _require_string(asset, "id", errors, prefix=prefix)
        for key in ("type", "hostname"):
            _require_string_type(asset, key, errors, prefix=prefix)
        _require_list(asset, "roles", errors, prefix=prefix)
        _require_list(asset, "tags", errors, prefix=prefix)
    return errors


def validate_runbook_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Runbook report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "runbooks", errors)
    _require_list(document, "services", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in (
            "runbooks_total",
            "observed_runbooks",
            "expected_runbooks",
            "missing_runbooks_count",
            "stale_runbooks_count",
            "unreferenced_runbooks_count",
            "invalid_timestamp_count",
            "services_total",
            "services_with_missing_runbooks",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, runbook in enumerate(document.get("runbooks", [])):
        if not isinstance(runbook, dict):
            errors.append(f"runbooks[{index}] must be an object.")
            continue
        prefix = f"runbooks[{index}]."
        _require_string(runbook, "name", errors, prefix=prefix)
        _require_enum(runbook, "status", {"current", "missing", "stale", "unreferenced", "warn"}, errors, prefix=prefix)
        for key in ("path", "updated_at", "reason"):
            _require_string_type(runbook, key, errors, prefix=prefix)
        if "age_days" not in runbook:
            errors.append(f"{prefix}age_days is required.")
        elif runbook["age_days"] is not None:
            _require_int_range(runbook, "age_days", errors, minimum=0, prefix=prefix)
        if "timestamp_valid" not in runbook:
            errors.append(f"{prefix}timestamp_valid is required.")
        elif runbook["timestamp_valid"] is not None and not isinstance(runbook["timestamp_valid"], bool):
            errors.append(f"{prefix}timestamp_valid must be a boolean or null.")
        for key in ("expected", "observed"):
            if not isinstance(runbook.get(key), bool):
                errors.append(f"{prefix}{key} must be a boolean.")
        _require_list(runbook, "referenced_by", errors, prefix=prefix)
    for index, service in enumerate(document.get("services", [])):
        if not isinstance(service, dict):
            errors.append(f"services[{index}] must be an object.")
            continue
        prefix = f"services[{index}]."
        _require_string(service, "id", errors, prefix=prefix)
        _require_string_type(service, "name", errors, prefix=prefix)
        _require_string_type(service, "owner", errors, prefix=prefix)
        _require_enum(service, "status", {"pass", "warn"}, errors, prefix=prefix)
        for key in ("runbooks", "present_runbooks", "missing_runbooks"):
            _require_list(service, key, errors, prefix=prefix)
    return errors


def validate_freshness_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Freshness report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "timestamps", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        for key in ("timestamps_total", "current_count", "stale_count", "future_count", "invalid_count"):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
        for key in ("oldest_age_days", "newest_age_days"):
            if key not in summary:
                errors.append(f"summary.{key} is required.")
            elif summary[key] is not None:
                _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, item in enumerate(document.get("timestamps", [])):
        if not isinstance(item, dict):
            errors.append(f"timestamps[{index}] must be an object.")
            continue
        prefix = f"timestamps[{index}]."
        _require_string(item, "path", errors, prefix=prefix)
        _require_enum(item, "status", {"current", "stale", "future", "invalid"}, errors, prefix=prefix)
        _require_string_type(item, "value", errors, prefix=prefix)
        _require_string(item, "reason", errors, prefix=prefix)
        for key in ("age_days", "future_days", "max_age_days"):
            if key not in item:
                errors.append(f"{prefix}{key} is required.")
            elif item[key] is not None:
                _require_int_range(item, key, errors, minimum=0, prefix=prefix)
        if not isinstance(item.get("timestamp_valid"), bool):
            errors.append(f"{prefix}timestamp_valid must be a boolean.")
    return errors


def validate_restore_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Restore report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "checks", errors)
    _require_list(document, "restore_tests", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        for key in ("tool", "last_success_at", "latest_restore_test_at"):
            _require_string_type(summary, key, errors, prefix="summary.")
        for key in ("repository_count", "last_success_age_days", "latest_restore_test_age_days"):
            if key not in summary:
                errors.append(f"summary.{key} is required.")
            elif summary[key] is not None:
                _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
        for key in (
            "restore_tests_total",
            "successful_restore_tests",
            "failed_restore_tests",
            "stale_restore_tests",
            "unknown_restore_tests",
            "invalid_timestamp_count",
            "future_restore_tests",
            "protected_hosts_count",
            "protected_paths_count",
            "checks_total",
            "checks_passed",
            "checks_warn",
            "checks_failed",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, check in enumerate(document.get("checks", [])):
        if not isinstance(check, dict):
            errors.append(f"checks[{index}] must be an object.")
            continue
        prefix = f"checks[{index}]."
        _require_string(check, "id", errors, prefix=prefix)
        _require_string(check, "title", errors, prefix=prefix)
        _require_enum(check, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
        _require_enum(check, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        for key in ("path", "reason", "recommended_action"):
            _require_string_type(check, key, errors, prefix=prefix)
    for index, item in enumerate(document.get("restore_tests", [])):
        if not isinstance(item, dict):
            errors.append(f"restore_tests[{index}] must be an object.")
            continue
        prefix = f"restore_tests[{index}]."
        _require_string(item, "id", errors, prefix=prefix)
        _require_enum(item, "status", {"current", "stale", "future", "invalid", "failed", "unknown"}, errors, prefix=prefix)
        _require_enum(item, "outcome", {"pass", "fail", "unknown"}, errors, prefix=prefix)
        for key in ("target", "tested_at", "verifier", "path", "reason"):
            _require_string_type(item, key, errors, prefix=prefix)
        for key in ("age_days", "max_age_days"):
            if key not in item:
                errors.append(f"{prefix}{key} is required.")
            elif item[key] is not None:
                _require_int_range(item, key, errors, minimum=0, prefix=prefix)
        if not isinstance(item.get("timestamp_valid"), bool):
            errors.append(f"{prefix}timestamp_valid must be a boolean.")
    return errors


def validate_mail_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Mail report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "domains", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        for key in (
            "domains_total",
            "domains_passed",
            "domains_warn",
            "domains_failed",
            "spf_passed",
            "spf_missing",
            "dkim_passed",
            "dkim_missing",
            "dmarc_enforced",
            "dmarc_monitoring",
            "dmarc_missing",
            "dmarc_unknown",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, domain in enumerate(document.get("domains", [])):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object.")
            continue
        prefix = f"domains[{index}]."
        _require_string(domain, "domain", errors, prefix=prefix)
        _require_enum(domain, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
        if domain.get("spf") is not None and not isinstance(domain.get("spf"), bool):
            errors.append(f"{prefix}spf must be a boolean or null.")
        if domain.get("dkim") is not None and not isinstance(domain.get("dkim"), bool):
            errors.append(f"{prefix}dkim must be a boolean or null.")
        _require_string_type(domain, "dmarc", errors, prefix=prefix)
        _require_string(domain, "dmarc_policy", errors, prefix=prefix)
        _require_enum(domain, "dmarc_status", {"enforced", "monitoring", "missing", "unknown"}, errors, prefix=prefix)
        for key in ("reason", "recommended_action"):
            _require_string(domain, key, errors, prefix=prefix)
    return errors


def validate_tls_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["TLS report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "certificates", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        for key in (
            "certificates_total",
            "certificates_passed",
            "certificates_warn",
            "certificates_failed",
            "expired_count",
            "expiring_soon_count",
            "invalid_count",
            "unknown_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, certificate in enumerate(document.get("certificates", [])):
        if not isinstance(certificate, dict):
            errors.append(f"certificates[{index}] must be an object.")
            continue
        prefix = f"certificates[{index}]."
        _require_string(certificate, "hostname", errors, prefix=prefix)
        if "port" not in certificate:
            errors.append(f"{prefix}port is required.")
        elif certificate["port"] is not None:
            _require_int_range(certificate, "port", errors, minimum=1, prefix=prefix)
        _require_enum(certificate, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
        _require_enum(
            certificate,
            "certificate_status",
            {"current", "expiring_soon", "expired", "invalid", "unknown"},
            errors,
            prefix=prefix,
        )
        _require_string_type(certificate, "not_after", errors, prefix=prefix)
        if "days_remaining" not in certificate:
            errors.append(f"{prefix}days_remaining is required.")
        elif certificate["days_remaining"] is not None:
            _require_int(certificate, "days_remaining", errors, prefix=prefix)
        for key in ("issuer", "reason", "recommended_action"):
            _require_string_type(certificate, key, errors, prefix=prefix)
    return errors


def validate_access_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Access report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "checks", errors)
    _require_list(document, "entrypoints", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        for key in ("ssh_public_exposed", "mfa_required"):
            if key not in summary:
                errors.append(f"summary.{key} is required.")
            elif summary[key] is not None and not isinstance(summary[key], bool):
                errors.append(f"summary.{key} must be a boolean or null.")
        for key in (
            "entrypoints_total",
            "safe_entrypoints",
            "risky_entrypoints",
            "unknown_entrypoints",
            "checks_total",
            "checks_passed",
            "checks_warn",
            "checks_failed",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, check in enumerate(document.get("checks", [])):
        if not isinstance(check, dict):
            errors.append(f"checks[{index}] must be an object.")
            continue
        prefix = f"checks[{index}]."
        _require_string(check, "id", errors, prefix=prefix)
        _require_string(check, "title", errors, prefix=prefix)
        _require_enum(check, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
        _require_enum(check, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        for key in ("path", "reason", "recommended_action"):
            _require_string_type(check, key, errors, prefix=prefix)
    for index, entrypoint in enumerate(document.get("entrypoints", [])):
        if not isinstance(entrypoint, dict):
            errors.append(f"entrypoints[{index}] must be an object.")
            continue
        prefix = f"entrypoints[{index}]."
        _require_string(entrypoint, "name", errors, prefix=prefix)
        _require_enum(entrypoint, "status", {"safe", "risky", "unknown"}, errors, prefix=prefix)
        _require_string(entrypoint, "reason", errors, prefix=prefix)
    return errors


def _validate_drift_change(change: Any, errors: list[str], prefix: str, name_key: str) -> None:
    if not isinstance(change, dict):
        errors.append(f"{prefix[:-1]} must be an object.")
        return
    _require_string(change, name_key, errors, prefix=prefix)
    _require_enum(change, "change_type", {"added", "removed", "changed"}, errors, prefix=prefix)
    if "before" not in change:
        errors.append(f"{prefix}before is required.")
    elif change["before"] is not None and not isinstance(change["before"], dict):
        errors.append(f"{prefix}before must be an object or null.")
    if "after" not in change:
        errors.append(f"{prefix}after is required.")
    elif change["after"] is not None and not isinstance(change["after"], dict):
        errors.append(f"{prefix}after must be an object or null.")
    _require_list(change, "changed_fields", errors, prefix=prefix)


def _validate_operational_check(check: Any, errors: list[str], prefix: str) -> None:
    if not isinstance(check, dict):
        errors.append(f"{prefix[:-1]} must be an object.")
        return
    _require_string(check, "id", errors, prefix=prefix)
    _require_string(check, "title", errors, prefix=prefix)
    _require_enum(check, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
    _require_enum(check, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
    for key in ("path", "reason", "recommended_action"):
        _require_string_type(check, key, errors, prefix=prefix)


def validate_policy_coverage(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Policy coverage must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "domains", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn"}, errors, prefix="summary.")
        _require_int_range(summary, "coverage_percent", errors, minimum=0, maximum=100, prefix="summary.")
        for key in (
            "evidence_domains_total",
            "policy_domains_total",
            "domains_total",
            "covered_domains_count",
            "unreviewed_evidence_domains_count",
            "missing_evidence_domains_count",
            "checks_total",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, domain in enumerate(document.get("domains", [])):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object.")
            continue
        prefix = f"domains[{index}]."
        _require_string(domain, "domain", errors, prefix=prefix)
        _require_enum(
            domain,
            "status",
            {"covered", "unreviewed_evidence", "missing_evidence"},
            errors,
            prefix=prefix,
        )
        for key in ("evidence_present", "policy_present"):
            if not isinstance(domain.get(key), bool):
                errors.append(f"{prefix}{key} must be a boolean.")
        for key in ("check_count", "required_count", "optional_count"):
            _require_int_range(domain, key, errors, minimum=0, prefix=prefix)
        _require_list(domain, "check_ids", errors, prefix=prefix)
        _require_list(domain, "paths", errors, prefix=prefix)
    return errors


def validate_questionnaire(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Questionnaire must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "questions", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        for key in (
            "questions_total",
            "domain_count",
            "required_count",
            "optional_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, question in enumerate(document.get("questions", [])):
        if not isinstance(question, dict):
            errors.append(f"questions[{index}] must be an object.")
            continue
        prefix = f"questions[{index}]."
        _require_string(question, "id", errors, prefix=prefix)
        _require_string(question, "domain", errors, prefix=prefix)
        _require_string(question, "title", errors, prefix=prefix)
        if not isinstance(question.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        _require_enum(question, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        _require_string_type(question, "path", errors, prefix=prefix)
        _require_string_type(question, "operator", errors, prefix=prefix)
        _require_string(question, "request", errors, prefix=prefix)
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


def validate_scorecard(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Scorecard must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "domains", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        _require_int_range(summary, "source_score", errors, minimum=0, maximum=100, prefix="summary.")
        for key in (
            "domains_total",
            "domains_passed",
            "domains_failed",
            "domains_warn",
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, domain in enumerate(document.get("domains", [])):
        if not isinstance(domain, dict):
            errors.append(f"domains[{index}] must be an object.")
            continue
        prefix = f"domains[{index}]."
        _require_string(domain, "domain", errors, prefix=prefix)
        _require_string(domain, "title", errors, prefix=prefix)
        _require_enum(domain, "status", {"pass", "warn", "fail"}, errors, prefix=prefix)
        _require_int_range(domain, "score", errors, minimum=0, maximum=100, prefix=prefix)
        for key in (
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(domain, key, errors, minimum=0, prefix=prefix)
        _require_list(domain, "checks", errors, prefix=prefix)
        for check_index, check in enumerate(domain.get("checks", [])):
            if not isinstance(check, dict):
                errors.append(f"{prefix}checks[{check_index}] must be an object.")
                continue
            check_prefix = f"{prefix}checks[{check_index}]."
            _require_string(check, "id", errors, prefix=check_prefix)
            _require_string(check, "title", errors, prefix=check_prefix)
            _require_enum(check, "status", {"pass", "warn", "fail"}, errors, prefix=check_prefix)
            _require_enum(check, "severity", {"critical", "high", "medium", "low"}, errors, prefix=check_prefix)
            if not isinstance(check.get("required"), bool):
                errors.append(f"{check_prefix}required must be a boolean.")
            _require_string_type(check, "path", errors, prefix=check_prefix)
    return errors


def validate_gate_result(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Gate result must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "conditions", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "fail"}, errors, prefix="summary.")
        for key in (
            "conditions_total",
            "conditions_failed",
            "source_score",
            "source_failed",
            "source_warnings",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, condition in enumerate(document.get("conditions", [])):
        if not isinstance(condition, dict):
            errors.append(f"conditions[{index}] must be an object.")
            continue
        prefix = f"conditions[{index}]."
        _require_string(condition, "id", errors, prefix=prefix)
        _require_string(condition, "title", errors, prefix=prefix)
        _require_enum(condition, "status", {"pass", "fail"}, errors, prefix=prefix)
        _require_string(condition, "operator", errors, prefix=prefix)
        if "observed" not in condition:
            errors.append(f"{prefix}observed is required.")
        if "expected" not in condition:
            errors.append(f"{prefix}expected is required.")
    return errors


def validate_badge(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Badge must be a JSON object."]
    schema_version = document.get("schemaVersion")
    if schema_version != 1:
        errors.append("schemaVersion must be 1.")
    for key in ("label", "message", "color"):
        _require_string(document, key, errors)
    return errors


def validate_monitoring_report(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Monitoring report must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "checks", errors)
    _require_list(document, "down_targets", errors)
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        _require_datetime(metadata, "evaluated_at", errors, prefix="metadata.")
        _require_int_range(metadata, "max_alert_test_age_days", errors, minimum=0, prefix="metadata.")
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "warn", "fail"}, errors, prefix="summary.")
        _require_string_type(summary, "system", errors, prefix="summary.")
        for key in (
            "down_targets_count",
            "alert_channels_total",
            "checks_total",
            "checks_passed",
            "checks_warn",
            "checks_failed",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
        for key in ("targets", "targets_total", "targets_up", "targets_down"):
            if summary.get(key) is not None:
                _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
        if summary.get("last_alert_test_age_days") is not None:
            _require_int(summary, "last_alert_test_age_days", errors, prefix="summary.")
        if not isinstance(summary.get("last_alert_test_at"), str):
            errors.append("summary.last_alert_test_at must be a string.")
    for index, check in enumerate(document.get("checks", [])):
        _validate_operational_check(check, errors, f"checks[{index}].")
    for index, target in enumerate(document.get("down_targets", [])):
        if not isinstance(target, dict):
            errors.append(f"down_targets[{index}] must be an object.")
            continue
        prefix = f"down_targets[{index}]."
        _require_string(target, "target", errors, prefix=prefix)
        _require_string(target, "status", errors, prefix=prefix)
        _require_string_type(target, "reason", errors, prefix=prefix)
    return errors


def validate_report_history(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Report history must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "entries", errors)
    entries = document.get("entries")
    if isinstance(entries, list) and not entries:
        errors.append("entries must contain at least one item.")
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_int_range(summary, "entries_total", errors, minimum=1, prefix="summary.")
        _require_enum(summary, "latest_status", {"pass", "fail"}, errors, prefix="summary.")
        for key in (
            "latest_score",
            "previous_score",
            "best_score",
            "worst_score",
        ):
            _require_int_range(summary, key, errors, minimum=0, maximum=100, prefix="summary.")
        for key in ("latest_failed", "latest_warnings"):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
        for key in ("score_change", "failed_delta", "warnings_delta"):
            _require_int(summary, key, errors, prefix="summary.")
    for index, entry in enumerate(document.get("entries", [])):
        if not isinstance(entry, dict):
            errors.append(f"entries[{index}] must be an object.")
            continue
        prefix = f"entries[{index}]."
        _require_datetime(entry, "recorded_at", errors, prefix=prefix)
        _require_datetime(entry, "report_generated_at", errors, prefix=prefix)
        _require_string_type(entry, "source", errors, prefix=prefix)
        _require_string_type(entry, "note", errors, prefix=prefix)
        _require_enum(entry, "status", {"pass", "fail"}, errors, prefix=prefix)
        _require_int_range(entry, "score", errors, minimum=0, maximum=100, prefix=prefix)
        for key in ("checks_total", "checks_passed", "checks_failed", "checks_warn"):
            _require_int_range(entry, key, errors, minimum=0, prefix=prefix)
    return errors


def validate_executive_brief(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Executive brief must be a JSON object."]
    _require_supported_schema_version(document, errors)
    _require_datetime(document, "generated_at", errors)
    _require_mapping(document, "metadata", errors)
    _require_mapping(document, "summary", errors)
    _require_list(document, "top_findings", errors)
    _require_list(document, "next_steps", errors)
    summary = document.get("summary")
    if isinstance(summary, dict):
        _require_enum(summary, "status", {"pass", "fail"}, errors, prefix="summary.")
        _require_enum(summary, "health", {"on_track", "watch", "action_required"}, errors, prefix="summary.")
        _require_string(summary, "message", errors, prefix="summary.")
        _require_int_range(summary, "score", errors, minimum=0, maximum=100, prefix="summary.")
        for key in (
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
            "top_findings_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ):
            _require_int_range(summary, key, errors, minimum=0, prefix="summary.")
    for index, finding in enumerate(document.get("top_findings", [])):
        if not isinstance(finding, dict):
            errors.append(f"top_findings[{index}] must be an object.")
            continue
        prefix = f"top_findings[{index}]."
        _require_string(finding, "id", errors, prefix=prefix)
        _require_string(finding, "title", errors, prefix=prefix)
        _require_enum(finding, "status", {"fail", "warn"}, errors, prefix=prefix)
        _require_enum(finding, "severity", {"critical", "high", "medium", "low"}, errors, prefix=prefix)
        if not isinstance(finding.get("required"), bool):
            errors.append(f"{prefix}required must be a boolean.")
        _require_string_type(finding, "path", errors, prefix=prefix)
        _require_string(finding, "remediation", errors, prefix=prefix)
    for index, step in enumerate(document.get("next_steps", [])):
        if not isinstance(step, str) or not step:
            errors.append(f"next_steps[{index}] must be a non-empty string.")
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


def _require_int(document: dict[str, Any], key: str, errors: list[str], prefix: str = "") -> None:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(f"{prefix}{key} must be an integer.")


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
