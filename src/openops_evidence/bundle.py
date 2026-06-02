from __future__ import annotations

import hashlib
import hmac
import json
import os
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schema import (
    validate_action_plan,
    validate_badge,
    validate_bundle_signature,
    validate_bundle_verification,
    validate_evidence,
    validate_evidence_drift,
    validate_executive_brief,
    validate_freshness_report,
    validate_gate_result,
    validate_inventory,
    validate_mail_report,
    validate_policy_coverage,
    validate_questionnaire,
    validate_report,
    validate_report_comparison,
    validate_report_history,
    validate_review_attestation,
    validate_review_summary,
    validate_restore_report,
    validate_risk_register,
    validate_runbook_report,
    validate_scorecard,
    validate_service_catalog_report,
    validate_scope_report,
)
from .waivers import validate_waiver_document

SIGNATURE_ALGORITHM = "hmac-sha256"
DEFAULT_SIGNING_KEY_ENV = "OPENOPS_BUNDLE_SIGNING_KEY"


def create_bundle_manifest(
    paths: list[str],
    name: str = "openops-evidence-bundle",
    base_dir: str | None = None,
) -> dict[str, Any]:
    if not paths:
        raise ValueError("At least one artifact path is required")
    base = Path(base_dir).resolve() if base_dir else None
    artifacts = [_artifact_record(Path(path), base) for path in paths]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "name": name,
            "created_by": "openops-evidencekit",
            "artifact_count": len(artifacts),
        },
        "artifacts": artifacts,
    }


def create_bundle_signature(
    manifest_path: str,
    key: bytes,
    key_id: str | None = None,
) -> dict[str, Any]:
    manifest = Path(manifest_path)
    manifest_bytes = _read_bytes(manifest)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "key_id": key_id or "default",
        },
        "manifest": {
            "path": manifest.name,
            "size_bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "value": _signature_value(manifest_bytes, key),
        },
    }


def verify_bundle_manifest(manifest: dict[str, Any], base_dir: str | None = None) -> dict[str, Any]:
    base = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    results = [_verify_artifact(artifact, base) for artifact in manifest.get("artifacts", [])]
    missing = [item for item in results if item["status"] == "missing"]
    mismatched = [item for item in results if item["status"] == "mismatch"]
    verified = [item for item in results if item["status"] == "verified"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "manifest_name": manifest.get("metadata", {}).get("name"),
            "base_dir": str(base),
        },
        "summary": {
            "status": "fail" if missing or mismatched else "pass",
            "artifacts_total": len(results),
            "verified_count": len(verified),
            "missing_count": len(missing),
            "mismatched_count": len(mismatched),
        },
        "results": results,
    }


def create_bundle_archive(
    manifest: dict[str, Any],
    manifest_path: str,
    output_path: str,
    base_dir: str | None = None,
    *,
    include_manifest: bool = True,
) -> dict[str, Any]:
    base = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    archive_path = Path(output_path)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    records = _archive_records(manifest, base)
    seen_names: set[str] = set()
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if include_manifest:
            manifest_file = Path(manifest_path)
            if not manifest_file.is_file():
                raise ValueError(f"Manifest does not exist or is not a file: {manifest_path}")
            _write_archive_file(archive, manifest_file, manifest_file.name, seen_names)
        for source, archive_name in records:
            _write_archive_file(archive, source, archive_name, seen_names)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "archive_path": str(archive_path),
            "manifest_included": include_manifest,
            "file_count": len(seen_names),
        },
        "files": sorted(seen_names),
    }


def verify_bundle_signature(
    manifest_path: str,
    signature_document: dict[str, Any],
    key: bytes,
) -> dict[str, Any]:
    manifest = Path(manifest_path)
    manifest_bytes = _read_bytes(manifest)
    actual_size = len(manifest_bytes)
    actual_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    metadata_record = _mapping_value(signature_document, "metadata")
    manifest_record = _mapping_value(signature_document, "manifest")
    signature_record = _mapping_value(signature_document, "signature")
    expected_sha256 = manifest_record.get("sha256")
    expected_size = manifest_record.get("size_bytes")
    expected_signature = signature_record.get("value")
    expected_algorithm = signature_record.get("algorithm")
    signature_errors = validate_bundle_signature(signature_document)
    manifest_status = (
        "verified"
        if expected_size == actual_size and expected_sha256 == actual_sha256
        else "mismatch"
    )
    actual_signature = _signature_value(manifest_bytes, key)
    signature_status = (
        "verified"
        if expected_algorithm == SIGNATURE_ALGORITHM
        and isinstance(expected_signature, str)
        and hmac.compare_digest(expected_signature, actual_signature)
        else "mismatch"
    )
    status = "pass" if not signature_errors and manifest_status == "verified" and signature_status == "verified" else "fail"
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "manifest_path": manifest.name,
            "key_id": metadata_record.get("key_id"),
            "algorithm": expected_algorithm,
        },
        "summary": {
            "status": status,
            "manifest_hash_match": manifest_status == "verified",
            "signature_match": signature_status == "verified",
            "signature_document_valid": not signature_errors,
        },
        "results": [
            {
                "path": manifest.name,
                "check": "manifest-sha256",
                "expected_size_bytes": expected_size,
                "actual_size_bytes": actual_size,
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
                "status": manifest_status,
            },
            {
                "path": manifest.name,
                "check": SIGNATURE_ALGORITHM,
                "expected_signature": expected_signature,
                "actual_signature": actual_signature,
                "status": signature_status,
            },
        ],
        "errors": signature_errors,
    }


def load_signing_key(
    *,
    key_file: str | None = None,
    key_env: str = DEFAULT_SIGNING_KEY_ENV,
) -> bytes:
    if key_file:
        key = Path(key_file).read_bytes().rstrip(b"\r\n")
        if key:
            return key
        raise ValueError(f"Signing key file is empty: {key_file}")
    value = os.environ.get(key_env)
    if value:
        return value.encode("utf-8")
    raise ValueError(f"Signing key not found. Set {key_env} or pass --key-file.")


def _artifact_record(path: Path, base_dir: Path | None) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Artifact does not exist or is not a file: {path}")
    resolved = path.resolve()
    return {
        "path": _display_path(resolved, base_dir),
        "filename": path.name,
        "role": classify_artifact(resolved),
        "media_type": _media_type(resolved),
        "size_bytes": resolved.stat().st_size,
        "sha256": _sha256(resolved),
    }


def classify_artifact(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return "json"
        if validate_evidence(document) == []:
            return "evidence"
        if validate_inventory(document) == []:
            return "inventory"
        if validate_policy_coverage(document) == []:
            return "policy-coverage"
        if validate_report(document) == []:
            return "report"
        if _looks_like_sarif(document):
            return "report-sarif"
        if validate_action_plan(document) == []:
            return "action-plan"
        if validate_risk_register(document) == []:
            return "risk-register"
        if validate_gate_result(document) == []:
            return "gate-result"
        if validate_badge(document) == []:
            return "badge"
        if _looks_like_bundle_manifest(document):
            return "bundle-manifest"
        if validate_bundle_signature(document) == []:
            return "bundle-signature"
        if validate_bundle_verification(document) == []:
            return "bundle-verification"
        if validate_report_comparison(document) == []:
            return "report-comparison"
        if validate_evidence_drift(document) == []:
            return "evidence-drift"
        if validate_freshness_report(document) == []:
            return "freshness-report"
        if validate_report_history(document) == []:
            return "report-history"
        if validate_review_attestation(document) == []:
            return "review-attestation"
        if validate_review_summary(document) == []:
            return "review-summary"
        if validate_restore_report(document) == []:
            return "restore-report"
        if validate_mail_report(document) == []:
            return "mail-report"
        if validate_executive_brief(document) == []:
            return "executive-brief"
        if validate_scorecard(document) == []:
            return "scorecard"
        if validate_scope_report(document) == []:
            return "scope-report"
        if validate_service_catalog_report(document) == []:
            return "service-catalog"
        if validate_runbook_report(document) == []:
            return "runbook-report"
        if validate_questionnaire(document) == []:
            return "questionnaire"
        if validate_waiver_document(document) == []:
            return "waivers"
        return "json"
    if suffix == ".toml":
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            return "policy"
        if validate_waiver_document(document) == []:
            return "waivers"
        return "policy"
    if suffix in {".md", ".markdown"}:
        return "report-markdown"
    if suffix == ".svg":
        return "visual"
    if suffix in {".html", ".htm"}:
        return "report-html"
    if suffix in {".prom", ".metrics"}:
        return "report-prometheus"
    return "artifact"


def _verify_artifact(artifact: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    display_path = str(artifact.get("path") or "")
    expected_size = artifact.get("size_bytes")
    expected_sha256 = artifact.get("sha256")
    result = {
        "path": display_path,
        "role": artifact.get("role"),
        "expected_size_bytes": expected_size,
        "expected_sha256": expected_sha256,
        "actual_size_bytes": None,
        "actual_sha256": None,
        "status": "missing",
    }
    path = _resolve_manifest_path(display_path, base_dir)
    if path is None or not path.is_file():
        return result
    actual_size = path.stat().st_size
    actual_sha256 = _sha256(path)
    result["actual_size_bytes"] = actual_size
    result["actual_sha256"] = actual_sha256
    result["status"] = (
        "verified"
        if actual_size == expected_size and actual_sha256 == expected_sha256
        else "mismatch"
    )
    return result


def _resolve_manifest_path(path: str, base_dir: Path) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved = (base_dir / candidate).resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        return None
    return resolved


def _archive_records(manifest: dict[str, Any], base_dir: Path) -> list[tuple[Path, str]]:
    records = []
    for artifact in manifest.get("artifacts", []):
        display_path = str(artifact.get("path") or "")
        source = _resolve_manifest_path(display_path, base_dir)
        if source is None or not source.is_file():
            raise ValueError(f"Bundle artifact is missing or unsafe: {display_path}")
        records.append((source, display_path))
    return records


def _write_archive_file(
    archive: zipfile.ZipFile,
    source: Path,
    archive_name: str,
    seen_names: set[str],
) -> None:
    normalized = Path(archive_name).as_posix()
    if not normalized or normalized.startswith("../") or normalized.startswith("/"):
        raise ValueError(f"Archive path is unsafe: {archive_name}")
    if normalized in seen_names:
        raise ValueError(f"Archive path is duplicated: {normalized}")
    archive.write(source, normalized)
    seen_names.add(normalized)


def _display_path(path: Path, base_dir: Path | None) -> str:
    if base_dir is None:
        return path.name
    try:
        return path.relative_to(base_dir).as_posix()
    except ValueError as exc:
        raise ValueError(f"Artifact {path} is not below base directory {base_dir}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _signature_value(content: bytes, key: bytes) -> str:
    if not key:
        raise ValueError("Signing key must not be empty")
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def _mapping_value(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    return value if isinstance(value, dict) else {}


def _read_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise ValueError(f"Manifest does not exist or is not a file: {path}")
    return path.read_bytes()


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".toml":
        return "application/toml"
    if suffix in {".md", ".markdown"}:
        return "text/markdown"
    if suffix in {".html", ".htm"}:
        return "text/html"
    if suffix == ".svg":
        return "image/svg+xml"
    if suffix in {".prom", ".metrics"}:
        return "text/plain"
    if suffix == ".txt":
        return "text/plain"
    return "application/octet-stream"


def _looks_like_bundle_manifest(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and isinstance(document.get("artifacts"), list)
        and isinstance(document.get("metadata"), dict)
    )


def _looks_like_sarif(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and document.get("version") == "2.1.0"
        and isinstance(document.get("runs"), list)
    )
