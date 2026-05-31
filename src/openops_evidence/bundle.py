from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schema import validate_evidence, validate_report


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
        if validate_report(document) == []:
            return "report"
        if _looks_like_bundle_manifest(document):
            return "bundle-manifest"
        return "json"
    if suffix == ".toml":
        return "policy"
    if suffix in {".md", ".markdown"}:
        return "report-markdown"
    if suffix in {".html", ".htm"}:
        return "report-html"
    return "artifact"


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
    if suffix == ".txt":
        return "text/plain"
    return "application/octet-stream"


def _looks_like_bundle_manifest(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and isinstance(document.get("artifacts"), list)
        and isinstance(document.get("metadata"), dict)
    )
