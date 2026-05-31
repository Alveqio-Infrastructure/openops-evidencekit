from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path
from typing import Any


class UserFacingError(RuntimeError):
    """An error that should be shown without a Python traceback."""


def read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise UserFacingError(f"Could not read {path}: {exc}") from exc


def write_text(path: str | Path | None, content: str) -> None:
    if path is None or str(path) == "-":
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        return
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise UserFacingError(f"Could not write {path}: {exc}") from exc


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise UserFacingError(f"Invalid JSON in {path}: {exc}") from exc


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def load_toml(path: str | Path) -> dict[str, Any]:
    try:
        return tomllib.loads(read_text(path))
    except tomllib.TOMLDecodeError as exc:
        raise UserFacingError(f"Invalid TOML in {path}: {exc}") from exc


def load_structured(path: str | Path) -> Any:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return load_json(path)
    if suffix == ".toml":
        return load_toml(path)
    raise UserFacingError(f"Unsupported file type for {path}; use .json or .toml")
