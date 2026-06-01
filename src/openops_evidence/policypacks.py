from __future__ import annotations

import json
from importlib import resources
from typing import Any


PACKAGE = "openops_evidence.policies"


def list_policy_packs() -> list[dict[str, Any]]:
    manifest = _load_manifest()
    packs = manifest.get("packs", [])
    if not isinstance(packs, list):
        raise ValueError("Policy pack manifest must contain a packs list")
    return sorted([_normalize_pack(item) for item in packs], key=lambda item: item["name"])


def get_policy_pack(name: str) -> dict[str, Any]:
    pack_name, requested_version = parse_policy_pack_reference(name)
    for pack in list_policy_packs():
        if pack["name"] == pack_name and (
            requested_version is None or pack["version"] == requested_version
        ):
            return pack
    packs = list_policy_packs()
    if requested_version is not None and any(pack["name"] == pack_name for pack in packs):
        known_versions = ", ".join(
            f"{pack['name']}@{pack['version']}" for pack in packs if pack["name"] == pack_name
        )
        raise ValueError(f"Unknown policy pack version {name!r}. Available versions: {known_versions}")
    known = ", ".join(pack["name"] for pack in packs)
    raise ValueError(f"Unknown policy pack {name!r}. Available packs: {known}")


def parse_policy_pack_reference(reference: str) -> tuple[str, str | None]:
    name, separator, version = reference.partition("@")
    if not name or (separator and not version):
        raise ValueError("Policy pack reference must use name or name@version.")
    return name, version or None


def read_policy_pack(name: str) -> str:
    pack = get_policy_pack(name)
    return resources.files(PACKAGE).joinpath(str(pack["file"])).read_text(encoding="utf-8")


def render_policy_pack_list(format_name: str = "table") -> str:
    packs = list_policy_packs()
    if format_name == "json":
        return json.dumps({"packs": packs}, indent=2, sort_keys=True) + "\n"
    if format_name != "table":
        raise ValueError(f"Unsupported policy list format: {format_name}")
    lines = ["Name | Version | Title", "--- | --- | ---"]
    for pack in packs:
        lines.append(f"{pack['name']} | {pack['version']} | {pack['title']}")
    return "\n".join(lines) + "\n"


def _load_manifest() -> dict[str, Any]:
    text = resources.files(PACKAGE).joinpath("manifest.json").read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("Policy pack manifest must be a JSON object")
    return payload


def _normalize_pack(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("Each policy pack manifest entry must be an object")
    required = ("name", "title", "version", "description", "file")
    missing = [key for key in required if not isinstance(item.get(key), str) or not item.get(key)]
    if missing:
        raise ValueError(f"Policy pack manifest entry is missing: {', '.join(missing)}")
    return {key: str(item[key]) for key in required}
