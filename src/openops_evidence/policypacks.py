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
    for pack in list_policy_packs():
        if pack["name"] == name:
            return pack
    known = ", ".join(pack["name"] for pack in list_policy_packs())
    raise ValueError(f"Unknown policy pack {name!r}. Available packs: {known}")


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
