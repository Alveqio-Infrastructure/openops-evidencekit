from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any


def merge_evidence(documents: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "source": "merge",
            "merged_documents": len(documents),
        },
        "assets": [],
        "signals": {},
    }
    assets_by_id: dict[str, dict[str, Any]] = {}
    for document in documents:
        for asset in document.get("assets", []):
            if not isinstance(asset, dict):
                continue
            asset_id = str(asset.get("id") or "")
            if not asset_id:
                continue
            current = assets_by_id.get(asset_id, {})
            assets_by_id[asset_id] = _deep_merge(current, asset)
        merged["signals"] = _deep_merge(merged["signals"], document.get("signals", {}))
    merged["assets"] = [assets_by_id[key] for key in sorted(assets_by_id)]
    return merged


def _deep_merge(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        result = deepcopy(left)
        for key, value in right.items():
            result[key] = _deep_merge(result[key], value) if key in result else deepcopy(value)
        return result
    if isinstance(left, list) and isinstance(right, list):
        result = deepcopy(left)
        for item in right:
            if item not in result:
                result.append(deepcopy(item))
        return result
    return deepcopy(right)
