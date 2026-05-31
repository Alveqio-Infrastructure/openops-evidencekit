from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def query(document: Any, path: str) -> list[Any]:
    """Return values for a small dotted path language.

    Supported examples:
    - signals.backup.last_success_at
    - assets[*].hostname
    - signals.mail.domains[0].dmarc
    """

    if path == ".":
        return [document]

    values = [document]
    for raw_part in path.split("."):
        part, selectors = _split_selectors(raw_part)
        values = _descend_key(values, part)
        for selector in selectors:
            values = _apply_selector(values, selector)
    return values


def _split_selectors(part: str) -> tuple[str, list[str]]:
    key = []
    selectors = []
    i = 0
    while i < len(part):
        char = part[i]
        if char != "[":
            key.append(char)
            i += 1
            continue
        end = part.find("]", i)
        if end == -1:
            raise ValueError(f"Invalid path selector in {part!r}")
        selectors.append(part[i + 1 : end])
        i = end + 1
    return "".join(key), selectors


def _descend_key(values: Iterable[Any], key: str) -> list[Any]:
    if key == "":
        return list(values)
    out: list[Any] = []
    for value in values:
        if isinstance(value, dict) and key in value:
            out.append(value[key])
    return out


def _apply_selector(values: Iterable[Any], selector: str) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if selector == "*":
            if isinstance(value, list):
                out.extend(value)
            continue
        if not isinstance(value, list):
            continue
        try:
            index = int(selector)
        except ValueError as exc:
            raise ValueError(f"Unsupported path selector [{selector}]") from exc
        if -len(value) <= index < len(value):
            out.append(value[index])
    return out
