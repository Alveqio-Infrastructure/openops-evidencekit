from __future__ import annotations

import copy
import re
from typing import Any

DEFAULT_SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "password",
    "private_key",
    "secret",
    "token",
}
SECRET_KEY_PARTS = {
    "authorization",
    "cookie",
    "key",
    "password",
    "passwd",
    "private",
    "pwd",
    "secret",
    "session",
    "token",
}

DEFAULT_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ipv4>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
]


def redact_document(document: Any, *, redact_hostnames: bool = False) -> Any:
    result = copy.deepcopy(document)
    return _redact_value(result, redact_hostnames=redact_hostnames)


def _redact_value(value: Any, *, redact_hostnames: bool) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _is_secret_key(key):
                out[key] = "<redacted>"
                continue
            out[key] = _redact_value(item, redact_hostnames=redact_hostnames)
        return out
    if isinstance(value, list):
        return [_redact_value(item, redact_hostnames=redact_hostnames) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in DEFAULT_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        if redact_hostnames:
            redacted = _redact_hostname_like(redacted)
        return redacted
    return value


def _redact_hostname_like(value: str) -> str:
    if "." not in value or " " in value:
        return value
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        return "<hostname>"
    return value


def _is_secret_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    if normalized in DEFAULT_SECRET_KEYS:
        return True
    parts = set(normalized.split("_"))
    if not parts & SECRET_KEY_PARTS:
        return False
    if {"api", "key"} <= parts:
        return True
    if {"private", "key"} <= parts:
        return True
    if {"session", "cookie"} <= parts:
        return True
    return bool(parts & {"authorization", "password", "passwd", "pwd", "secret", "token"})


def _normalize_key(key: Any) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", separated).lower()
    return normalized.strip("_")
