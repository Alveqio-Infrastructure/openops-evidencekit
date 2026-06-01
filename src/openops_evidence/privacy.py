from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .reports import escape_markdown_text, format_markdown_code


SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "__pycache__", "node_modules"}
TEXT_SUFFIXES = {
    ".csv",
    ".json",
    ".jsonl",
    ".md",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
TOKEN_RE = re.compile(r"\b(?:ghp|github_pat|glpat|xox[baprs]?)-[A-Za-z0-9_=-]{8,}\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)[\"']?\b(?:api[_-]?key|token|secret|password|passwd|pwd|authorization)"
    r"\b[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{8,})"
)


def scan_privacy(paths: Iterable[str | Path]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    skipped_files = 0
    for path in _iter_files(paths):
        if not _looks_textual(path):
            skipped_files += 1
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped_files += 1
            continue
        scanned_files += 1
        findings.extend(_scan_text(path, text))
    findings.sort(key=lambda item: (item["path"], item["line"], item["kind"]))
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "status": "fail" if findings else "pass",
            "files_scanned": scanned_files,
            "files_skipped": skipped_files,
            "findings_count": len(findings),
            "high_count": sum(1 for item in findings if item["severity"] == "high"),
            "medium_count": sum(1 for item in findings if item["severity"] == "medium"),
            "low_count": sum(1 for item in findings if item["severity"] == "low"),
        },
        "findings": findings,
    }


def render_privacy_scan_markdown(scan: dict[str, Any]) -> str:
    summary = scan.get("summary", {})
    lines = [
        "# OpenOps Privacy Scan",
        "",
        f"- Generated: {format_markdown_code(scan.get('generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Files scanned: **{escape_markdown_text(summary.get('files_scanned', 0))}**",
        f"- Findings: **{escape_markdown_text(summary.get('findings_count', 0))}**",
        "",
    ]
    findings = scan.get("findings", [])
    if not findings:
        lines.extend(["No likely sensitive values were detected.", ""])
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(
        [
            "| Severity | Kind | File | Line | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        lines.append(
            "| "
            f"{escape_markdown_text(finding.get('severity', ''))} | "
            f"{escape_markdown_text(finding.get('kind', ''))} | "
            f"{format_markdown_code(finding.get('path', ''))} | "
            f"{escape_markdown_text(finding.get('line', ''))} | "
            f"{escape_markdown_text(finding.get('excerpt', ''))} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _iter_files(paths: Iterable[str | Path]) -> Iterable[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and not any(part in SKIP_DIRS for part in child.parts):
                    yield child
        elif path.is_file():
            yield path


def _looks_textual(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        data = path.read_bytes()[:2048]
    except OSError:
        return False
    return b"\x00" not in data


def _scan_text(path: Path, text: str) -> list[dict[str, Any]]:
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(_regex_findings(path, line_number, line, PRIVATE_KEY_RE, "private_key", "high"))
        findings.extend(_regex_findings(path, line_number, line, TOKEN_RE, "token", "high"))
        findings.extend(_secret_assignment_findings(path, line_number, line))
        findings.extend(_regex_findings(path, line_number, line, EMAIL_RE, "email", "medium"))
        for match in IPV4_RE.finditer(line):
            ip_value = match.group(0)
            try:
                ip = ipaddress.ip_address(ip_value)
            except ValueError:
                continue
            if ip.is_private:
                findings.append(_finding(path, line_number, "private_ipv4", "medium", line, match.span()))
            elif ip.is_global:
                findings.append(_finding(path, line_number, "public_ipv4", "low", line, match.span()))
    return findings


def _secret_assignment_findings(path: Path, line_number: int, line: str) -> list[dict[str, Any]]:
    findings = []
    for match in SECRET_ASSIGNMENT_RE.finditer(line):
        value = match.group(1).strip()
        if value.startswith("<") and value.endswith(">"):
            continue
        if value.lower() in {"redacted", "masked", "removed"}:
            continue
        findings.append(_finding(path, line_number, "secret_assignment", "high", line, match.span(1)))
    return findings


def _regex_findings(
    path: Path,
    line_number: int,
    line: str,
    pattern: re.Pattern[str],
    kind: str,
    severity: str,
) -> list[dict[str, Any]]:
    return [_finding(path, line_number, kind, severity, line, match.span()) for match in pattern.finditer(line)]


def _finding(
    path: Path,
    line_number: int,
    kind: str,
    severity: str,
    line: str,
    span: tuple[int, int],
) -> dict[str, Any]:
    return {
        "path": str(path),
        "line": line_number,
        "kind": kind,
        "severity": severity,
        "excerpt": _masked_excerpt(line, span),
    }


def _masked_excerpt(line: str, span: tuple[int, int]) -> str:
    start, end = span
    excerpt = f"{line[:start]}<match>{line[end:]}"
    excerpt = excerpt.strip()
    if len(excerpt) <= 160:
        return excerpt
    return excerpt[:157].rstrip() + "..."
