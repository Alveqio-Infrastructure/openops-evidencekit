from __future__ import annotations

import csv
import html
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SEVERITY_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1}
STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}


def create_report_scorecard(report: dict[str, Any]) -> dict[str, Any]:
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        grouped.setdefault(_domain_id(item), []).append(item)
    domains = [_domain_scorecard(domain, items) for domain, items in sorted(grouped.items())]
    failed = [item for item in domains if item["status"] == "fail"]
    warnings = [item for item in domains if item["status"] == "warn"]
    passed = [item for item in domains if item["status"] == "pass"]
    summary = report.get("summary", {})
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_report_generated_at": report.get("generated_at"),
            "source_status": summary.get("status"),
            "source_score": summary.get("score"),
        },
        "summary": {
            "status": "fail" if failed else ("warn" if warnings else "pass"),
            "source_score": _int(summary.get("score")),
            "domains_total": len(domains),
            "domains_passed": len(passed),
            "domains_failed": len(failed),
            "domains_warn": len(warnings),
            "checks_total": sum(item["checks_total"] for item in domains),
            "checks_passed": sum(item["checks_passed"] for item in domains),
            "checks_failed": sum(item["checks_failed"] for item in domains),
            "checks_warn": sum(item["checks_warn"] for item in domains),
        },
        "domains": domains,
    }


def render_scorecard_markdown(scorecard: dict[str, Any]) -> str:
    summary = scorecard.get("summary", {})
    metadata = scorecard.get("metadata", {})
    lines = [
        "# OpenOps Domain Scorecard",
        "",
        f"- Generated: {format_markdown_code(scorecard.get('generated_at', 'unknown'))}",
        f"- Source report: {format_markdown_code(metadata.get('source_report_generated_at', 'unknown'))}",
        f"- Source status: {format_markdown_code(metadata.get('source_status', 'unknown'))}",
        f"- Source score: **{escape_markdown_text(summary.get('source_score', 0))}**",
        f"- Domains: **{escape_markdown_text(summary.get('domains_total', 0))}**",
        "",
        "| Domain | Status | Score | Checks | Failed | Warnings | Critical | High |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for domain in scorecard.get("domains", []):
        lines.append(
            "| "
            f"{escape_markdown_text(domain.get('title', ''))} | "
            f"{escape_markdown_text(domain.get('status', ''))} | "
            f"{escape_markdown_text(domain.get('score', 0))} | "
            f"{escape_markdown_text(domain.get('checks_total', 0))} | "
            f"{escape_markdown_text(domain.get('checks_failed', 0))} | "
            f"{escape_markdown_text(domain.get('checks_warn', 0))} | "
            f"{escape_markdown_text(domain.get('critical_count', 0))} | "
            f"{escape_markdown_text(domain.get('high_count', 0))} |"
        )
    lines.extend(["", "## Checks", ""])
    for domain in scorecard.get("domains", []):
        lines.extend(
            [
                f"### {escape_markdown_text(domain.get('title', ''))}",
                "",
                "| Status | Severity | Check |",
                "| --- | --- | --- |",
            ]
        )
        for check in domain.get("checks", []):
            lines.append(
                "| "
                f"{escape_markdown_text(check.get('status', ''))} | "
                f"{escape_markdown_text(check.get('severity', ''))} | "
                f"{format_markdown_code(check.get('id', ''))} {escape_markdown_text(check.get('title', ''))} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_scorecard_csv(scorecard: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "domain",
            "title",
            "status",
            "score",
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for domain in scorecard.get("domains", []):
        writer.writerow({key: domain.get(key) for key in writer.fieldnames})
    return output.getvalue()


def render_scorecard_html(scorecard: dict[str, Any]) -> str:
    summary = scorecard.get("summary", {})
    cards = "\n".join(_domain_card_html(domain) for domain in scorecard.get("domains", []))
    rows = "\n".join(_domain_row_html(domain) for domain in scorecard.get("domains", []))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OpenOps Domain Scorecard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #566573;
      --line: #d5dde5;
      --pass: #1e8449;
      --warn: #b7950b;
      --fail: #b03a2e;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 30px;
      line-height: 1.15;
    }}
    h2 {{
      margin: 32px 0 12px;
      font-size: 20px;
    }}
    .summary {{
      color: var(--muted);
      margin: 0 0 24px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 0 0 24px;
    }}
    .metric, .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
    }}
    .metric strong {{
      display: block;
      font-size: 24px;
      margin-top: 4px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .card h3 {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin: 0 0 12px;
      font-size: 17px;
    }}
    .status {{
      border-radius: 999px;
      color: #fff;
      font-size: 12px;
      line-height: 1;
      padding: 5px 8px;
      text-transform: uppercase;
    }}
    .status.pass {{ background: var(--pass); }}
    .status.warn {{ background: var(--warn); }}
    .status.fail {{ background: var(--fail); }}
    .bar {{
      background: #e8eef3;
      border-radius: 999px;
      height: 10px;
      overflow: hidden;
      margin: 10px 0;
    }}
    .fill {{
      height: 100%;
      background: #2874a6;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }}
    td.number {{
      text-align: right;
      white-space: nowrap;
    }}
  </style>
</head>
<body>
  <main>
    <h1>OpenOps Domain Scorecard</h1>
    <p class="summary">Generated {_escape(scorecard.get("generated_at", "unknown"))}</p>
    <section class="metrics">
      <div class="metric"><span>Overall status</span><strong>{_escape(summary.get("status", "unknown")).upper()}</strong></div>
      <div class="metric"><span>Source score</span><strong>{_escape(summary.get("source_score", 0))}</strong></div>
      <div class="metric"><span>Domains</span><strong>{_escape(summary.get("domains_total", 0))}</strong></div>
      <div class="metric"><span>Failed domains</span><strong>{_escape(summary.get("domains_failed", 0))}</strong></div>
    </section>
    <section class="cards">
{cards}
    </section>
    <h2>Domain Detail</h2>
    <table>
      <thead>
        <tr><th>Domain</th><th>Status</th><th>Score</th><th>Checks</th><th>Failed</th><th>Warnings</th><th>Critical</th><th>High</th></tr>
      </thead>
      <tbody>
{rows}
      </tbody>
    </table>
  </main>
</body>
</html>
"""


def _domain_scorecard(domain: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [_check_summary(item) for item in sorted(items, key=_check_sort_key)]
    failed = [item for item in checks if item["status"] == "fail"]
    warnings = [item for item in checks if item["status"] == "warn"]
    passed = [item for item in checks if item["status"] == "pass"]
    return {
        "domain": domain,
        "title": _domain_title(domain),
        "status": "fail" if failed else ("warn" if warnings else "pass"),
        "score": _domain_score(checks),
        "checks_total": len(checks),
        "checks_passed": len(passed),
        "checks_failed": len(failed),
        "checks_warn": len(warnings),
        "critical_count": _attention_count(checks, "critical"),
        "high_count": _attention_count(checks, "high"),
        "medium_count": _attention_count(checks, "medium"),
        "low_count": _attention_count(checks, "low"),
        "checks": checks,
    }


def _check_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id") or ""),
        "title": str(item.get("title") or item.get("id") or ""),
        "status": str(item.get("status") or ""),
        "severity": str(item.get("severity") or "medium"),
        "required": bool(item.get("required")),
        "path": str(item.get("path") or ""),
    }


def _domain_id(item: dict[str, Any]) -> str:
    path = str(item.get("path") or "")
    if path.startswith("signals."):
        parts = path.split(".")
        if len(parts) > 1:
            return _clean_domain_token(parts[1])
    first = path.split(".", 1)[0] if path else ""
    return _clean_domain_token(first) or "general"


def _clean_domain_token(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_")


def _domain_title(domain: str) -> str:
    if domain == "tls":
        return "TLS"
    return domain.replace("_", " ").title()


def _domain_score(checks: list[dict[str, Any]]) -> int:
    total = sum(_severity_weight(item.get("severity")) for item in checks) or 1
    lost = sum(
        _severity_weight(item.get("severity"))
        for item in checks
        if item.get("status") == "fail" and item.get("required")
    )
    return max(0, round(100 * (1 - lost / total)))


def _attention_count(checks: list[dict[str, Any]], severity: str) -> int:
    return sum(1 for item in checks if item.get("status") != "pass" and item.get("severity") == severity)


def _check_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        STATUS_RANK.get(str(item.get("status", "")), 9),
        SEVERITY_WEIGHT.get(str(item.get("severity", "")), 0) * -1,
        str(item.get("id", "")),
    )


def _severity_weight(value: Any) -> int:
    return SEVERITY_WEIGHT.get(str(value), 2)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _domain_card_html(domain: dict[str, Any]) -> str:
    score = _int(domain.get("score"))
    status = str(domain.get("status", "unknown"))
    return f"""      <article class="card">
        <h3>{_escape(domain.get("title", ""))}<span class="status {_escape(status)}">{_escape(status)}</span></h3>
        <div class="bar"><div class="fill" style="width: {score}%"></div></div>
        <p>{score} score, {_escape(domain.get("checks_failed", 0))} failed, {_escape(domain.get("checks_warn", 0))} warnings.</p>
      </article>"""


def _domain_row_html(domain: dict[str, Any]) -> str:
    status = str(domain.get("status", "unknown"))
    return (
        "        <tr>"
        f"<td>{_escape(domain.get('title', ''))}</td>"
        f"<td><span class=\"status {_escape(status)}\">{_escape(status)}</span></td>"
        f"<td class=\"number\">{_escape(domain.get('score', 0))}</td>"
        f"<td class=\"number\">{_escape(domain.get('checks_total', 0))}</td>"
        f"<td class=\"number\">{_escape(domain.get('checks_failed', 0))}</td>"
        f"<td class=\"number\">{_escape(domain.get('checks_warn', 0))}</td>"
        f"<td class=\"number\">{_escape(domain.get('critical_count', 0))}</td>"
        f"<td class=\"number\">{_escape(domain.get('high_count', 0))}</td>"
        "</tr>"
    )


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)
