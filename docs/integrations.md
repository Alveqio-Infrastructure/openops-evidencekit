# Integration Principles

Integrations should collect facts, not secrets.

## Collector Rules

- Never read private keys.
- Never print bearer tokens or API keys.
- Prefer metadata and timestamps over raw logs.
- Keep customer identifiers out of fixtures.
- Support offline fixture-based tests.
- Document required permissions.

## Supported Offline Collectors

| Area | Integration | Evidence examples |
| --- | --- | --- |
| Backup | restic | last successful snapshot, repository count, protected hosts and paths |
| Backup | Borg | archive recency, repository identifier, protected hosts |
| Monitoring | Prometheus | target count, up/down target count, down target list |
| Monitoring | Uptime Kuma | monitor count, enabled target count, alert channel references |
| Runtime | systemd | enabled timers, failed units |
| Runtime | Docker | running containers, restart policies |
| Documentation | local directory | required files, stale files, runbook and inventory timestamps |

## CI Outputs

Run `openops-evidence init --github-actions` to generate a starter workflow that
produces the common CI artifacts below.

| Output | Command | Use |
| --- | --- | --- |
| Inventory JSON | `openops-evidence inventory evidence -i evidence.json -f json -o inventory.json` | Publish asset and signal-domain inventory from evidence. |
| Gate JSON | `openops-evidence gate report -i report.json --min-score 90 -o gate-result.json` | Enforce readiness thresholds in CI. |
| Badge JSON | `openops-evidence badge report -i report.json -o readiness-badge.json` | Publish a compact Shields-compatible readiness status. |
| Executive brief | `openops-evidence brief report -i report.json -o executive-brief.md` | Share a concise stakeholder summary. |
| History JSON | `openops-evidence history append -i report.json -o readiness-history.json` | Track score and finding changes across recurring reviews. |
| JUnit XML | `openops-evidence report -i report.json -f junit -o report.junit.xml` | Publish readiness checks as CI test results. |
| SARIF JSON | `openops-evidence report -i report.json -f sarif -o report.sarif.json` | Import findings into SARIF-aware review tools. |
| Prometheus text | `openops-evidence report -i report.json -f prometheus -o report.prom` | Export score, status, and check counts into monitoring pipelines. |
| Markdown tickets | `openops-evidence ticket export -i action-plan.json -o action-tickets` | Import remediation work into issue trackers or service desks. |

## Candidate Integrations

| Area | Integration | Evidence examples |
| --- | --- | --- |
| Documentation | BookStack | page freshness and required runbook pages from the BookStack API |
| Access | SSH config | public exposure marker, access method evidence |

## AI-Assisted Integrations

AI can help summarize reports or draft remediation text, but AI output must not
change deterministic check results. A future optional assistant layer should
read report JSON and produce commentary that is clearly marked as advisory.
