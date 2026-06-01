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

| Output | Command | Use |
| --- | --- | --- |
| Gate JSON | `openops-evidence gate report -i report.json --min-score 90 -o gate-result.json` | Enforce readiness thresholds in CI. |
| JUnit XML | `openops-evidence report -i report.json -f junit -o report.junit.xml` | Publish readiness checks as CI test results. |
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
