# Integration Principles

Integrations should collect facts, not secrets.

## Collector Rules

- Never read private keys.
- Never print bearer tokens or API keys.
- Prefer metadata and timestamps over raw logs.
- Keep customer identifiers out of fixtures.
- Support offline fixture-based tests.
- Document required permissions.

## Candidate Integrations

| Area | Integration | Evidence examples |
| --- | --- | --- |
| Backup | restic | last successful snapshot, repository count, protected hosts and paths |
| Backup | Borg | archive recency, repository reachability |
| Monitoring | Prometheus | target count, alert rule count |
| Monitoring | Uptime Kuma | monitor count, status page presence |
| Runtime | systemd | enabled timers, failed units |
| Runtime | Docker | running containers, restart policies |
| Documentation | BookStack | page freshness, required runbook pages |
| Access | SSH config | public exposure marker, access method evidence |

## AI-Assisted Integrations

AI can help summarize reports or draft remediation text, but AI output must not
change deterministic check results. A future optional assistant layer should
read report JSON and produce commentary that is clearly marked as advisory.
