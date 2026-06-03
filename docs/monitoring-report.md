# Monitoring Reports

`monitoring report` turns `signals.monitoring` evidence into a standalone
target health and alert-routing artifact.

```powershell
python -m openops_evidence monitoring report -i evidence.redacted.json -o monitoring-report.md
python -m openops_evidence monitoring report -i evidence.redacted.json --max-alert-test-age-days 90 -f json -o monitoring-report.json
python -m openops_evidence validate -i monitoring-report.json -t monitoring-report
python -m openops_evidence monitoring report -i evidence.redacted.json -f csv -o monitoring-report.csv
```

The report checks:

- Monitoring evidence exists.
- At least one target or monitor is recorded.
- No known down targets are recorded.
- Alert channels are recorded.
- `last_alert_test_at` is current for the configured age window.

Down targets fail the report because they are direct operational readiness
blockers. Missing alert channels or stale alert-test evidence warn because they
usually need operator review before a handoff can be trusted.

Use `--fail-on-warn` when warnings should fail CI:

```powershell
python -m openops_evidence monitoring report -i evidence.redacted.json --fail-on-warn -o monitoring-report.md
```

`review create` includes `monitoring-report.json`, `monitoring-report.md`, and
`monitoring-report.csv` automatically when the evidence or policy contains
monitoring paths. Add `--fail-on-monitoring-warn` to make missing alert routing,
stale alert tests, or down targets fail the review-pack command after the pack
has been written.
