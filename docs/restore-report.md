# Restore Assurance Reports

`restore report` turns backup evidence into a focused operational assurance
artifact:

```powershell
python -m openops_evidence restore report -i evidence.redacted.json --max-drill-age-days 90 --max-backup-age-days 2 -o restore-report.md
python -m openops_evidence restore report -i evidence.redacted.json -f json -o restore-report.json
python -m openops_evidence validate -i restore-report.json -t restore-report
```

The report checks:

- whether `signals.backup` exists
- whether `signals.backup.last_success_at` is present and recent
- whether repository, snapshot, or archive counts are recorded
- whether restore drill evidence exists
- whether restore drill timestamps are current
- whether restore drill outcomes are explicitly successful

Evidence can use the simple baseline field:

```json
{
  "signals": {
    "backup": {
      "last_success_at": "2026-06-01T22:10:00+00:00",
      "restore_test_at": "2026-05-18T13:30:00+00:00",
      "repository_count": 1
    }
  }
}
```

For recurring restore reviews, use explicit restore test rows:

```json
{
  "signals": {
    "backup": {
      "restore_tests": [
        {
          "id": "restore-drill-2026-05",
          "target": "wiki",
          "tested_at": "2026-05-18T13:30:00+00:00",
          "outcome": "pass",
          "verifier": "ops"
        }
      ]
    }
  }
}
```

The JSON, Markdown, and CSV outputs are safe to place in review packs after raw
evidence has been redacted. `review create` includes restore reports by default
and supports `--fail-on-restore-warn` when CI should reject packs with missing,
stale, unknown, or failed restore evidence.
