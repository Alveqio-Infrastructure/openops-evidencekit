# Evidence Freshness Reports

Freshness reports inspect timestamp-like fields in an Evidence JSON file. They
help reviewers see whether a handoff is based on recent observations or old
collector output.

```powershell
python -m openops_evidence freshness report -i evidence.local.json -o freshness-report.md
python -m openops_evidence freshness report -i evidence.local.json --max-age-days 30 -f json -o freshness-report.json
python -m openops_evidence validate -i freshness-report.json -t freshness-report
python -m openops_evidence freshness report -i evidence.local.json --max-age-days 30 -f csv -o freshness-report.csv
```

Use `--max-age-days` to decide when valid timestamps should be treated as stale:

```powershell
python -m openops_evidence freshness report -i evidence.local.json --max-age-days 14 --fail-on-warn -o freshness-report.md
```

The command recursively checks keys such as `generated_at`, `updated_at`,
`last_success_at`, `restore_test_at`, `inventory_updated_at`, `not_after`, and
other fields ending in `_at`, `_time`, or `_until`.

Timestamp records use these statuses:

- `current`: valid timestamp and no older than `max_age_days`
- `stale`: valid timestamp but older than `max_age_days`
- `future`: valid timestamp that lies in the future
- `invalid`: timestamp-like field that could not be parsed as ISO 8601

The overall report status is `warn` when stale or invalid timestamps are found.
Future timestamps are listed separately because certificate expiry and
valid-until fields are often intentionally in the future.

Review packs include `freshness-report.json`, `freshness-report.md`, and
`freshness-report.csv` by default. Add `--fail-on-freshness-warn` to
`review create` when stale or invalid evidence timestamps should fail CI after
the pack has been written.
