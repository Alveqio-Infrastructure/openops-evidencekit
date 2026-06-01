# Report History

`openops-evidence history` keeps a compact timeline of recurring readiness
reports. This is useful when a team wants to show whether operational posture is
improving, stable, or regressing across weekly checks, releases, onboarding
reviews, or customer handoffs.

## Append A Report

```powershell
python -m openops_evidence history append -i report.local.json --source weekly-review --note "Backup fixes verified" -o readiness-history.json
python -m openops_evidence validate -i readiness-history.json -t history
```

If `-o readiness-history.json` already exists, `history append` reads it first
and appends the new report entry. Use `--history other-history.json` when the
input history and output path should differ.

## Render A Timeline

```powershell
python -m openops_evidence history render -i readiness-history.json -f markdown -o readiness-history.md
python -m openops_evidence history render -i readiness-history.json -f csv -o readiness-history.csv
python -m openops_evidence history render -i readiness-history.json -f svg -o readiness-history.svg
```

The JSON history records:

- latest status and score
- previous score and score delta
- best and worst recorded score
- failed and warning check deltas
- one entry per appended report with source and note fields

Keep the machine-readable JSON when you need auditability. Render Markdown for
BookStack, GitHub, customer handoff, or release notes, CSV for spreadsheets or
lightweight reporting, and SVG when a wiki, README, or dashboard should show a
compact score trend.
