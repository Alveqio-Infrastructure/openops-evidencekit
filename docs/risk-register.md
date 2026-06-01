# Risk Registers

Risk registers turn readiness report findings into a stable list of open,
accepted, expired, and closed operational risks. They are useful for recurring
service reviews, customer handoffs, and management conversations where the team
needs to see risk treatment decisions instead of only remediation tasks.

```powershell
python -m openops_evidence risk register -i report.local.json -o risk-register.json
python -m openops_evidence validate -i risk-register.json -t risk-register
python -m openops_evidence risk register -i report.local.json -f markdown -o risk-register.md
python -m openops_evidence risk register -i report.local.json -f csv -o risk-register.csv
```

Apply waiver files to mark accepted risks with an owner, reason, and expiry:

```powershell
python -m openops_evidence risk register -i report.local.json --waivers waivers.toml -f markdown -o risk-register.md
```

Risk statuses are:

- `open`: failed or warning finding without an active acceptance
- `accepted`: failed or warning finding covered by an active waiver
- `closed`: passing finding included with `--include-pass`

Expired waivers are listed with `waiver_status` `expired` and remain `open`.
Use `--fail-on-open` when CI should fail if any open risk remains after active
waivers have been applied.

Review packs include `risk-register.json`, `risk-register.md`, and
`risk-register.csv` automatically. Add `--fail-on-open-risk` to
`review create` when open risks should fail CI after the pack has been written.
