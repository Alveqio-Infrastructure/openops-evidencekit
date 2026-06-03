# Access Exposure Reports

`access report` turns `signals.access` evidence into a focused administrative
access review artifact:

```powershell
python -m openops_evidence access report -i evidence.redacted.json -o access-report.md
python -m openops_evidence access report -i evidence.redacted.json -f json -o access-report.json
python -m openops_evidence validate -i access-report.json -t access-report
```

The report checks:

- whether access evidence exists
- whether public SSH exposure is closed
- whether administrative MFA is required
- whether administrative entrypoints are recorded
- whether entrypoints look controlled, risky, or unknown

Evidence can use this compact shape:

```json
{
  "signals": {
    "access": {
      "ssh_public_exposed": false,
      "mfa_required": true,
      "admin_entrypoints": ["vpn", "sso"]
    }
  }
}
```

Known controlled entrypoints include values such as `vpn`, `sso`, `netbird`,
`wireguard`, `bastion`, `pam`, and `zero-trust`. Values such as `public-ssh`,
`direct`, `public-admin`, `password`, and `rdp-public` are treated as risky.
Unknown values produce warnings so teams can review and document their access
model explicitly.

`review create` includes `access-report.json`, `access-report.md`, and
`access-report.csv` automatically when the evidence or policy contains access
signals. Add `--fail-on-access-warn` when missing MFA, public SSH exposure,
risky entrypoints, or unclassified entrypoints should fail the review pack
command after the pack has been written.
