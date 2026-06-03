# TLS Certificate Reports

`tls report` turns `signals.tls.certificates` evidence into a focused
certificate expiry review artifact:

```powershell
python -m openops_evidence tls report -i evidence.redacted.json -o tls-report.md
python -m openops_evidence tls report -i evidence.redacted.json --warn-days 30 -f json -o tls-report.json
python -m openops_evidence validate -i tls-report.json -t tls-report
```

The report checks:

- whether TLS certificate evidence exists
- whether each certificate has a valid `not_after` timestamp
- whether certificates are expired
- whether certificates expire inside the configured warning window

Evidence can use this compact shape:

```json
{
  "signals": {
    "tls": {
      "certificates": [
        {
          "hostname": "www.example.invalid",
          "port": 443,
          "not_after": "2026-08-20T12:00:00+00:00",
          "issuer": "Example CA"
        }
      ]
    }
  }
}
```

`review create` includes `tls-report.json`, `tls-report.md`, and
`tls-report.csv` automatically when the evidence or policy contains TLS
signals. Add `--fail-on-tls-warn` when missing, invalid, expired, or soon
expiring certificate evidence should fail the review pack command after the
pack has been written.
