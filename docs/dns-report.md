# DNS Hygiene Reports

`dns report` turns `signals.dns.domains` evidence into a focused DNS hygiene
artifact:

```powershell
python -m openops_evidence dns report -i evidence.redacted.json -o dns-report.md
python -m openops_evidence dns report -i evidence.redacted.json -f json -o dns-report.json
python -m openops_evidence validate -i dns-report.json -t dns-report
```

The report checks:

- whether DNS evidence exists for each declared domain;
- whether address records are present through `a`, `aaaa`, or `cname`;
- whether authoritative nameserver evidence is present through `nameservers` or
  `ns`;
- whether CAA evidence is present;
- whether DNSSEC evidence is enabled.

Evidence can use this compact shape:

```json
{
  "signals": {
    "dns": {
      "domains": [
        {
          "domain": "example.invalid",
          "a": ["192.0.2.10"],
          "aaaa": ["2001:db8::10"],
          "nameservers": ["ns1.example.invalid", "ns2.example.invalid"],
          "caa": ["0 issue \"example-ca.invalid\""],
          "dnssec": true
        }
      ]
    }
  }
}
```

`review create` includes `dns-report.json`, `dns-report.md`, and
`dns-report.csv` automatically when the evidence or policy contains DNS
signals. Add `--fail-on-dns-warn` when missing CAA or DNSSEC evidence should
fail the review pack command after the pack has been written.
