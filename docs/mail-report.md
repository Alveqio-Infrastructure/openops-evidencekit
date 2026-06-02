# Mail Domain Reports

`mail report` turns `signals.mail.domains` evidence into a focused mail-domain
hygiene artifact:

```powershell
python -m openops_evidence mail report -i evidence.redacted.json -o mail-report.md
python -m openops_evidence mail report -i evidence.redacted.json -f json -o mail-report.json
python -m openops_evidence validate -i mail-report.json -t mail-report
```

The report checks:

- SPF evidence
- DKIM evidence
- DMARC policy evidence
- whether DMARC is enforced with `quarantine` or `reject`

Evidence can use a compact shape:

```json
{
  "signals": {
    "mail": {
      "domains": [
        {
          "domain": "example.invalid",
          "spf": true,
          "dkim": true,
          "dmarc": "quarantine"
        }
      ]
    }
  }
}
```

Full DMARC records are also accepted. The report extracts the `p=` policy from
values such as `v=DMARC1; p=reject; rua=mailto:dmarc@example.invalid`.

`review create` includes `mail-report.json`, `mail-report.md`, and
`mail-report.csv` automatically when the evidence or policy contains mail
signals. Add `--fail-on-mail-warn` when missing SPF, DKIM, or enforced DMARC
evidence should fail the review pack command after the pack has been written.
