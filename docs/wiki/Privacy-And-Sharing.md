# Privacy And Sharing

Treat raw evidence as sensitive infrastructure data.

Before sharing:

```powershell
python -m openops_evidence redact -i evidence.merged.json --redact-hostnames -o evidence.redacted.json
python -m openops_evidence bundle manifest evidence.redacted.json report.local.json report.local.md -o evidence-bundle.manifest.json
```

Then manually review the redacted file for:

- domains
- hostnames
- IP addresses
- user names
- customer names
- tokens or credentials
- operational details that the recipient does not need

Redaction reduces disclosure risk, but it is not a formal data loss prevention
system.
