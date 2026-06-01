# Privacy Model

OpenOps EvidenceKit is meant to make operations evidence shareable without
turning infrastructure data into a leak. It treats evidence as sensitive by
default, even when it was collected from routine systems.

## Data Classes

Evidence files may contain:

- hostnames, service names, URLs, and ports
- backup timestamps, snapshot identifiers, and repository labels
- monitor names, target health, and alert metadata
- TLS certificate subjects and expiry dates
- inventory and runbook status
- free-form notes added by humans or other tools

Evidence files must not contain:

- passwords, tokens, API keys, private keys, recovery codes, or session cookies
- raw customer data or personal data unrelated to infrastructure readiness
- full configuration dumps when a narrow collector output is enough
- internal incident details that have not been reviewed for disclosure

## Redaction

The `redact` command masks common secret-looking keys and selected value
patterns. It also supports hostname redaction with `--redact-hostnames`.

Redaction is intentionally conservative, but it is not a formal data loss
prevention system. Before sharing a bundle externally, review the redacted file
with a plain text search for organization names, domains, user names, IP
addresses, customer identifiers, and credentials.

## Privacy Scan

Use `privacy scan` as a lightweight sharing gate after redaction and before
publishing artifacts:

```powershell
python -m openops_evidence privacy scan evidence.redacted.json report.local.md -o privacy-scan.json
python -m openops_evidence validate -i privacy-scan.json -t privacy-scan
python -m openops_evidence privacy scan evidence.redacted.json report.local.md --fail-on-findings
```

The scanner looks for private keys, common token shapes, secret assignments,
email addresses, and IPv4 addresses. Findings mask the matched value in the
excerpt so the scan report does not echo secrets into logs.

## AI-Assisted Review

AI systems can help summarize findings, draft remediation text, or compare
reports across time. Do not send unreviewed evidence bundles to third-party AI
services unless the data owner has approved that processing.

When using AI on evidence data:

- prefer redacted evidence over raw evidence
- remove customer names and internal hostnames unless they are required
- keep deterministic policy results as the source of truth
- record human review before using generated text in customer-facing material

## Sharing Checklist

Before publishing or attaching evidence to an issue, pull request, ticket, or
wiki page:

- run `openops-evidence redact`
- validate the redacted artifact
- run `openops-evidence privacy scan` and review any findings
- search manually for organization domains, customer names, and context-specific
  identifiers that generic scanners cannot know
- remove generated reports that include operational details not needed by the
  recipient
- prefer aggregate findings over raw source data when discussing public bugs

## Responsible Defaults

The project avoids background upload features and does not include telemetry in
the core command line tool. Integrations should keep this property: collection
and publication are separate actions, and publication must be explicit.
