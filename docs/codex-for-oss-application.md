# Codex for OSS Application Draft

This page is a copy-ready maintainer draft for the OpenAI Codex for OSS
application. Keep it factual and update it when the repository changes.

## Repository

https://github.com/Alveqio-Infrastructure/openops-evidencekit

## Project Summary

OpenOps EvidenceKit is a vendor-neutral CLI toolkit for collecting, validating,
redacting, reporting, and packaging infrastructure operations evidence. It helps
small teams prove backup, restore, monitoring, access, patch, vulnerability,
software inventory, TLS, mail, runbook, service catalog, and incident readiness
basics with deterministic checks and privacy-safe examples.

## Why This Project Qualifies

OpenOps EvidenceKit helps small infrastructure teams, MSPs, self-hosters,
nonprofits, associations, and platform teams produce repeatable readiness
evidence without buying a heavy compliance platform or exposing sensitive
operational details. The project is vendor-neutral, deterministic, test-backed,
and useful for public-interest infrastructure operations.

## Maintainer Role

The maintainer designs the evidence schema, policy checks, collectors, reports,
fixtures, documentation, governance, and release workflow. Maintainer work also
includes reviewing contributions for privacy and data-minimization risk,
preserving deterministic pass/fail behavior, and keeping reports practical for
operators rather than only auditors.

## Planned API Credit Use

API credits would support Codex-assisted open source maintenance:

- scaffold collectors from public source formats;
- generate synthetic fixtures and tests;
- improve report wording and operator remediation guidance;
- review redaction, schema, and security-sensitive paths;
- draft documentation, release notes, and issue responses;
- build realistic review-pack examples without real infrastructure data;
- triage integration requests and contributor pull requests.

The project will keep readiness decisions deterministic. AI assistance helps
maintainers work faster, but policy evaluation remains implemented as auditable
rules, schemas, tests, and CLI output.

## Public Benefit

Many small organizations run important services with limited operations staff.
EvidenceKit makes healthy infrastructure habits easier to adopt: prove backups,
verify restore drills, review monitoring, check exposed access, track stale
runbooks, summarize vulnerabilities, and hand off action plans. This benefits
community operators and small teams that need accountable infrastructure without
vendor lock-in.

## Current Evidence For Reviewers

- Public repository with Apache-2.0 license.
- Governance, security, contributor, maintainer, and adopter documentation.
- Synthetic examples and report screenshots in the README.
- Deterministic test suite and CI workflow.
- JSON schemas for generated artifacts.
- GitHub issue templates for bugs, collectors, policies, integrations, and
  adopter stories.
- Privacy model that rejects secrets, customer data, private hostnames, private
  IP addresses, and real infrastructure details in public artifacts.

## Short Form Text

### Qualification

OpenOps EvidenceKit helps small infra teams, MSPs, self-hosters, nonprofits,
and platform teams create deterministic readiness evidence for backups, restore,
monitoring, access, patching, vulnerabilities, SBOMs, TLS, mail, and runbooks
without vendor lock-in or leaking sensitive data.

### Maintainer Role

I maintain the schema, collectors, policy checks, reports, synthetic fixtures,
tests, docs, governance, and release process, and review contributions for
privacy, data minimization, deterministic behavior, and operator usefulness.

### API Credit Use

Credits would support Codex-assisted maintainer work: collector scaffolding,
synthetic fixtures, tests, report UX, redaction/security review, release
checklists, documentation, issue triage, and review-pack examples while keeping
pass/fail checks deterministic.
