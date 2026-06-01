# Governance

OpenOps EvidenceKit is maintained as a small, deterministic infrastructure
operations toolkit. Governance should keep the project useful for operators,
safe for sensitive evidence, and predictable for downstream automation.

## Maintainer Responsibilities

Maintainers are responsible for:

- keeping generated examples synthetic and free of secrets
- reviewing collector changes for data-minimization risks
- preserving documented schema, policy, report, and exit-code contracts
- requiring tests for user-visible behavior changes
- keeping release notes and migration notes accurate
- triaging security reports according to `SECURITY.md`

## Decision Process

Small fixes, documentation updates, tests, and narrowly scoped collectors may be
merged after normal review. Changes that affect artifact schemas, policy
operator semantics, report fields, exit codes, redaction behavior, or trust
boundaries require an explicit maintainer decision in the pull request or issue.

When there is disagreement, prefer the option that is easier to audit, safer for
sensitive evidence, and less surprising for existing automation.

## Compatibility Policy

Before 1.0, incompatible changes are allowed only when they are documented in
`CHANGELOG.md` and the relevant schema or policy documentation. Patch-level
schema changes may add optional fields. Removing fields, renaming fields,
changing field types, or changing policy/report semantics requires a new
major/minor schema version and a migration note.

Policy operator semantics are part of the public contract. Additions are allowed
when documented and tested. Changing an existing operator's meaning requires a
migration note and should be avoided unless the current behavior is unsafe or
incorrect.

## Security And Privacy

Raw evidence can describe real infrastructure. Maintainers should reject
fixtures, screenshots, reports, or examples that include real customer data,
tokens, private keys, internal hostnames, private IP addresses, or other
sensitive operational details.

Security fixes should minimize public exploit detail until a fixed release is
available. New integrations must document what they collect, what they do not
collect, and how users should redact or review the output before sharing it.

## Releases

Release preparation follows `docs/release-process.md`. A release should not be
published unless tests pass, schemas match generated artifacts, sample evidence
is synthetic, and human-readable reports are reviewed for clarity.
