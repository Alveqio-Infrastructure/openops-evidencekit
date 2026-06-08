# Maintainers

OpenOps EvidenceKit is maintained as a deterministic, privacy-conscious
infrastructure operations evidence toolkit.

## Maintainer Duties

Maintainers are expected to:

- keep public examples synthetic and free of secrets or real infrastructure
  details;
- review collectors for data minimization before merging;
- preserve schema, policy, report, and exit-code contracts;
- require tests for user-visible behavior changes;
- keep generated examples and screenshots aligned with the current CLI;
- document breaking changes in `CHANGELOG.md` and the relevant docs;
- handle security reports according to `SECURITY.md`.

## Review Priorities

When reviewing changes, prefer the option that is easier to audit, safer to
share, and more useful to an operator under time pressure. A new feature should
answer at least one concrete readiness question or make evidence easier to
collect, validate, redact, report, compare, or hand off.

## Codex-Assisted Maintenance

Codex is useful for repeatable maintainer work such as:

- scaffolding collectors from public source formats;
- generating synthetic fixtures and focused tests;
- finding missing schema coverage;
- improving remediation text and report clarity;
- reviewing redaction and privacy-sensitive paths;
- drafting release notes, issue replies, and maintainer checklists.

Codex assistance must not make readiness decisions opaque. Pass/fail decisions
belong to deterministic policy rules, documented schemas, and reviewable code.

## Maintainer Checklist

Before merging a substantial change, verify:

- tests pass;
- fixtures use fake names, `.invalid` domains, and non-routable examples;
- new collectors document collected and intentionally avoided fields;
- reports remain readable for non-specialist operators;
- schema or CLI contract changes are documented;
- release notes describe the operational impact.
