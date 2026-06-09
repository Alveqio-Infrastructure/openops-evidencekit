# Project Impact

OpenOps EvidenceKit exists to make practical infrastructure readiness easier to
prove, review, and improve.

## Project Summary

OpenOps EvidenceKit is a vendor-neutral CLI toolkit for collecting, validating,
redacting, reporting, and packaging infrastructure operations evidence. It helps
small teams prove backup, restore, monitoring, access, patch, vulnerability,
software inventory, TLS, mail, runbook, service catalog, and incident readiness
basics with deterministic checks and privacy-safe examples.

## Why It Matters

Small teams often run important infrastructure without a reliable way to prove
operational readiness. EvidenceKit turns readiness checks into repeatable,
reviewable artifacts that can be used by maintainers, internal IT teams,
managed service providers, associations, agencies, nonprofits, and self-hosters.

The project focuses on work that is useful before a team needs a heavy
compliance platform:

- prove that backups exist and restore drills are recent;
- review monitoring targets, alert channels, and alert-test freshness;
- identify public access exposure and risky network services;
- summarize patch, vulnerability, and SBOM evidence;
- check TLS, DNS, mail, runbook, service catalog, and incident readiness basics;
- create privacy-reviewed handoff bundles for stakeholders.

## Public Benefit

Infrastructure operations are not only a large-enterprise problem. Community
services, small SaaS products, volunteer-run organizations, agencies, and local
IT teams all need a clearer way to prove that systems are maintained
responsibly. OpenOps EvidenceKit gives these teams a shared, auditable language
for readiness without requiring vendor lock-in or exposing sensitive details.

## Design Principles

- Deterministic checks over opaque scoring.
- Synthetic public examples over real infrastructure data.
- Data minimization for every collector.
- Human-readable reports for operators and stakeholders.
- Machine-readable outputs for CI, dashboards, and recurring reviews.
- Clear scope boundaries, action plans, risk registers, and review packs.

## Maintainer Work

Useful maintainer work includes:

- adding parsers for common infrastructure exports;
- generating privacy-safe fixtures from documented source formats;
- expanding policy packs and remediation text;
- improving Markdown, SARIF, JUnit, Prometheus, and executive report output;
- reviewing redaction paths and schema migrations;
- drafting docs, release notes, issue responses, and maintainer checklists;
- building examples that show realistic workflows without real operational data.

Automation and AI assistance can help with repetitive maintainer work, but
readiness decisions remain deterministic, documented, and reviewable.
