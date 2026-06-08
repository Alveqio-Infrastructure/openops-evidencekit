# Running a Readiness Check

This document describes a minimal readiness-check workflow.

## 1. Collect Evidence

Start with a fixture or a collector:

```powershell
python -m openops_evidence collect local -o evidence.local.json
```

For restic repositories, export snapshots first and then collect from the JSON
file:

```powershell
restic snapshots --json > restic.snapshots.json
python -m openops_evidence collect restic-snapshots restic.snapshots.json -o backup.evidence.json
```

For Uptime Kuma, export or back up monitor configuration and import it:

```powershell
python -m openops_evidence collect uptime-kuma uptime-kuma-export.json -o monitoring.evidence.json
```

For Prometheus, export target health:

```powershell
curl http://prometheus.example.invalid/api/v1/targets > prometheus.targets.json
python -m openops_evidence collect prometheus-targets prometheus.targets.json -o prometheus.evidence.json
```

For documentation, scan a reviewed directory without embedding file contents:

```powershell
python -m openops_evidence collect docs ./docs --required inventory.md --required runbooks/backup-restore.md --max-age-days 90 -o docs.evidence.json
```

For production use, combine collector output with documented facts from backup,
monitoring, access, and runbook systems.

If evidence is split across files, merge it first:

```powershell
python -m openops_evidence merge backup.json monitoring.json docs.json -o evidence.merged.json
```

## 2. Redact Before Sharing

```powershell
python -m openops_evidence redact -i evidence.local.json --redact-hostnames -o evidence.redacted.json
```

Review the redacted file manually before sending it to anyone else.

## 3. Evaluate Policy

```powershell
python -m openops_evidence check -i evidence.redacted.json -p examples/policy.baseline.toml -o report.json
python -m openops_evidence gate report -i report.json --min-score 90 --max-warnings 0 -o gate-result.json
python -m openops_evidence restore report -i evidence.redacted.json --max-drill-age-days 90 -o restore-report.md
python -m openops_evidence mail report -i evidence.redacted.json -o mail-report.md
python -m openops_evidence tls report -i evidence.redacted.json -o tls-report.md
python -m openops_evidence access report -i evidence.redacted.json -o access-report.md
python -m openops_evidence monitoring report -i evidence.redacted.json -o monitoring-report.md
python -m openops_evidence exposure report -i evidence.redacted.json -o exposure-report.md
python -m openops_evidence patch report -i evidence.redacted.json -o patch-report.md
python -m openops_evidence runtime report -i evidence.redacted.json -o runtime-report.md
python -m openops_evidence service-level report -i evidence.redacted.json -c examples/service-catalog.sample.toml -o service-level-report.md
python -m openops_evidence incident report -i evidence.redacted.json -c examples/service-catalog.sample.toml -o incident-report.md
```

## 4. Render Report

```powershell
python -m openops_evidence report -i report.json -f markdown -o report.md
python -m openops_evidence report -i report.json -f junit -o report.junit.xml
python -m openops_evidence report -i report.json -f sarif -o report.sarif.json
```

Store the report in your operations documentation system and track remediation
work in your ticket system. Use JUnit output when a CI system should publish
readiness checks as test results, and SARIF output when review tooling should
ingest fail/warn findings.

For BookStack-style wiki pages:

```powershell
python -m openops_evidence report -i report.json -f bookstack -o readiness.bookstack.md
```
