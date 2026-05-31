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
```

## 4. Render Report

```powershell
python -m openops_evidence report -i report.json -f markdown -o report.md
```

Store the report in your operations documentation system and track remediation
work in your ticket system.

For BookStack-style wiki pages:

```powershell
python -m openops_evidence report -i report.json -f bookstack -o readiness.bookstack.md
```
