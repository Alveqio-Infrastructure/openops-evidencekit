# Policy Authoring

Bundled policies can be listed and exported:

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.baseline.toml
python -m openops_evidence policy validate policy.baseline.toml
python -m openops_evidence policy matrix policy.baseline.toml -f markdown -o policy.matrix.md
```

Policies are TOML files with one or more checks:

```toml
[[checks]]
id = "backup_recent"
title = "Recent successful backup exists"
path = "signals.backup.last_success_at"
operator = "within_days"
value = 2
severity = "critical"
required = true
remediation = "Configure backups and record the last successful backup timestamp."
```

## Operators

Use the CLI to list the stable operator catalog:

```powershell
python -m openops_evidence policy operators
```

Common operators include `exists`, `missing`, `equals`, `one_of`, `matches`,
`within_days`, and `after_now`. Use `policy operators -f json` when automation
needs the machine-readable semantics.

## Modes

Use `mode = "all"` when every selected value must pass and `mode = "none"` when
no selected value may pass. The default mode is `any`.
