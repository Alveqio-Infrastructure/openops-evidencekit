# Policy Authoring

Bundled policies can be listed and exported:

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.baseline.toml
python -m openops_evidence policy validate policy.baseline.toml
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

- `exists`
- `missing`
- `equals`
- `not_equals`
- `contains`
- `one_of`
- `at_least`
- `at_most`
- `matches`
- `within_days`
- `after_now`

## Modes

Use `mode = "all"` when every selected value must pass and `mode = "none"` when
no selected value may pass. The default mode is `any`.
