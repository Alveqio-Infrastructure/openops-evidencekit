# Policy Packs

Policy packs are bundled TOML policies that ship with the package. They give
teams a stable starting point without requiring repository-relative example
paths.

## List Packs

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy list -f json
```

Bundled packs:

- `baseline`: general infrastructure readiness checks
- `security-minimum`: small external-facing security baseline
- `documentation`: inventory and runbook documentation checks

## Export A Pack

```powershell
python -m openops_evidence policy show baseline -o policy.baseline.toml
```

The exported TOML file is meant to be copied into a repository and adjusted for
local requirements. Keep custom policy files under version control so threshold
changes are reviewable.

## Initialize With A Pack

```powershell
python -m openops_evidence init ./my-check --policy-pack security-minimum
```

This creates `policy.security-minimum.toml` and `evidence.sample.json`.

## Versioning

Policy pack names are stable. Individual checks may evolve before 1.0, and any
user-visible change should be documented in `CHANGELOG.md`.
