# Exit Codes

OpenOps EvidenceKit uses stable exit codes so it can run in CI, scheduled jobs,
and automation wrappers.

| Code | Meaning |
| --- | --- |
| `0` | Command completed successfully. |
| `1` | Command completed and found a policy failure or requested guardrail failure. |
| `2` | Input, validation, parsing, filesystem, or usage error. |

## Commands That May Return 1

- `check` returns `1` when required checks fail.
- `gate report` returns `1` when one or more configured gate conditions fail.
- `plan` returns `1` when the generated action plan has at least one non-waived action item.
- `validate` returns `1` when the selected artifact is invalid.
- `policy validate` returns `1` when the selected policy is invalid.
- `waiver validate` returns `1` when the selected waiver file is invalid.
- `privacy scan --fail-on-findings` returns `1` when likely sensitive data is found.
- `risk register --fail-on-open` returns `1` when one or more open risks remain.
- `compare --fail-on-regression` returns `1` when an existing check regresses.
- `evidence diff --fail-on-drift` returns `1` when asset or signal-domain drift is found.
- `evidence quality` returns `1` when quality checks fail, or when `--fail-on-warn` is set and warnings are found.
- `evidence completeness --fail-on-missing` returns `1` when required policy evidence is missing.
- `scope report --fail-on-warn` returns `1` when scope warnings are found.
- `service-level report --fail-on-warn` returns `1` when service-level targets fail or SLO evidence warnings exist.
- `review create --fail-on-gate` returns `1` when the generated gate fails.
- `review create --fail-on-drift` returns `1` when an included evidence drift report warns.
- `review create --fail-on-scope-warn` returns `1` when an included scope report warns.
- `review create --fail-on-open-risk` returns `1` when generated risk registers contain open risks.
- `attest review --fail-on-warn` returns `1` when an included attestation check warns.
- `bundle verify --fail-on-mismatch` returns `1` when an artifact is missing or changed.
- `bundle verify-signature --fail-on-invalid` returns `1` when the manifest signature does not match.

Other commands should return `0` for successful generation and `2` for
user-facing errors.

## Version

Use:

```powershell
python -m openops_evidence --version
```

The installed console script uses the same flag:

```powershell
openops-evidence --version
```
