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
- `plan` returns `1` when the generated action plan has at least one non-waived action item.
- `validate` returns `1` when the selected artifact is invalid.
- `policy validate` returns `1` when the selected policy is invalid.
- `waiver validate` returns `1` when the selected waiver file is invalid.
- `privacy scan --fail-on-findings` returns `1` when likely sensitive data is found.
- `compare --fail-on-regression` returns `1` when an existing check regresses.
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
