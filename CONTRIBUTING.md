# Contributing

OpenOps EvidenceKit welcomes issues, documentation improvements, policy packs,
collectors, and tests.

## Principles

- Keep the core deterministic and auditable.
- Avoid collecting secrets.
- Prefer explicit evidence over inference.
- Make checks understandable to operators, not only auditors.
- Keep vendor-specific integrations optional.

## Development

```powershell
python -m unittest discover -s tests
python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
```

Use focused pull requests. Include sample evidence for new collectors, and make
sure fixtures do not contain real customer names, hostnames, IP addresses, tokens,
or private infrastructure details.

## Good First Contributions

- Add a synthetic fixture for a common infrastructure export.
- Improve remediation text for an existing policy check.
- Propose a collector or integration with clear data-minimization notes.
- Add docs for an operator workflow in `docs/use-cases.md`.
- Improve report readability without changing deterministic results.
- Add tests around redaction, schema validation, or generated artifacts.

Maintainer decisions, compatibility rules, and security governance are described
in [GOVERNANCE.md](GOVERNANCE.md).

Maintainer duties and Codex-assisted maintenance expectations are described in
[MAINTAINERS.md](MAINTAINERS.md). Privacy-safe adopter notes are tracked in
[ADOPTERS.md](ADOPTERS.md).

## Commit Style

Use short imperative commit messages:

```text
Add baseline backup checks
Document redaction model
```
