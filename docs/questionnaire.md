# Evidence Questionnaires

`questionnaire policy` turns a policy file into a concrete evidence request
list. This is useful before a readiness review, customer onboarding, or an
internal operations audit.

```powershell
python -m openops_evidence questionnaire policy policy.baseline.toml -o questionnaire.md
python -m openops_evidence questionnaire policy policy.baseline.toml -f json -o questionnaire.json
python -m openops_evidence questionnaire policy policy.baseline.toml -f csv -o questionnaire.csv
```

Each question includes:

- check ID and title
- evidence domain
- required flag and severity
- evidence path and operator
- expected value when the policy defines one
- a plain request sentence

Example request:

```text
Provide a timestamp for signals.backup.last_success_at no older than 2 day(s).
```

Validate JSON output with:

```powershell
python -m openops_evidence validate -i questionnaire.json -t questionnaire
```

Questionnaires are deterministic. They are not a replacement for a statement of
work, but they make evidence collection much clearer before the technical check
starts.
