# Executive Briefs

`openops-evidence brief report` creates a short stakeholder-friendly summary
from report JSON. It is meant for customer handoffs, release notes, management
updates, internal review meetings, and wiki pages where the full technical
report would be too detailed.

```powershell
python -m openops_evidence brief report -i report.local.json -o executive-brief.md
python -m openops_evidence brief report -i report.local.json -f json -o executive-brief.json
python -m openops_evidence validate -i executive-brief.json -t executive-brief
```

The brief is deterministic. It does not use an AI model or rewrite findings
free-form. It extracts:

- status, score, and health label
- a concise readout sentence
- prioritized failed or warning findings
- recommended next steps derived from remediation text

Use `--max-findings` when the brief should include fewer or more findings:

```powershell
python -m openops_evidence brief report -i report.local.json --max-findings 3 -o executive-brief.md
```

The brief is a summary, not a substitute for the full report, action plan,
privacy scan, or signed evidence bundle.
