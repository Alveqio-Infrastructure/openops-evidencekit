# Wiki Export

OpenOps EvidenceKit can render reports in a Markdown shape that is easy to paste
or sync into an operations wiki such as BookStack.

```powershell
python -m openops_evidence report -i report.local.json -f bookstack -o readiness.bookstack.md
```

The BookStack-oriented output:

- starts with a compact summary table;
- groups failed checks and warnings under "Required Action";
- keeps passed checks compact;
- includes a note that the report is operational evidence, not certification.

Future versions may add direct BookStack API publishing. That integration should
stay optional because wiki credentials are sensitive and should not be required
for local checks.
