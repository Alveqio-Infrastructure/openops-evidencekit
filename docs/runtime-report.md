# Runtime Reports

`runtime report` turns Docker and systemd runtime evidence into a focused
handoff artifact.

```powershell
python -m openops_evidence runtime report -i evidence.redacted.json -o runtime-report.md
python -m openops_evidence runtime report -i evidence.redacted.json -f json -o runtime-report.json
python -m openops_evidence validate -i runtime-report.json -t runtime-report
python -m openops_evidence runtime report -i evidence.redacted.json -f csv -o runtime-report.csv
```

The report reads `signals.runtime.docker` and `signals.runtime.systemd`, which
can be produced by:

```powershell
python -m openops_evidence collect docker-containers docker.containers.jsonl -o docker.evidence.json
python -m openops_evidence collect systemd-timers systemd.timers.json -o systemd.evidence.json
```

It highlights:

- exited containers
- running containers without restart policies
- failed systemd timers
- missing runtime evidence

Review packs include `runtime-report.json`, `runtime-report.md`, and
`runtime-report.csv` automatically when the evidence or policy contains
`signals.runtime`. Use `--fail-on-warn` when runtime warnings should fail local
scripts or CI jobs.
