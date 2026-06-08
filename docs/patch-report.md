# Patch Reports

`patch report` turns package update and reboot evidence into a focused handoff
artifact.

```powershell
apt list --upgradable > apt.upgradable.txt
python -m openops_evidence collect apt-upgrades apt.upgradable.txt -o patch.evidence.json
python -m openops_evidence patch report -i patch.evidence.json -o patch-report.md
python -m openops_evidence patch report -i patch.evidence.json -f json -o patch-report.json
python -m openops_evidence validate -i patch-report.json -t patch-report
python -m openops_evidence patch report -i patch.evidence.json -f csv -o patch-report.csv
```

The report reads `signals.patch`. It highlights:

- pending package updates
- pending security updates
- missing or positive reboot-required evidence

Review packs include `patch-report.json`, `patch-report.md`, and
`patch-report.csv` automatically when evidence or policy contains
`signals.patch`. Use `--fail-on-warn` when pending updates or unknown reboot
state should fail local scripts or CI jobs.
