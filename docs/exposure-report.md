# Exposure Reports

`exposure report` turns public network scan evidence into a focused handoff
artifact for open ports and risky services.

```powershell
nmap -oX nmap.xml example.com
python -m openops_evidence collect nmap-xml nmap.xml -o exposure.evidence.json
python -m openops_evidence exposure report -i exposure.evidence.json -o exposure-report.md
python -m openops_evidence exposure report -i exposure.evidence.json -f json -o exposure-report.json
python -m openops_evidence validate -i exposure-report.json -t exposure-report
python -m openops_evidence exposure report -i exposure.evidence.json -f csv -o exposure-report.csv
```

The report reads `signals.exposure.open_ports`, which can be produced from
Nmap XML. It highlights:

- all open ports found in the scan
- risky administrative or data ports such as SSH, RDP, SMB, databases, Redis,
  Docker API, and similar services
- missing exposure evidence

Review packs include `exposure-report.json`, `exposure-report.md`, and
`exposure-report.csv` automatically when evidence or policy contains
`signals.exposure`. Use `--fail-on-warn` when any open port should fail local
scripts or CI jobs.
