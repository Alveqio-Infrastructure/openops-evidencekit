# Firewall Reports

`firewall report` turns firewall status and rule evidence into a focused
handoff artifact.

```powershell
ufw status verbose > ufw.status.txt
python -m openops_evidence collect ufw-status ufw.status.txt -o firewall.evidence.json
python -m openops_evidence firewall report -i firewall.evidence.json -o firewall-report.md
python -m openops_evidence firewall report -i firewall.evidence.json -f json -o firewall-report.json
python -m openops_evidence validate -i firewall-report.json -t firewall-report
python -m openops_evidence firewall report -i firewall.evidence.json -f csv -o firewall-report.csv
```

The report reads `signals.firewall`. It highlights:

- missing or inactive firewall evidence
- default incoming policy that is not deny/reject
- public allow rules for administrative ports such as SSH, RDP, VNC, or Docker API

Review packs include `firewall-report.json`, `firewall-report.md`, and
`firewall-report.csv` automatically when evidence or policy contains
`signals.firewall`. Use `--fail-on-warn` when public administrative allow rules
should fail local scripts or CI jobs.
