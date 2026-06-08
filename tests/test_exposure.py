import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.exposure import create_exposure_report, render_exposure_csv, render_exposure_markdown
from openops_evidence.schema import validate_exposure_report


def _evidence(exposure: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"exposure": exposure},
    }


class ExposureReportTests(unittest.TestCase):
    def test_exposure_report_passes_empty_scan(self):
        report = create_exposure_report(
            _evidence(
                {
                    "scanner": "nmap",
                    "hosts_total": 1,
                    "open_ports_total": 0,
                    "open_ports": [],
                    "risky_ports": [],
                }
            )
        )

        self.assertEqual(validate_exposure_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Exposure Report", render_exposure_markdown(report))
        rows = list(csv.DictReader(render_exposure_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_exposure_report_fails_on_risky_ports(self):
        report = create_exposure_report(
            _evidence(
                {
                    "scanner": "nmap",
                    "hosts_total": 1,
                    "open_ports": [
                        {"host": "203.0.113.10", "port": 80, "protocol": "tcp", "service": "http"},
                        {"host": "203.0.113.10", "port": 22, "protocol": "tcp", "service": "ssh"},
                    ],
                }
            )
        )

        self.assertEqual(validate_exposure_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["open_ports_total"], 2)
        self.assertEqual(report["summary"]["risky_ports_total"], 1)
        self.assertEqual(report["risky_ports"][0]["id"], "203.0.113.10:22/tcp")

    def test_exposure_cli_collects_renders_and_fails_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            nmap = temp / "nmap.xml"
            evidence = temp / "exposure.evidence.json"
            report_json = temp / "exposure-report.json"
            report_md = temp / "exposure-report.md"
            report_csv = temp / "exposure-report.csv"
            nmap.write_text(
                """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
""".strip(),
                encoding="utf-8",
            )

            self.assertEqual(main(["collect", "nmap-xml", str(nmap), "-o", str(evidence)]), 0)
            self.assertEqual(main(["exposure", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "exposure-report"]), 0)
            self.assertEqual(main(["exposure", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["exposure", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["exposure", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Exposure Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("open_port", report_csv.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(report_json.read_text(encoding="utf-8"))["summary"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
