import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.schema import validate_vulnerability_report
from openops_evidence.vulnerabilities import (
    create_vulnerability_report,
    render_vulnerability_csv,
    render_vulnerability_markdown,
)


def _evidence(vulnerabilities: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"vulnerabilities": vulnerabilities},
    }


class VulnerabilityReportTests(unittest.TestCase):
    def test_vulnerability_report_passes_clean_scan(self):
        report = create_vulnerability_report(_evidence({"scanner": "trivy", "targets_total": 1, "findings": []}))

        self.assertEqual(validate_vulnerability_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Vulnerability Report", render_vulnerability_markdown(report))
        rows = list(csv.DictReader(render_vulnerability_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_vulnerability_report_fails_on_critical_and_high_findings(self):
        report = create_vulnerability_report(
            _evidence(
                {
                    "scanner": "trivy",
                    "targets_total": 1,
                    "findings": [
                        {
                            "id": "CVE-2026-0001",
                            "target": "example/app:1.0",
                            "package": "openssl",
                            "installed_version": "1.0",
                            "fixed_version": "1.1",
                            "severity": "critical",
                            "title": "Synthetic critical",
                            "primary_url": "https://example.invalid/CVE-2026-0001",
                        },
                        {
                            "id": "CVE-2026-0002",
                            "target": "example/app:1.0",
                            "package": "curl",
                            "installed_version": "7.0",
                            "fixed_version": "",
                            "severity": "high",
                            "title": "Synthetic high",
                            "primary_url": "https://example.invalid/CVE-2026-0002",
                        },
                    ],
                }
            )
        )

        self.assertEqual(validate_vulnerability_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["critical_total"], 1)
        self.assertEqual(report["summary"]["high_total"], 1)
        self.assertEqual(report["summary"]["fixable_total"], 1)
        self.assertEqual(len(report["critical_high_findings"]), 2)

    def test_vulnerability_cli_collects_renders_and_fails_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            trivy = temp / "trivy.json"
            evidence = temp / "vulnerability.evidence.json"
            report_json = temp / "vulnerability-report.json"
            report_md = temp / "vulnerability-report.md"
            report_csv = temp / "vulnerability-report.csv"
            trivy.write_text(
                """
{
  "Results": [
    {
      "Target": "example/app:1.0",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-0003",
          "PkgName": "zlib",
          "InstalledVersion": "1.0",
          "Severity": "MEDIUM",
          "Title": "Synthetic medium"
        }
      ]
    }
  ]
}
""".strip(),
                encoding="utf-8",
            )

            self.assertEqual(main(["collect", "trivy-json", str(trivy), "-o", str(evidence)]), 0)
            self.assertEqual(main(["vulnerability", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "vulnerability-report"]), 0)
            self.assertEqual(main(["vulnerability", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["vulnerability", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["vulnerability", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Vulnerability Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("finding", report_csv.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(report_json.read_text(encoding="utf-8"))["summary"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
