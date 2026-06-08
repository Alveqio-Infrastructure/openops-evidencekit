import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.firewall import create_firewall_report, render_firewall_csv, render_firewall_markdown
from openops_evidence.schema import validate_firewall_report


def _evidence(firewall: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"firewall": firewall},
    }


class FirewallReportTests(unittest.TestCase):
    def test_firewall_report_passes_restrictive_firewall(self):
        report = create_firewall_report(
            _evidence({"source": "ufw", "status": "active", "default_incoming": "deny", "rules": []})
        )

        self.assertEqual(validate_firewall_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Firewall Report", render_firewall_markdown(report))
        rows = list(csv.DictReader(render_firewall_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_firewall_report_warns_on_public_admin_rule(self):
        report = create_firewall_report(
            _evidence(
                {
                    "source": "ufw",
                    "status": "active",
                    "default_incoming": "deny",
                    "rules": [{"id": "22/tcp ALLOW Anywhere", "to": "22/tcp", "action": "ALLOW", "from": "Anywhere"}],
                }
            )
        )

        self.assertEqual(validate_firewall_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["public_admin_rules_total"], 1)
        self.assertTrue(report["public_admin_rules"][0]["public_admin"])

    def test_firewall_report_fails_when_inactive_or_default_allows(self):
        report = create_firewall_report(
            _evidence({"source": "ufw", "status": "inactive", "default_incoming": "allow", "rules": []})
        )

        self.assertEqual(validate_firewall_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["checks_failed"], 2)

    def test_firewall_cli_collects_renders_and_fails_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            ufw = temp / "ufw.txt"
            evidence = temp / "firewall.evidence.json"
            report_json = temp / "firewall-report.json"
            report_md = temp / "firewall-report.md"
            report_csv = temp / "firewall-report.csv"
            ufw.write_text(
                """
Status: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
Default: deny (incoming), allow (outgoing), disabled (routed)
""".strip(),
                encoding="utf-8",
            )

            self.assertEqual(main(["collect", "ufw-status", str(ufw), "-o", str(evidence)]), 0)
            self.assertEqual(main(["firewall", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "firewall-report"]), 0)
            self.assertEqual(main(["firewall", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["firewall", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["firewall", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Firewall Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("rule", report_csv.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(report_json.read_text(encoding="utf-8"))["summary"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
