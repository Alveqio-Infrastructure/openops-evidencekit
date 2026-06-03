import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.access import create_access_report, render_access_csv, render_access_markdown
from openops_evidence.cli import main
from openops_evidence.schema import validate_access_report


def _evidence(access: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"access": access},
    }


class AccessReportTests(unittest.TestCase):
    def test_access_report_passes_controlled_admin_access(self):
        report = create_access_report(
            _evidence(
                {
                    "ssh_public_exposed": False,
                    "mfa_required": True,
                    "admin_entrypoints": ["vpn", "sso"],
                }
            )
        )

        self.assertEqual(validate_access_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["safe_entrypoints"], 2)
        self.assertEqual(report["summary"]["risky_entrypoints"], 0)
        self.assertIn("# OpenOps Access Exposure Report", render_access_markdown(report))
        rows = list(csv.DictReader(render_access_csv(report).splitlines()))
        self.assertGreaterEqual(len(rows), 2)
        self.assertIn("record_type", rows[0])

    def test_access_report_fails_public_ssh_missing_mfa_and_risky_entrypoint(self):
        report = create_access_report(
            _evidence(
                {
                    "ssh_public_exposed": True,
                    "mfa_required": False,
                    "admin_entrypoints": ["public-ssh"],
                }
            )
        )

        self.assertEqual(validate_access_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["risky_entrypoints"], 1)
        self.assertGreaterEqual(report["summary"]["checks_failed"], 3)

    def test_access_report_warns_on_unknown_entrypoint(self):
        report = create_access_report(
            _evidence(
                {
                    "ssh_public_exposed": False,
                    "mfa_required": True,
                    "admin_entrypoints": ["vpn", "custom-admin-proxy"],
                }
            )
        )

        self.assertEqual(validate_access_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["unknown_entrypoints"], 1)

    def test_access_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            report_json = temp / "access-report.json"
            report_md = temp / "access-report.md"
            report_csv = temp / "access-report.csv"
            evidence.write_text(
                json.dumps(
                    _evidence(
                        {
                            "ssh_public_exposed": False,
                            "mfa_required": True,
                            "admin_entrypoints": ["vpn", "custom-admin-proxy"],
                        }
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["access", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "access-report"]), 0)
            self.assertEqual(main(["access", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["access", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(
                main(["access", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )
            self.assertIn("# OpenOps Access Exposure Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,title", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
