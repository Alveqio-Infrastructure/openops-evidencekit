import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.patching import create_patch_report, render_patch_csv, render_patch_markdown
from openops_evidence.schema import validate_patch_report


def _evidence(patch: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"patch": patch},
    }


class PatchReportTests(unittest.TestCase):
    def test_patch_report_passes_clean_patch_state(self):
        report = create_patch_report(_evidence({"source": "apt", "packages": [], "reboot_required": False}))

        self.assertEqual(validate_patch_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Patch Report", render_patch_markdown(report))
        rows = list(csv.DictReader(render_patch_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_patch_report_fails_on_security_updates_and_reboot(self):
        report = create_patch_report(
            _evidence(
                {
                    "source": "apt",
                    "reboot_required": True,
                    "packages": [
                        {
                            "name": "openssl",
                            "current_version": "1",
                            "candidate_version": "2",
                            "architecture": "amd64",
                            "security": True,
                        },
                        {
                            "name": "curl",
                            "current_version": "1",
                            "candidate_version": "2",
                            "architecture": "amd64",
                            "security": False,
                        },
                    ],
                }
            )
        )

        self.assertEqual(validate_patch_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["security_updates_total"], 1)
        self.assertEqual(report["summary"]["checks_failed"], 2)
        self.assertEqual(report["security_packages"][0]["name"], "openssl")

    def test_patch_cli_collects_renders_and_fails_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            apt = temp / "apt.txt"
            evidence = temp / "patch.evidence.json"
            report_json = temp / "patch-report.json"
            report_md = temp / "patch-report.md"
            report_csv = temp / "patch-report.csv"
            apt.write_text(
                "Listing...\ncurl/jammy-updates 7.81.0-1ubuntu1.21 amd64 [upgradable from: 7.81.0-1ubuntu1.20]\n",
                encoding="utf-8",
            )

            self.assertEqual(main(["collect", "apt-upgrades", str(apt), "-o", str(evidence)]), 0)
            self.assertEqual(main(["patch", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "patch-report"]), 0)
            self.assertEqual(main(["patch", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["patch", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["patch", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Patch Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("package", report_csv.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(report_json.read_text(encoding="utf-8"))["summary"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
