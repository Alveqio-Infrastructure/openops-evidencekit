import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.schema import validate_software_inventory_report
from openops_evidence.software_inventory import (
    create_software_inventory_report,
    render_software_inventory_csv,
    render_software_inventory_markdown,
)


def _evidence(software_inventory: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"software_inventory": software_inventory},
    }


class SoftwareInventoryReportTests(unittest.TestCase):
    def test_software_inventory_report_passes_complete_components(self):
        report = create_software_inventory_report(
            _evidence(
                {
                    "source": "cyclonedx",
                    "bom_format": "CycloneDX",
                    "spec_version": "1.5",
                    "components": [
                        {
                            "bom_ref": "pkg:pypi/requests@2.32.3",
                            "type": "library",
                            "name": "requests",
                            "version": "2.32.3",
                            "group": "",
                            "purl": "pkg:pypi/requests@2.32.3",
                            "licenses": ["Apache-2.0"],
                        }
                    ],
                }
            )
        )

        self.assertEqual(validate_software_inventory_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Software Inventory Report", render_software_inventory_markdown(report))
        rows = list(csv.DictReader(render_software_inventory_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_software_inventory_report_warns_on_metadata_gaps(self):
        report = create_software_inventory_report(
            _evidence(
                {
                    "source": "cyclonedx",
                    "components": [
                        {
                            "bom_ref": "internal-helper",
                            "type": "library",
                            "name": "internal-helper",
                            "version": "",
                            "group": "",
                            "purl": "",
                            "licenses": [],
                        }
                    ],
                }
            )
        )

        self.assertEqual(validate_software_inventory_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["missing_versions"], 1)
        self.assertEqual(report["summary"]["missing_purls"], 1)
        self.assertEqual(report["summary"]["missing_licenses"], 1)

    def test_software_cli_collects_renders_and_fails_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            cyclonedx = temp / "bom.json"
            evidence = temp / "software.evidence.json"
            report_json = temp / "software-inventory-report.json"
            report_md = temp / "software-inventory-report.md"
            report_csv = temp / "software-inventory-report.csv"
            cyclonedx.write_text(
                """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"bom-ref": "pkg:pypi/requests@2.32.3", "type": "library", "name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3", "licenses": [{"license": {"id": "Apache-2.0"}}]},
    {"bom-ref": "internal-helper", "type": "library", "name": "internal-helper"}
  ]
}
""".strip(),
                encoding="utf-8",
            )

            self.assertEqual(main(["collect", "cyclonedx-json", str(cyclonedx), "-o", str(evidence)]), 0)
            self.assertEqual(main(["software", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "software-inventory-report"]), 0)
            self.assertEqual(main(["software", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["software", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["software", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Software Inventory Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("component", report_csv.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(report_json.read_text(encoding="utf-8"))["summary"]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
