import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.schema import validate_service_level_report
from openops_evidence.service_level import (
    create_service_level_report,
    render_service_level_csv,
    render_service_level_markdown,
)


def _evidence(service_levels: list[dict]) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"monitoring": {"service_levels": service_levels}},
    }


def _catalog() -> dict:
    return {
        "metadata": {"name": "Unit catalog", "owner": "Ops"},
        "services": [
            {
                "id": "api",
                "name": "API",
                "owner": "platform",
                "criticality": "high",
                "slo_target_percent": 99.5,
                "domains": ["monitoring"],
            },
            {
                "id": "db",
                "name": "Database",
                "owner": "platform",
                "criticality": "critical",
                "domains": ["monitoring"],
            },
        ],
    }


class ServiceLevelReportTests(unittest.TestCase):
    def test_service_level_report_marks_pass_fail_and_missing_evidence(self):
        report = create_service_level_report(
            _evidence(
                [
                    {
                        "service_id": "api",
                        "uptime_percent": 99.7,
                        "window": "30d",
                        "error_budget_remaining_percent": 80.0,
                    },
                    {
                        "service_id": "db",
                        "uptime_percent": 99.1,
                        "window": "30d",
                        "error_budget_remaining_percent": 0.0,
                    },
                ]
            ),
            _catalog(),
        )

        self.assertEqual(validate_service_level_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["services_passed"], 1)
        self.assertEqual(report["summary"]["services_failed"], 1)
        self.assertEqual(report["services"][0]["status"], "pass")
        self.assertEqual(report["services"][1]["status"], "fail")
        self.assertIn("# OpenOps Service Level Report", render_service_level_markdown(report))
        rows = list(csv.DictReader(render_service_level_csv(report).splitlines()))
        self.assertEqual(rows[0]["id"], "api")

    def test_service_level_report_warns_on_missing_evidence(self):
        report = create_service_level_report(_evidence([]), _catalog())

        self.assertEqual(validate_service_level_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["services_missing_evidence"], 2)
        self.assertEqual(report["services"][0]["evidence_status"], "missing")

    def test_service_level_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            catalog = temp / "catalog.json"
            report_json = temp / "service-level-report.json"
            report_md = temp / "service-level-report.md"
            report_csv = temp / "service-level-report.csv"
            evidence.write_text(json.dumps(_evidence([])), encoding="utf-8")
            catalog.write_text(json.dumps(_catalog()), encoding="utf-8")

            self.assertEqual(
                main(["service-level", "report", "-i", str(evidence), "-c", str(catalog), "-f", "json", "-o", str(report_json)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "service-level-report"]), 0)
            self.assertEqual(main(["service-level", "report", "-i", str(evidence), "-c", str(catalog), "-o", str(report_md)]), 0)
            self.assertEqual(
                main(["service-level", "report", "-i", str(evidence), "-c", str(catalog), "-f", "csv", "-o", str(report_csv)]),
                0,
            )
            self.assertEqual(
                main(["service-level", "report", "-i", str(evidence), "-c", str(catalog), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )
            self.assertIn("# OpenOps Service Level Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("id,name,owner,criticality", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
