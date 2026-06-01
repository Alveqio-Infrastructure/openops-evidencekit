import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.runbooks import create_runbook_report
from openops_evidence.schema import validate_runbook_report


ROOT = Path(__file__).resolve().parents[1]


class RunbookReportTests(unittest.TestCase):
    def test_runbook_report_renders_all_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "runbook-report.json"
            markdown = temp / "runbook-report.md"
            csv = temp / "runbook-report.csv"

            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--max-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(report), "-t", "runbook-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--max-age-days",
                        "365",
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--fail-on-warn",
                        "-o",
                        str(temp / "runbook-fail.md"),
                    ]
                ),
                1,
            )

            data = json.loads(report.read_text(encoding="utf-8"))
            runbooks = {item["name"]: item for item in data["runbooks"]}
            services = {item["id"]: item for item in data["services"]}
            self.assertEqual(validate_runbook_report(data), [])
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["summary"]["observed_runbooks"], 2)
            self.assertEqual(data["summary"]["expected_runbooks"], 3)
            self.assertEqual(data["summary"]["missing_runbooks_count"], 1)
            self.assertEqual(runbooks["backup-restore"]["status"], "current")
            self.assertEqual(runbooks["database-restore"]["status"], "missing")
            self.assertEqual(services["database"]["missing_runbooks"], ["database-restore"])
            self.assertIn("# OpenOps Runbook Coverage Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,name,owner,status", csv.read_text(encoding="utf-8"))

    def test_runbook_report_marks_stale_and_unreferenced_runbooks(self):
        report = create_runbook_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {
                    "docs": {
                        "runbooks": [
                            {
                                "name": "backup-restore",
                                "path": "runbooks/backup-restore.md",
                                "updated_at": "2000-01-01T00:00:00+00:00",
                            },
                            {
                                "name": "orphan",
                                "path": "runbooks/orphan.md",
                                "updated_at": "2026-06-01T00:00:00+00:00",
                            },
                        ]
                    }
                },
            },
            catalog_document={
                "services": [
                    {
                        "id": "web",
                        "name": "Web",
                        "owner": "platform",
                        "runbooks": ["backup-restore"],
                    }
                ]
            },
            max_age_days=30,
        )

        runbooks = {item["name"]: item for item in report["runbooks"]}
        self.assertEqual(validate_runbook_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["stale_runbooks_count"], 1)
        self.assertEqual(report["summary"]["unreferenced_runbooks_count"], 1)
        self.assertEqual(runbooks["backup-restore"]["status"], "stale")
        self.assertEqual(runbooks["orphan"]["status"], "unreferenced")


if __name__ == "__main__":
    unittest.main()
