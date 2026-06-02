import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.restore import create_restore_report, render_restore_csv, render_restore_markdown
from openops_evidence.schema import validate_restore_report


ROOT = Path(__file__).resolve().parents[1]


class RestoreReportTests(unittest.TestCase):
    def test_create_report_passes_current_backup_and_restore_drill(self):
        evidence = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T09:00:00+00:00",
            "metadata": {"source": "unit-test", "organization": "Example", "environment": "test"},
            "assets": [],
            "signals": {
                "backup": {
                    "tool": "restic",
                    "last_success_at": "2026-05-31T22:10:00+00:00",
                    "restore_test_at": "2026-05-18T13:30:00+00:00",
                    "repository_count": 1,
                    "protected_hosts": ["web-01"],
                }
            },
        }

        report = create_restore_report(
            evidence,
            max_drill_age_days=90,
            max_backup_age_days=2,
            now=datetime(2026, 6, 1, 12, tzinfo=UTC),
        )

        self.assertEqual(validate_restore_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["restore_tests_total"], 1)
        self.assertEqual(report["summary"]["successful_restore_tests"], 1)
        self.assertEqual(report["summary"]["protected_hosts_count"], 1)
        self.assertIn("# OpenOps Restore Assurance Report", render_restore_markdown(report))
        self.assertIn("record_type,id,title", render_restore_csv(report))

    def test_create_report_fails_missing_restore_and_backup_signal(self):
        report = create_restore_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T09:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            },
            now=datetime(2026, 6, 1, 12, tzinfo=UTC),
        )

        self.assertEqual(validate_restore_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["restore_tests_total"], 0)
        statuses = {check["id"]: check["status"] for check in report["checks"]}
        self.assertEqual(statuses["backup_signal_present"], "fail")
        self.assertEqual(statuses["restore_drill_recorded"], "fail")

    def test_create_report_flags_failed_explicit_restore_test(self):
        report = create_restore_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T09:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {
                    "backup": {
                        "last_success_at": "2026-06-01T01:00:00+00:00",
                        "repository_count": 1,
                        "restore_tests": [
                            {
                                "id": "restore-drill-2026-06",
                                "target": "wiki",
                                "tested_at": "2026-06-01T08:00:00+00:00",
                                "outcome": "fail",
                                "verifier": "ops",
                            }
                        ],
                    }
                },
            },
            now=datetime(2026, 6, 1, 12, tzinfo=UTC),
        )

        self.assertEqual(validate_restore_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["failed_restore_tests"], 1)
        self.assertEqual(report["restore_tests"][0]["status"], "failed")

    def test_cli_outputs_all_formats_and_fail_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            json_report = temp / "restore-report.json"
            markdown = temp / "restore-report.md"
            csv = temp / "restore-report.csv"
            stale_evidence = temp / "stale-restore.json"
            stale_evidence.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-01-01T00:00:00+00:00",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "restore",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-drill-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(json_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(json_report), "-t", "restore-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "restore",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-drill-age-days",
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
                        "restore",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-drill-age-days",
                        "365",
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )
            self.assertIn("# OpenOps Restore Assurance Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,title", csv.read_text(encoding="utf-8"))
            self.assertEqual(
                main(
                    [
                        "restore",
                        "report",
                        "-i",
                        str(stale_evidence),
                        "--max-drill-age-days",
                        "7",
                        "--fail-on-warn",
                        "-o",
                        str(temp / "stale.md"),
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
