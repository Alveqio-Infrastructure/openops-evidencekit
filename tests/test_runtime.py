import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.runtime import create_runtime_report, render_runtime_csv, render_runtime_markdown
from openops_evidence.schema import validate_runtime_report


def _evidence(runtime: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"runtime": runtime},
    }


class RuntimeReportTests(unittest.TestCase):
    def test_runtime_report_passes_healthy_runtime_evidence(self):
        report = create_runtime_report(
            _evidence(
                {
                    "docker": {
                        "containers_total": 2,
                        "containers_running": 2,
                        "containers_exited": 0,
                        "exited_containers": [],
                        "restart_policy_missing": [],
                    },
                    "systemd": {
                        "timers_total": 2,
                        "timers_active": 2,
                        "timers_failed": 0,
                        "failed_timers": [],
                    },
                }
            )
        )

        self.assertEqual(validate_runtime_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertIn("# OpenOps Runtime Report", render_runtime_markdown(report))
        rows = list(csv.DictReader(render_runtime_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_runtime_report_warns_on_container_gaps_and_fails_on_timers(self):
        report = create_runtime_report(
            _evidence(
                {
                    "docker": {
                        "containers_total": 3,
                        "containers_running": 2,
                        "containers_exited": 1,
                        "exited_containers": ["worker"],
                        "restart_policy_missing": ["api"],
                    },
                    "systemd": {
                        "timers_total": 2,
                        "timers_active": 1,
                        "timers_failed": 1,
                        "failed_timers": ["backup.timer"],
                    },
                }
            )
        )

        self.assertEqual(validate_runtime_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["checks_failed"], 1)
        self.assertEqual(report["summary"]["checks_warn"], 2)
        self.assertEqual(report["exited_containers"], ["worker"])
        self.assertEqual(report["restart_policy_missing"], ["api"])
        self.assertEqual(report["failed_timers"], ["backup.timer"])

    def test_runtime_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            report_json = temp / "runtime-report.json"
            report_md = temp / "runtime-report.md"
            report_csv = temp / "runtime-report.csv"
            evidence.write_text(
                json.dumps(
                    _evidence(
                        {
                            "docker": {"containers_total": 1, "containers_running": 0, "containers_exited": 1, "exited_containers": ["worker"]},
                            "systemd": {"timers_total": 1, "timers_active": 1, "timers_failed": 0, "failed_timers": []},
                        }
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["runtime", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "runtime-report"]), 0)
            self.assertEqual(main(["runtime", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["runtime", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(main(["runtime", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]), 1)
            self.assertIn("# OpenOps Runtime Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,title,name", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
