import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.monitoring import create_monitoring_report, render_monitoring_csv, render_monitoring_markdown
from openops_evidence.schema import validate_monitoring_report


def _evidence(monitoring: dict) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"monitoring": monitoring},
    }


class MonitoringReportTests(unittest.TestCase):
    def test_monitoring_report_passes_healthy_targets_and_current_alert_test(self):
        report = create_monitoring_report(
            _evidence(
                {
                    "system": "prometheus",
                    "targets": 3,
                    "targets_down": 0,
                    "alert_channels": ["email", "matrix"],
                    "last_alert_test_at": "2026-05-25T08:15:00+00:00",
                }
            ),
            max_alert_test_age_days=90,
        )

        self.assertEqual(validate_monitoring_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["targets"], 3)
        self.assertEqual(report["summary"]["alert_channels_total"], 2)
        self.assertIn("# OpenOps Monitoring Report", render_monitoring_markdown(report))
        rows = list(csv.DictReader(render_monitoring_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_monitoring_report_fails_without_targets_or_with_down_targets(self):
        report = create_monitoring_report(
            _evidence(
                {
                    "system": "prometheus",
                    "targets": 0,
                    "targets_down": 2,
                    "down_targets": [
                        {"target": "db:9100", "reason": "unreachable"},
                        "web:9100",
                    ],
                    "alert_channels": ["email"],
                    "last_alert_test_at": "2026-05-25T08:15:00+00:00",
                }
            )
        )

        self.assertEqual(validate_monitoring_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["checks_failed"], 2)
        self.assertEqual(report["summary"]["down_targets_count"], 2)

    def test_monitoring_report_warns_on_missing_alert_evidence(self):
        report = create_monitoring_report(
            _evidence(
                {
                    "system": "uptime-kuma",
                    "targets": 1,
                    "targets_down": 0,
                    "alert_channels": [],
                }
            )
        )

        self.assertEqual(validate_monitoring_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["checks_warn"], 2)

    def test_monitoring_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            report_json = temp / "monitoring-report.json"
            report_md = temp / "monitoring-report.md"
            report_csv = temp / "monitoring-report.csv"
            evidence.write_text(
                json.dumps(
                    _evidence(
                        {
                            "system": "uptime-kuma",
                            "targets": 1,
                            "targets_down": 0,
                            "alert_channels": [],
                        }
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["monitoring", "report", "-i", str(evidence), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "monitoring-report"]), 0)
            self.assertEqual(main(["monitoring", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["monitoring", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(
                main(["monitoring", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )
            self.assertIn("# OpenOps Monitoring Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,title,target", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
