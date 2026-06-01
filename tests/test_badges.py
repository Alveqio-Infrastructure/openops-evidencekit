import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.badges import create_report_badge
from openops_evidence.cli import main
from openops_evidence.schema import validate_badge


def _report(status="pass", score=100):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "summary": {
            "score": score,
            "status": status,
            "checks_total": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "checks_warn": 0,
        },
        "results": [],
    }


class BadgeTests(unittest.TestCase):
    def test_report_badge_uses_shields_endpoint_shape(self):
        badge = create_report_badge(_report("pass", 96), label="readiness")

        self.assertEqual(validate_badge(badge), [])
        self.assertEqual(badge["schemaVersion"], 1)
        self.assertEqual(badge["label"], "readiness")
        self.assertEqual(badge["message"], "pass 96")
        self.assertEqual(badge["color"], "brightgreen")

    def test_report_badge_marks_failed_reports_red(self):
        badge = create_report_badge(_report("fail", 80))

        self.assertEqual(badge["message"], "fail 80")
        self.assertEqual(badge["color"], "red")

    def test_cli_badge_report_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            badge_path = temp / "badge.json"
            report.write_text(json.dumps(_report("pass", 90)), encoding="utf-8")

            exit_code = main(
                [
                    "badge",
                    "report",
                    "-i",
                    str(report),
                    "--label",
                    "openops readiness",
                    "-o",
                    str(badge_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            badge = json.loads(badge_path.read_text(encoding="utf-8"))
            self.assertEqual(badge["label"], "openops readiness")
            self.assertEqual(badge["color"], "green")
            self.assertEqual(main(["validate", "-i", str(badge_path), "-t", "badge"]), 0)


if __name__ == "__main__":
    unittest.main()
