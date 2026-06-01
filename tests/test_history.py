import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.history import append_report_history, render_history_csv, render_history_markdown
from openops_evidence.schema import validate_report_history


def _report(status="pass", score=100, failed=0, warnings=0):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "summary": {
            "score": score,
            "status": status,
            "checks_total": 10,
            "checks_passed": 10 - failed - warnings,
            "checks_failed": failed,
            "checks_warn": warnings,
        },
        "results": [],
    }


class HistoryTests(unittest.TestCase):
    def test_append_report_history_tracks_score_and_failure_delta(self):
        history = append_report_history(
            None,
            _report("fail", 70, failed=2, warnings=1),
            source="week-1",
            note="Initial review",
        )
        history = append_report_history(
            history,
            _report("pass", 95, failed=0, warnings=0),
            source="week-2",
            note="Backups fixed",
        )

        self.assertEqual(validate_report_history(history), [])
        self.assertEqual(history["summary"]["entries_total"], 2)
        self.assertEqual(history["summary"]["latest_status"], "pass")
        self.assertEqual(history["summary"]["score_change"], 25)
        self.assertEqual(history["summary"]["failed_delta"], -2)
        self.assertEqual(history["entries"][0]["source"], "week-1")

    def test_render_history_markdown_and_csv(self):
        history = append_report_history(
            None,
            _report("pass", 100),
            source="ci",
            note="Release check",
        )

        markdown = render_history_markdown(history)
        csv_output = render_history_csv(history)

        self.assertIn("# OpenOps Readiness History", markdown)
        self.assertIn("Release check", markdown)
        self.assertIn("recorded_at,report_generated_at,source,status,score", csv_output)
        self.assertIn("Release check", csv_output)

    def test_cli_history_append_validates_and_renders(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report_one = temp / "report-one.json"
            report_two = temp / "report-two.json"
            history_path = temp / "readiness-history.json"
            markdown_path = temp / "readiness-history.md"
            report_one.write_text(json.dumps(_report("fail", 80, failed=1)), encoding="utf-8")
            report_two.write_text(json.dumps(_report("pass", 100, failed=0)), encoding="utf-8")

            self.assertEqual(
                main(
                    [
                        "history",
                        "append",
                        "-i",
                        str(report_one),
                        "--source",
                        "first-run",
                        "-o",
                        str(history_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "history",
                        "append",
                        "-i",
                        str(report_two),
                        "--source",
                        "second-run",
                        "--note",
                        "All checks green",
                        "-o",
                        str(history_path),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(history_path), "-t", "history"]), 0)
            self.assertEqual(
                main(["history", "render", "-i", str(history_path), "-f", "markdown", "-o", str(markdown_path)]),
                0,
            )

            history = json.loads(history_path.read_text(encoding="utf-8"))
            self.assertEqual(history["summary"]["entries_total"], 2)
            self.assertEqual(history["summary"]["latest_score"], 100)
            self.assertIn("All checks green", markdown_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
