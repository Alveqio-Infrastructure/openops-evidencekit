import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.gates import evaluate_report_gate, render_gate_markdown
from openops_evidence.schema import validate_gate_result


def _report(status="pass", score=100, failed=0, warnings=0, *results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "summary": {
            "score": score,
            "status": status,
            "checks_total": len(results),
            "checks_passed": len([item for item in results if item["status"] == "pass"]),
            "checks_failed": failed,
            "checks_warn": warnings,
        },
        "results": list(results),
    }


def _result(check_id, status, severity):
    return {
        "id": check_id,
        "title": check_id.replace("_", " ").title(),
        "status": status,
        "severity": severity,
        "required": status == "fail",
        "path": f"signals.{check_id}",
        "operator": "exists",
    }


class GateTests(unittest.TestCase):
    def test_report_gate_passes_configured_thresholds(self):
        gate = evaluate_report_gate(
            _report("pass", 98, 0, 0, _result("backup_recent", "pass", "critical")),
            min_score=95,
            max_failed=0,
            max_warnings=0,
            max_critical=0,
        )

        self.assertEqual(validate_gate_result(gate), [])
        self.assertEqual(gate["summary"]["status"], "pass")
        self.assertEqual(gate["summary"]["conditions_failed"], 0)

    def test_report_gate_fails_failed_report_and_thresholds(self):
        gate = evaluate_report_gate(
            _report(
                "fail",
                70,
                1,
                1,
                _result("backup_recent", "fail", "critical"),
                _result("mail_dmarc_policy", "warn", "low"),
            ),
            min_score=90,
            max_failed=0,
            max_warnings=0,
            max_critical=0,
        )

        failed_ids = [condition["id"] for condition in gate["conditions"] if condition["status"] == "fail"]
        self.assertEqual(gate["summary"]["status"], "fail")
        self.assertIn("report_status", failed_ids)
        self.assertIn("min_score", failed_ids)
        self.assertIn("max_failed", failed_ids)
        self.assertIn("max_warnings", failed_ids)
        self.assertIn("max_critical", failed_ids)

    def test_report_gate_can_ignore_source_report_status(self):
        gate = evaluate_report_gate(
            _report("fail", 90, 1, 0, _result("backup_recent", "fail", "critical")),
            ignore_report_status=True,
        )

        self.assertEqual(gate["summary"]["status"], "pass")
        self.assertEqual(gate["summary"]["conditions_total"], 0)

    def test_render_gate_markdown(self):
        gate = evaluate_report_gate(
            _report("pass", 100, 0, 0, _result("backup_recent", "pass", "critical")),
            min_score=90,
        )

        rendered = render_gate_markdown(gate)

        self.assertIn("# OpenOps Gate Result", rendered)
        self.assertIn("Readiness score is at least 90", rendered)

    def test_cli_gate_report_writes_json_and_exits_on_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report_path = temp / "report.json"
            gate_path = temp / "gate.json"
            report_path.write_text(
                json.dumps(_report("fail", 70, 1, 0, _result("backup_recent", "fail", "critical"))),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "gate",
                    "report",
                    "-i",
                    str(report_path),
                    "--min-score",
                    "90",
                    "--max-critical",
                    "0",
                    "-o",
                    str(gate_path),
                ]
            )

            self.assertEqual(exit_code, 1)
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["status"], "fail")
            self.assertEqual(main(["validate", "-i", str(gate_path), "-t", "gate-result"]), 0)


if __name__ == "__main__":
    unittest.main()
