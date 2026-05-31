import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.compare import compare_reports, render_comparison_markdown
from openops_evidence.schema import validate_report_comparison


def _report(*results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-05-31T10:00:00+00:00",
        "summary": {
            "score": 90,
            "status": "pass",
            "checks_total": len(results),
            "checks_passed": sum(1 for item in results if item["status"] == "pass"),
            "checks_failed": sum(1 for item in results if item["status"] == "fail"),
            "checks_warn": sum(1 for item in results if item["status"] == "warn"),
        },
        "results": list(results),
    }


def _result(check_id, status, severity="medium", observed_count=1):
    return {
        "id": check_id,
        "title": check_id.replace("_", " ").title(),
        "status": status,
        "severity": severity,
        "required": True,
        "path": f"signals.{check_id}",
        "operator": "exists",
        "expected": None,
        "observed": [],
        "observed_count": observed_count,
        "mode": "any",
        "remediation": f"Fix {check_id}.",
        "error": None,
    }


class CompareTests(unittest.TestCase):
    def test_compare_reports_detects_regressions_and_improvements(self):
        base = _report(
            _result("backup_recent", "pass"),
            _result("mfa_required", "fail"),
            _result("old_check", "pass"),
        )
        current = _report(
            _result("backup_recent", "fail"),
            _result("mfa_required", "pass"),
            _result("new_check", "warn"),
        )

        comparison = compare_reports(base, current)

        self.assertEqual(validate_report_comparison(comparison), [])
        self.assertEqual(comparison["summary"]["regressions_count"], 1)
        self.assertEqual(comparison["summary"]["improvements_count"], 1)
        self.assertEqual(comparison["summary"]["added_count"], 1)
        self.assertEqual(comparison["summary"]["removed_count"], 1)
        self.assertEqual(comparison["regressions"][0]["id"], "backup_recent")
        self.assertEqual(comparison["improvements"][0]["id"], "mfa_required")
        self.assertEqual(comparison["added"][0]["id"], "new_check")
        self.assertEqual(comparison["removed"][0]["id"], "old_check")

    def test_render_comparison_markdown(self):
        comparison = compare_reports(
            _report(_result("backup_recent", "pass")),
            _report(_result("backup_recent", "fail")),
        )
        markdown = render_comparison_markdown(comparison)
        self.assertIn("# OpenOps Report Comparison", markdown)
        self.assertIn("## Regressions", markdown)
        self.assertIn("backup_recent", markdown)

    def test_cli_compare_fail_on_regression(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            base = temp / "base.json"
            current = temp / "current.json"
            output = temp / "comparison.json"
            base.write_text(json.dumps(_report(_result("backup_recent", "pass"))), encoding="utf-8")
            current.write_text(json.dumps(_report(_result("backup_recent", "fail"))), encoding="utf-8")

            exit_code = main(
                [
                    "compare",
                    "--base",
                    str(base),
                    "--current",
                    str(current),
                    "--fail-on-regression",
                    "-o",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 1)
            comparison = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(comparison["summary"]["regressions_count"], 1)


if __name__ == "__main__":
    unittest.main()
