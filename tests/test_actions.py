import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from openops_evidence.cli import main
from openops_evidence.schema import validate_action_plan


def _report(*results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-05-31T10:00:00+00:00",
        "summary": {
            "score": 50,
            "status": "fail",
            "checks_total": len(results),
            "checks_passed": sum(1 for item in results if item["status"] == "pass"),
            "checks_failed": sum(1 for item in results if item["status"] == "fail"),
            "checks_warn": sum(1 for item in results if item["status"] == "warn"),
        },
        "results": list(results),
    }


def _result(check_id, status, severity, remediation="Fix it."):
    return {
        "id": check_id,
        "title": check_id.replace("_", " ").title(),
        "status": status,
        "severity": severity,
        "required": status == "fail",
        "path": f"signals.{check_id}",
        "operator": "exists",
        "expected": None,
        "observed": [],
        "observed_count": 1,
        "mode": "any",
        "remediation": remediation,
        "error": None,
    }


class ActionPlanTests(unittest.TestCase):
    def test_create_action_plan_prioritizes_non_pass_results(self):
        plan = create_action_plan(
            _report(
                _result("low_warn", "warn", "low"),
                _result("critical_fail", "fail", "critical", "Restore backups."),
                _result("high_pass", "pass", "high"),
            )
        )

        self.assertEqual(validate_action_plan(plan), [])
        self.assertEqual(plan["summary"]["status"], "action_required")
        self.assertEqual(plan["summary"]["items_total"], 2)
        self.assertEqual(plan["summary"]["action_required_count"], 2)
        self.assertEqual([item["id"] for item in plan["items"]], ["critical_fail", "low_warn"])
        self.assertEqual(plan["items"][0]["priority"], "P0")

    def test_create_action_plan_marks_active_waivers(self):
        plan = create_action_plan(
            _report(_result("critical_fail", "fail", "critical")),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "critical_fail",
                        "owner": "ops@example.invalid",
                        "reason": "Accepted during migration.",
                        "expires_at": "2099-12-31T00:00:00+00:00",
                    }
                ]
            },
        )

        self.assertEqual(validate_action_plan(plan), [])
        self.assertEqual(plan["summary"]["status"], "pass")
        self.assertEqual(plan["summary"]["action_required_count"], 0)
        self.assertEqual(plan["summary"]["waived_count"], 1)
        self.assertTrue(plan["items"][0]["waived"])
        self.assertEqual(plan["items"][0]["waiver"]["owner"], "ops@example.invalid")

    def test_create_action_plan_expired_waivers_still_require_action(self):
        plan = create_action_plan(
            _report(_result("critical_fail", "fail", "critical")),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "critical_fail",
                        "owner": "ops@example.invalid",
                        "reason": "Old exception.",
                        "expires_at": "2000-01-01T00:00:00+00:00",
                    }
                ]
            },
        )

        self.assertEqual(plan["summary"]["status"], "action_required")
        self.assertEqual(plan["summary"]["expired_waiver_count"], 1)
        self.assertFalse(plan["items"][0]["waived"])

    def test_action_plan_can_include_passed_results(self):
        plan = create_action_plan(
            _report(_result("passed", "pass", "medium")),
            include_pass=True,
        )
        self.assertEqual(plan["summary"]["pass_count"], 1)
        self.assertEqual(plan["items"][0]["status"], "pass")

    def test_render_action_plan_markdown_escapes_fields(self):
        plan = create_action_plan(
            _report(
                {
                    **_result("bad`id", "fail", "critical"),
                    "title": "<script>alert(1)</script>",
                    "remediation": "[click](javascript:alert(1))",
                }
            )
        )
        markdown = render_action_plan_markdown(plan)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[click](javascript:alert(1))", markdown)
        self.assertIn("&lt;script&gt;alert\\(1\\)&lt;/script&gt;", markdown)
        self.assertIn("``bad`id``", markdown)

    def test_render_action_plan_csv(self):
        plan = create_action_plan(_report(_result("backup_recent", "fail", "critical")))
        rows = list(csv.DictReader(io.StringIO(render_action_plan_csv(plan))))
        self.assertEqual(rows[0]["priority"], "P0")
        self.assertEqual(rows[0]["id"], "backup_recent")
        self.assertEqual(rows[0]["waived"], "False")

    def test_cli_plan_writes_json_and_returns_one_for_actions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            output = temp / "action-plan.json"
            report.write_text(
                json.dumps(_report(_result("backup_recent", "fail", "critical"))),
                encoding="utf-8",
            )

            exit_code = main(["plan", "-i", str(report), "-o", str(output)])

            self.assertEqual(exit_code, 1)
            plan = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(validate_action_plan(plan), [])
            self.assertEqual(plan["summary"]["items_total"], 1)

    def test_cli_plan_returns_zero_when_no_actions_exist(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            output = temp / "action-plan.md"
            report.write_text(json.dumps(_report(_result("mfa", "pass", "high"))), encoding="utf-8")

            exit_code = main(["plan", "-i", str(report), "-f", "markdown", "-o", str(output)])

            self.assertEqual(exit_code, 0)
            self.assertIn("No action items.", output.read_text(encoding="utf-8"))

    def test_cli_plan_accepts_waiver_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            waivers = temp / "waivers.toml"
            output = temp / "action-plan.json"
            report.write_text(
                json.dumps(_report(_result("backup_recent", "fail", "critical"))),
                encoding="utf-8",
            )
            waivers.write_text(
                "\n".join(
                    [
                        "[[waivers]]",
                        'check_id = "backup_recent"',
                        'owner = "ops@example.invalid"',
                        'reason = "Accepted during migration."',
                        'expires_at = "2099-12-31T00:00:00+00:00"',
                    ]
                ),
                encoding="utf-8",
            )

            exit_code = main(["plan", "-i", str(report), "--waivers", str(waivers), "-o", str(output)])

            self.assertEqual(exit_code, 0)
            plan = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(plan["summary"]["waived_count"], 1)


if __name__ == "__main__":
    unittest.main()
