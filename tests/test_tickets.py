import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.actions import create_action_plan
from openops_evidence.cli import main
from openops_evidence.tickets import export_action_plan_tickets


def _report(*results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-05-31T10:00:00+00:00",
        "summary": {
            "score": 50,
            "status": "fail",
            "checks_total": len(results),
            "checks_passed": 0,
            "checks_failed": len(results),
            "checks_warn": 0,
        },
        "results": list(results),
    }


def _result(check_id, severity="critical"):
    return {
        "id": check_id,
        "title": check_id.replace("_", " ").title(),
        "status": "fail",
        "severity": severity,
        "required": True,
        "path": f"signals.{check_id}",
        "operator": "exists",
        "expected": None,
        "observed": [],
        "observed_count": 1,
        "mode": "any",
        "remediation": "Fix it.",
        "error": None,
    }


class TicketExportTests(unittest.TestCase):
    def test_export_action_plan_tickets_skips_waived_items_by_default(self):
        plan = create_action_plan(
            _report(_result("backup_recent"), _result("mail_dmarc_policy", "low")),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "mail_dmarc_policy",
                        "owner": "ops@example.invalid",
                        "reason": "Accepted during rollout.",
                        "expires_at": "2099-12-31T00:00:00+00:00",
                    }
                ]
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = export_action_plan_tickets(plan, temp_dir)
            paths = sorted(path.name for path in Path(temp_dir).glob("*.md"))
            index = (Path(temp_dir) / "index.md").read_text(encoding="utf-8")

        self.assertEqual(summary["summary"]["ticket_count"], 1)
        self.assertEqual(paths, ["001-p0-backup_recent.md", "index.md"])
        self.assertIn("(001-p0-backup_recent.md)", index)

    def test_export_action_plan_tickets_can_include_waived_items(self):
        plan = create_action_plan(
            _report(_result("backup_recent")),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "backup_recent",
                        "owner": "ops@example.invalid",
                        "reason": "Accepted during migration.",
                        "expires_at": "2099-12-31T00:00:00+00:00",
                    }
                ]
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = export_action_plan_tickets(plan, temp_dir, include_waived=True)
            ticket = Path(temp_dir) / "001-p0-backup_recent.md"
            content = ticket.read_text(encoding="utf-8")

        self.assertEqual(summary["summary"]["ticket_count"], 1)
        self.assertIn("## Waiver", content)
        self.assertIn("ops@example\\.invalid", content)

    def test_cli_ticket_export(self):
        plan = create_action_plan(_report(_result("backup_recent")))
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            plan_path = temp / "action-plan.json"
            output_dir = temp / "tickets"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            exit_code = main(["ticket", "export", "-i", str(plan_path), "-o", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "index.md").is_file())
            self.assertTrue((output_dir / "001-p0-backup_recent.md").is_file())


if __name__ == "__main__":
    unittest.main()
