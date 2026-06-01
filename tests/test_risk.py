import csv
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.risk import create_risk_register, render_risk_register_csv, render_risk_register_markdown
from openops_evidence.schema import validate_risk_register


def _report(*results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-05-31T10:00:00+00:00",
        "summary": {
            "score": 70,
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


class RiskRegisterTests(unittest.TestCase):
    def test_create_risk_register_tracks_open_accepted_and_closed_risks(self):
        register = create_risk_register(
            _report(
                _result("backup_recent", "fail", "critical", "Restore backup jobs."),
                _result("mail_policy", "warn", "medium", "Tighten DMARC."),
                _result("mfa", "pass", "high"),
            ),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "backup_recent",
                        "owner": "ops@example.invalid",
                        "reason": "Accepted during migration.",
                        "expires_at": "2026-12-31T00:00:00+00:00",
                    }
                ]
            },
            include_pass=True,
            now=datetime(2026, 6, 1, tzinfo=UTC),
        )

        self.assertEqual(validate_risk_register(register), [])
        self.assertEqual(register["summary"]["status"], "action_required")
        self.assertEqual(register["summary"]["open_count"], 1)
        self.assertEqual(register["summary"]["accepted_count"], 1)
        self.assertEqual(register["summary"]["closed_count"], 1)
        risks = {item["id"]: item for item in register["risks"]}
        self.assertEqual(risks["backup_recent"]["risk_status"], "accepted")
        self.assertEqual(risks["backup_recent"]["owner"], "ops@example.invalid")
        self.assertEqual(risks["mail_policy"]["risk_status"], "open")
        self.assertEqual(risks["mfa"]["risk_status"], "closed")
        self.assertIn("# OpenOps Risk Register", render_risk_register_markdown(register))
        rows = list(csv.DictReader(io.StringIO(render_risk_register_csv(register))))
        self.assertEqual({row["id"] for row in rows}, {"backup_recent", "mail_policy", "mfa"})

    def test_expired_waiver_remains_open(self):
        register = create_risk_register(
            _report(_result("backup_recent", "fail", "critical")),
            waiver_document={
                "waivers": [
                    {
                        "check_id": "backup_recent",
                        "owner": "ops@example.invalid",
                        "reason": "Old exception.",
                        "expires_at": "2026-01-01T00:00:00+00:00",
                    }
                ]
            },
            now=datetime(2026, 6, 1, tzinfo=UTC),
        )

        self.assertEqual(register["summary"]["open_count"], 1)
        self.assertEqual(register["summary"]["expired_acceptance_count"], 1)
        self.assertEqual(register["risks"][0]["risk_status"], "open")
        self.assertEqual(register["risks"][0]["waiver_status"], "expired")

    def test_cli_risk_register_outputs_formats_and_fail_on_open(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            json_output = temp / "risk-register.json"
            markdown = temp / "risk-register.md"
            csv_output = temp / "risk-register.csv"
            report.write_text(
                json.dumps(_report(_result("backup_recent", "fail", "critical"))),
                encoding="utf-8",
            )

            self.assertEqual(main(["risk", "register", "-i", str(report), "-o", str(json_output)]), 0)
            self.assertEqual(main(["validate", "-i", str(json_output), "-t", "risk-register"]), 0)
            self.assertEqual(
                main(["risk", "register", "-i", str(report), "-f", "markdown", "-o", str(markdown)]),
                0,
            )
            self.assertEqual(
                main(["risk", "register", "-i", str(report), "-f", "csv", "-o", str(csv_output)]),
                0,
            )
            self.assertEqual(
                main(["risk", "register", "-i", str(report), "--fail-on-open", "-o", str(temp / "fail.json")]),
                1,
            )
            self.assertIn("# OpenOps Risk Register", markdown.read_text(encoding="utf-8"))
            self.assertIn("priority,id,title", csv_output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
