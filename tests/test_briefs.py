import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.briefs import create_report_brief, render_brief_markdown
from openops_evidence.cli import main
from openops_evidence.schema import validate_executive_brief


def _result(check_id, status, severity, remediation):
    return {
        "id": check_id,
        "title": check_id.replace("_", " ").title(),
        "status": status,
        "severity": severity,
        "required": status == "fail",
        "path": f"signals.{check_id}",
        "operator": "exists",
        "observed_count": 0,
        "remediation": remediation,
    }


def _report(status="fail", score=65, *results):
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "summary": {
            "score": score,
            "status": status,
            "checks_total": len(results),
            "checks_passed": len([item for item in results if item["status"] == "pass"]),
            "checks_failed": len([item for item in results if item["status"] == "fail"]),
            "checks_warn": len([item for item in results if item["status"] == "warn"]),
        },
        "results": list(results),
    }


class BriefTests(unittest.TestCase):
    def test_report_brief_prioritizes_top_findings(self):
        brief = create_report_brief(
            _report(
                "fail",
                65,
                _result("mail_dmarc", "warn", "low", "Set DMARC to quarantine or reject."),
                _result("backup_recent", "fail", "critical", "Fix backup jobs."),
                _result("mfa", "fail", "high", "Require MFA."),
            ),
            max_findings=2,
        )

        self.assertEqual(validate_executive_brief(brief), [])
        self.assertEqual(brief["summary"]["health"], "action_required")
        self.assertEqual([item["id"] for item in brief["top_findings"]], ["backup_recent", "mfa"])
        self.assertEqual(brief["next_steps"], ["Fix backup jobs.", "Require MFA."])

    def test_report_brief_for_clean_report_has_operational_next_steps(self):
        brief = create_report_brief(_report("pass", 100), max_findings=5)

        self.assertEqual(brief["summary"]["health"], "on_track")
        self.assertEqual(brief["top_findings"], [])
        self.assertIn("recurring evidence review cadence", brief["next_steps"][0])

    def test_render_brief_markdown(self):
        brief = create_report_brief(
            _report(
                "fail",
                70,
                _result("backup_recent", "fail", "critical", "Fix backups."),
            )
        )

        rendered = render_brief_markdown(brief)

        self.assertIn("# OpenOps Executive Brief", rendered)
        self.assertIn("Readiness needs attention", rendered)
        self.assertIn("Fix backups", rendered)

    def test_cli_brief_report_writes_json_and_validates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report_path = temp / "report.json"
            brief_path = temp / "brief.json"
            report_path.write_text(
                json.dumps(
                    _report(
                        "fail",
                        70,
                        _result("backup_recent", "fail", "critical", "Fix backups."),
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(["brief", "report", "-i", str(report_path), "-f", "json", "-o", str(brief_path)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(brief_path), "-t", "executive-brief"]), 0)
            brief = json.loads(brief_path.read_text(encoding="utf-8"))
            self.assertEqual(brief["summary"]["health"], "action_required")


if __name__ == "__main__":
    unittest.main()
