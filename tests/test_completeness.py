import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.completeness import (
    create_completeness_report,
    render_completeness_csv,
    render_completeness_markdown,
)
from openops_evidence.policy import Check
from openops_evidence.schema import validate_completeness_report


class CompletenessTests(unittest.TestCase):
    def test_completeness_report_marks_required_and_optional_missing_paths(self):
        evidence = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "metadata": {},
            "assets": [],
            "signals": {"backup": {"last_success_at": "2026-05-31T00:00:00+00:00"}},
        }
        checks = [
            Check(id="backup_recent", title="Backup recent", path="signals.backup.last_success_at", operator="exists"),
            Check(id="restore_drill", title="Restore drill", path="signals.backup.restore_test_at", operator="exists"),
            Check(
                id="mail_domain",
                title="Mail domain",
                path="signals.mail.domains[*].domain",
                operator="exists",
                required=False,
            ),
            Check(id="no_public_ssh", title="No public SSH", path="signals.access.public_ssh", operator="missing"),
        ]

        report = create_completeness_report(evidence, checks)

        self.assertEqual(validate_completeness_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["required_missing"], 1)
        self.assertEqual(report["summary"]["optional_missing"], 1)
        statuses = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(statuses["backup_recent"], "pass")
        self.assertEqual(statuses["restore_drill"], "fail")
        self.assertEqual(statuses["mail_domain"], "warn")
        self.assertEqual(statuses["no_public_ssh"], "pass")
        self.assertIn("# OpenOps Evidence Completeness Report", render_completeness_markdown(report))
        self.assertIn("id,title,status,evidence_status", render_completeness_csv(report))

    def test_completeness_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "completeness-report.json"

            self.assertEqual(
                main(
                    [
                        "evidence",
                        "completeness",
                        "-i",
                        "examples/evidence.sample.json",
                        "-p",
                        "examples/policy.baseline.toml",
                        "-f",
                        "json",
                        "-o",
                        str(output),
                    ]
                ),
                0,
            )

            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
