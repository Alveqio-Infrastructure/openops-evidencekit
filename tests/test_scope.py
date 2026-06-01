import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.scope import create_scope_report, validate_scope_document
from openops_evidence.schema import validate_scope_report


ROOT = Path(__file__).resolve().parents[1]


class ScopeTests(unittest.TestCase):
    def test_scope_report_renders_all_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "scope-report.json"
            markdown = temp / "scope-report.md"
            csv = temp / "scope-report.csv"

            self.assertEqual(main(["scope", "validate", str(ROOT / "examples" / "scope.sample.toml")]), 0)
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(report), "-t", "scope-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "--fail-on-warn",
                        "-o",
                        str(temp / "scope-fail.md"),
                    ]
                ),
                1,
            )

            data = json.loads(report.read_text(encoding="utf-8"))
            assets = {item["id"]: item for item in data["assets"]}
            domains = {item["name"]: item for item in data["domains"]}
            self.assertEqual(validate_scope_report(data), [])
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["summary"]["missing_in_scope_assets"], 1)
            self.assertEqual(data["summary"]["out_of_scope_evidence_domains"], 1)
            self.assertEqual(data["summary"]["unclassified_evidence_assets"], 0)
            self.assertEqual(assets["web-01"]["status"], "present_in_scope")
            self.assertEqual(assets["db-01"]["status"], "missing_in_scope")
            self.assertEqual(domains["mail"]["status"], "present_out_of_scope")
            self.assertIn("# OpenOps Scope Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,scope_status", csv.read_text(encoding="utf-8"))

    def test_scope_document_validation_reports_authoring_errors(self):
        errors = validate_scope_document(
            {
                "assets": [
                    {"id": "web-01", "status": "in_scope"},
                    {"id": "web-01", "status": "bad"},
                ],
                "domains": [{"name": "backup", "required": "yes"}],
            }
        )

        self.assertIn("assets[1].id duplicates another assets entry: web-01", errors)
        self.assertIn("assets[1].status must be one of: in_scope, out_of_scope.", errors)
        self.assertIn("domains[0].required must be a boolean when present.", errors)

    def test_create_scope_report_marks_unclassified_evidence(self):
        report = create_scope_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "assets": [{"id": "unknown-01", "type": "host", "hostname": "", "roles": [], "tags": []}],
                "signals": {"backup": {"last_success_at": "2026-06-01T09:00:00+00:00"}},
            },
            {"assets": [], "domains": [{"name": "backup", "status": "in_scope"}]},
        )

        self.assertEqual(validate_scope_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["unclassified_evidence_assets"], 1)
        self.assertEqual(report["assets"][0]["status"], "unclassified_evidence")


if __name__ == "__main__":
    unittest.main()
