import unittest
import tempfile
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.quality import create_evidence_quality_report, render_quality_csv, render_quality_markdown
from openops_evidence.schema import validate_quality_report


class EvidenceQualityTests(unittest.TestCase):
    def test_quality_report_detects_hygiene_failures_and_warnings(self):
        evidence = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "metadata": {"source": "test"},
            "assets": [
                {"id": "web-01", "type": "host", "roles": [], "tags": []},
                {"id": "web-01", "type": "host", "roles": ["web"], "tags": []},
                {"id": "backup-01", "type": "backup-repository", "roles": ["backup"], "tags": []},
            ],
            "signals": {
                "backup": {"last_success_at": "2026-05-31T00:00:00+00:00"},
                "monitoring": {"targets": 1},
                "docs": {},
            },
        }

        report = create_evidence_quality_report(evidence)

        self.assertEqual(validate_quality_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        statuses = {check["id"]: check["status"] for check in report["checks"]}
        self.assertEqual(statuses["asset_ids_unique"], "fail")
        self.assertEqual(statuses["metadata_organization_present"], "warn")
        self.assertEqual(statuses["backup_assets_have_backup_signal"], "warn")
        self.assertIn("# OpenOps Evidence Quality Report", render_quality_markdown(report))
        self.assertIn("id,title,status,severity,path,reason,recommended_action", render_quality_csv(report))

    def test_quality_report_passes_clean_evidence(self):
        evidence = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "metadata": {"source": "test", "organization": "Example", "environment": "production"},
            "assets": [{"id": "web-01", "type": "host", "roles": ["web"], "tags": ["prod"]}],
            "signals": {"monitoring": {"targets": 1, "alert_channels": ["email"]}},
        }

        report = create_evidence_quality_report(evidence)

        self.assertEqual(validate_quality_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")

    def test_quality_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "quality-report.json"

            self.assertEqual(
                main(
                    [
                        "evidence",
                        "quality",
                        "-i",
                        "examples/evidence.sample.json",
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
