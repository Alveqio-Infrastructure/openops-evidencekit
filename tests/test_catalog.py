import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.catalog import create_service_catalog_report, validate_catalog_document
from openops_evidence.cli import main
from openops_evidence.schema import validate_service_catalog_report


ROOT = Path(__file__).resolve().parents[1]


class ServiceCatalogTests(unittest.TestCase):
    def test_service_catalog_report_renders_all_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "service-catalog.json"
            markdown = temp / "service-catalog.md"
            csv = temp / "service-catalog.csv"

            self.assertEqual(main(["catalog", "validate", str(ROOT / "examples" / "service-catalog.sample.toml")]), 0)
            self.assertEqual(
                main(
                    [
                        "catalog",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(report), "-t", "service-catalog"]), 0)
            self.assertEqual(
                main(
                    [
                        "catalog",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "catalog",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
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
                        "catalog",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--fail-on-warn",
                        "-o",
                        str(temp / "service-catalog-fail.md"),
                    ]
                ),
                1,
            )

            data = json.loads(report.read_text(encoding="utf-8"))
            services = {item["id"]: item for item in data["services"]}
            self.assertEqual(validate_service_catalog_report(data), [])
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["summary"]["services_total"], 3)
            self.assertEqual(data["summary"]["services_warn"], 1)
            self.assertEqual(data["summary"]["missing_catalog_assets_count"], 1)
            self.assertEqual(data["summary"]["missing_runbooks_count"], 1)
            self.assertEqual(data["summary"]["unassigned_evidence_assets_count"], 0)
            self.assertEqual(services["public-web"]["status"], "pass")
            self.assertEqual(services["database"]["status"], "warn")
            self.assertEqual(services["database"]["missing_assets"], ["db-01"])
            self.assertEqual(services["database"]["missing_runbooks"], ["database-restore"])
            self.assertIn("# OpenOps Service Catalog Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,name,owner", csv.read_text(encoding="utf-8"))

    def test_catalog_document_validation_reports_authoring_errors(self):
        errors = validate_catalog_document(
            {
                "services": [
                    {
                        "id": "web",
                        "name": "Web",
                        "owner": "platform",
                        "criticality": "high",
                        "assets": ["web-01"],
                    },
                    {
                        "id": "web",
                        "name": "",
                        "owner": "",
                        "criticality": "urgent",
                        "assets": "web-02",
                    },
                    {
                        "id": "empty",
                        "name": "Empty service",
                        "owner": "ops",
                        "domains": [],
                        "runbooks": [],
                    },
                ]
            }
        )

        self.assertIn("services[1].id duplicates another services entry: web", errors)
        self.assertIn("services[1].name must be a non-empty string.", errors)
        self.assertIn("services[1].owner must be a non-empty string.", errors)
        self.assertIn("services[1].criticality must be one of: critical, high, low, medium.", errors)
        self.assertIn("services[1].assets must be a list when present.", errors)
        self.assertIn("services[2] must declare at least one asset, domain, or runbook.", errors)

    def test_create_service_catalog_report_tracks_unassigned_assets(self):
        report = create_service_catalog_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "assets": [
                    {"id": "web-01", "type": "host", "hostname": "web-01.example.invalid", "roles": ["web"], "tags": []},
                    {"id": "orphan-01", "type": "host", "hostname": "", "roles": [], "tags": ["orphan"]},
                ],
                "signals": {"backup": {"last_success_at": "2026-06-01T09:00:00+00:00"}},
            },
            {
                "services": [
                    {
                        "id": "web",
                        "name": "Web",
                        "owner": "platform",
                        "assets": ["web-01"],
                        "domains": ["backup"],
                    }
                ]
            },
        )

        self.assertEqual(validate_service_catalog_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["unassigned_evidence_assets_count"], 1)
        self.assertEqual(report["unassigned_assets"][0]["id"], "orphan-01")


if __name__ == "__main__":
    unittest.main()
