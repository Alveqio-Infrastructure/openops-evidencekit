import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.incident import create_incident_report, render_incident_csv, render_incident_markdown
from openops_evidence.schema import validate_incident_report


def _evidence(*, runbooks: list[dict], alert_channels: list[str], access: dict | None = None) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {
            "backup": {"restore_test_at": "2026-05-20T10:00:00+00:00"},
            "monitoring": {"alert_channels": alert_channels},
            "access": access or {"ssh_public_exposed": False, "mfa_required": True},
            "docs": {"runbooks": runbooks},
        },
    }


def _catalog(services: list[dict]) -> dict:
    return {"metadata": {"name": "Unit catalog"}, "services": services}


class IncidentReportTests(unittest.TestCase):
    def test_incident_report_passes_complete_readiness_evidence(self):
        report = create_incident_report(
            _evidence(
                runbooks=[{"name": "incident-escalation", "path": "runbooks/incident.md", "updated_at": "2026-05-20T00:00:00+00:00"}],
                alert_channels=["email"],
            ),
            catalog_document=_catalog(
                [
                    {
                        "id": "web",
                        "name": "Website",
                        "owner": "platform",
                        "criticality": "high",
                        "assets": ["web-01"],
                        "runbooks": ["incident-escalation"],
                        "contacts": ["platform@example.invalid"],
                    }
                ]
            ),
        )

        self.assertEqual(validate_incident_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["incident_runbooks_total"], 1)
        self.assertIn("# OpenOps Incident Readiness Report", render_incident_markdown(report))
        rows = list(csv.DictReader(render_incident_csv(report).splitlines()))
        self.assertEqual(rows[0]["record_type"], "check")

    def test_incident_report_fails_high_impact_service_without_contact_or_runbook(self):
        report = create_incident_report(
            _evidence(runbooks=[], alert_channels=[]),
            catalog_document=_catalog(
                [
                    {
                        "id": "db",
                        "name": "Database",
                        "owner": "platform",
                        "criticality": "critical",
                        "assets": ["db-01"],
                        "runbooks": ["database-restore"],
                        "contacts": [],
                    }
                ]
            ),
        )

        self.assertEqual(validate_incident_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertGreaterEqual(report["summary"]["checks_failed"], 4)
        self.assertEqual(report["summary"]["high_impact_services_missing_contacts"], 1)

    def test_incident_report_warns_without_catalog(self):
        report = create_incident_report(
            _evidence(
                runbooks=[{"name": "incident-escalation", "updated_at": "2026-05-20T00:00:00+00:00"}],
                alert_channels=["email"],
            )
        )

        self.assertEqual(validate_incident_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["checks_warn"], 2)

    def test_incident_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            catalog = temp / "catalog.json"
            report_json = temp / "incident-report.json"
            report_md = temp / "incident-report.md"
            report_csv = temp / "incident-report.csv"
            evidence.write_text(json.dumps(_evidence(runbooks=[], alert_channels=[])), encoding="utf-8")
            catalog.write_text(
                json.dumps(
                    _catalog(
                        [
                            {
                                "id": "db",
                                "name": "Database",
                                "owner": "platform",
                                "criticality": "critical",
                                "assets": ["db-01"],
                                "runbooks": ["database-restore"],
                                "contacts": [],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["incident", "report", "-i", str(evidence), "-c", str(catalog), "-f", "json", "-o", str(report_json)]), 0)
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "incident-report"]), 0)
            self.assertEqual(main(["incident", "report", "-i", str(evidence), "-c", str(catalog), "-o", str(report_md)]), 0)
            self.assertEqual(main(["incident", "report", "-i", str(evidence), "-c", str(catalog), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(
                main(["incident", "report", "-i", str(evidence), "-c", str(catalog), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )
            self.assertIn("# OpenOps Incident Readiness Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,title,name", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
