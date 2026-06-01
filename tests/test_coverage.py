import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CoverageTests(unittest.TestCase):
    def test_coverage_report_matches_baseline_domains(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            coverage = temp / "policy-coverage.json"
            markdown = temp / "policy-coverage.md"
            csv = temp / "policy-coverage.csv"

            self.assertEqual(
                main(
                    [
                        "coverage",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(coverage),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(coverage), "-t", "policy-coverage"]), 0)
            self.assertEqual(
                main(
                    [
                        "coverage",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "coverage",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )

            data = json.loads(coverage.read_text(encoding="utf-8"))
            domains = {item["domain"]: item for item in data["domains"]}
            self.assertEqual(data["summary"]["status"], "pass")
            self.assertEqual(data["summary"]["coverage_percent"], 100)
            self.assertEqual(data["summary"]["evidence_domains_total"], 6)
            self.assertEqual(domains["backup"]["check_count"], 2)
            self.assertEqual(domains["mail"]["optional_count"], 1)
            self.assertIn("# OpenOps Policy Coverage", markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,status,evidence_present", csv.read_text(encoding="utf-8"))

    def test_coverage_report_surfaces_missing_and_unreviewed_domains(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            policy = temp / "policy.toml"
            coverage = temp / "policy-coverage.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {"last_success_at": "2026-06-01T09:00:00+00:00"},
                            "tickets": {"open": 3},
                        },
                    }
                ),
                encoding="utf-8",
            )
            policy.write_text(
                """
[[checks]]
id = "backup_recent"
title = "Recent backup"
path = "signals.backup.last_success_at"
operator = "exists"
severity = "critical"
required = true

[[checks]]
id = "logging_present"
title = "Logging evidence exists"
path = "signals.logging.enabled"
operator = "equals"
value = true
severity = "high"
required = true
""".lstrip(),
                encoding="utf-8",
            )

            self.assertEqual(
                main(["coverage", "report", "-i", str(evidence), "-p", str(policy), "-f", "json", "-o", str(coverage)]),
                0,
            )

            data = json.loads(coverage.read_text(encoding="utf-8"))
            domains = {item["domain"]: item for item in data["domains"]}
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["summary"]["coverage_percent"], 50)
            self.assertEqual(domains["backup"]["status"], "covered")
            self.assertEqual(domains["logging"]["status"], "missing_evidence")
            self.assertEqual(domains["tickets"]["status"], "unreviewed_evidence")


if __name__ == "__main__":
    unittest.main()
