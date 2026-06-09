import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class ScorecardTests(unittest.TestCase):
    def test_scorecard_report_groups_checks_by_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            scorecard = temp / "scorecard.json"
            markdown = temp / "scorecard.md"
            csv = temp / "scorecard.csv"
            html = temp / "scorecard.html"

            self.assertEqual(
                main(
                    [
                        "check",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["scorecard", "report", "-i", str(report), "-f", "json", "-o", str(scorecard)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(scorecard), "-t", "scorecard"]), 0)
            self.assertEqual(
                main(["scorecard", "report", "-i", str(report), "-f", "markdown", "-o", str(markdown)]),
                0,
            )
            self.assertEqual(
                main(["scorecard", "report", "-i", str(report), "-f", "csv", "-o", str(csv)]),
                0,
            )
            self.assertEqual(
                main(["scorecard", "report", "-i", str(report), "-f", "html", "-o", str(html)]),
                0,
            )

            data = json.loads(scorecard.read_text(encoding="utf-8"))
            domains = {item["domain"]: item for item in data["domains"]}
            self.assertEqual(data["summary"]["status"], "pass")
            self.assertEqual(data["summary"]["domains_total"], 7)
            self.assertEqual(domains["backup"]["checks_total"], 2)
            self.assertEqual(domains["dns"]["checks_total"], 2)
            self.assertEqual(domains["monitoring"]["checks_total"], 2)
            self.assertEqual(domains["tls"]["title"], "TLS")
            self.assertIn("# OpenOps Domain Scorecard", markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,title,status,score", csv.read_text(encoding="utf-8"))
            self.assertIn("<title>OpenOps Domain Scorecard</title>", html.read_text(encoding="utf-8"))

    def test_scorecard_marks_warning_domains(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "report.json"
            scorecard = Path(temp_dir) / "scorecard.json"
            report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "summary": {
                            "score": 100,
                            "status": "pass",
                            "checks_total": 1,
                            "checks_passed": 0,
                            "checks_failed": 0,
                            "checks_warn": 1,
                        },
                        "results": [
                            {
                                "id": "mail_dmarc_policy",
                                "title": "Mail domain has DMARC policy",
                                "status": "warn",
                                "severity": "low",
                                "required": False,
                                "path": "signals.mail.domains[*].dmarc",
                                "operator": "one_of",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["scorecard", "report", "-i", str(report), "-f", "json", "-o", str(scorecard)]), 0)

            data = json.loads(scorecard.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["domains"][0]["domain"], "mail")
            self.assertEqual(data["domains"][0]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
