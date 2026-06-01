import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class QuestionnaireTests(unittest.TestCase):
    def test_questionnaire_policy_renders_all_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            questionnaire = temp / "questionnaire.json"
            markdown = temp / "questionnaire.md"
            csv = temp / "questionnaire.csv"

            self.assertEqual(
                main(
                    [
                        "questionnaire",
                        "policy",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(questionnaire),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(questionnaire), "-t", "questionnaire"]), 0)
            self.assertEqual(
                main(
                    [
                        "questionnaire",
                        "policy",
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
                        "questionnaire",
                        "policy",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )

            data = json.loads(questionnaire.read_text(encoding="utf-8"))
            questions = {item["id"]: item for item in data["questions"]}
            self.assertEqual(data["summary"]["questions_total"], 10)
            self.assertEqual(data["summary"]["domain_count"], 6)
            self.assertEqual(questions["backup_recent"]["domain"], "backup")
            self.assertIn("no older than 2 day(s)", questions["backup_recent"]["request"])
            self.assertIn("# OpenOps Evidence Questionnaire", markdown.read_text(encoding="utf-8"))
            self.assertIn("id,domain,title,required", csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
