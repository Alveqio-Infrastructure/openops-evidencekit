import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProjectDocsTests(unittest.TestCase):
    def test_required_project_policy_documents_exist(self):
        for name in ("SECURITY.md", "GOVERNANCE.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"):
            with self.subTest(name=name):
                path = ROOT / name
                self.assertTrue(path.is_file())
                self.assertGreater(len(path.read_text(encoding="utf-8").strip()), 100)

    def test_readme_links_maintainer_policy(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("GOVERNANCE.md", readme)
        self.assertIn("docs/release-process.md", readme)

    def test_readme_links_existing_workflow_visual(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        visual = ROOT / "docs" / "assets" / "openops-evidencekit-flow.svg"
        self.assertIn("docs/assets/openops-evidencekit-flow.svg", readme)
        self.assertTrue(visual.is_file())


if __name__ == "__main__":
    unittest.main()
