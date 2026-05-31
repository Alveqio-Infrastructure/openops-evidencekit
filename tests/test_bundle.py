import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.bundle import classify_artifact, create_bundle_manifest
from openops_evidence.schema import validate_bundle_manifest


class BundleTests(unittest.TestCase):
    def test_create_bundle_manifest_hashes_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-31T10:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {},
                    }
                ),
                encoding="utf-8",
            )
            report = temp / "report.md"
            report.write_text("# Report\n", encoding="utf-8", newline="\n")

            manifest = create_bundle_manifest(
                [str(evidence), str(report)],
                name="readiness-review",
                base_dir=str(temp),
            )

        self.assertEqual(validate_bundle_manifest(manifest), [])
        self.assertEqual(manifest["metadata"]["name"], "readiness-review")
        self.assertEqual(manifest["metadata"]["artifact_count"], 2)
        self.assertEqual(manifest["artifacts"][0]["path"], "evidence.json")
        self.assertEqual(manifest["artifacts"][0]["role"], "evidence")
        self.assertEqual(manifest["artifacts"][1]["role"], "report-markdown")
        expected_hash = hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "0.1",
                    "generated_at": "2026-05-31T10:00:00+00:00",
                    "metadata": {},
                    "assets": [],
                    "signals": {},
                }
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(manifest["artifacts"][0]["sha256"], expected_hash)

    def test_manifest_defaults_to_filenames_to_avoid_local_path_leaks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.toml"
            path.write_text("[[checks]]\nid = \"x\"\n", encoding="utf-8")
            manifest = create_bundle_manifest([str(path)])
        self.assertEqual(manifest["artifacts"][0]["path"], "policy.toml")

    def test_classifies_reports_and_policies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-31T10:00:00+00:00",
                        "summary": {},
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            policy = temp / "policy.toml"
            policy.write_text("[[checks]]\nid = \"x\"\n", encoding="utf-8")
            self.assertEqual(classify_artifact(report), "report")
            self.assertEqual(classify_artifact(policy), "policy")


if __name__ == "__main__":
    unittest.main()
