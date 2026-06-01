import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.attestations import (
    create_review_attestation,
    render_attestation_csv,
    render_attestation_markdown,
)
from openops_evidence.bundle import create_bundle_manifest
from openops_evidence.cli import main
from openops_evidence.schema import validate_review_attestation


ROOT = Path(__file__).resolve().parents[1]


class AttestationTests(unittest.TestCase):
    def test_review_attestation_records_manifest_and_warnings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "report.md"
            manifest_path = temp / "manifest.json"
            artifact.write_text("# Report\n", encoding="utf-8")
            manifest = create_bundle_manifest([str(artifact)], base_dir=str(temp))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            attestation = create_review_attestation(
                manifest,
                manifest_path,
                approver="Example Reviewer",
                role="Operations",
                statement="Reviewed generated artifacts for internal handoff.",
                report={
                    "summary": {
                        "status": "fail",
                        "score": 60,
                    }
                },
                gate={
                    "summary": {
                        "status": "pass",
                        "conditions_failed": 0,
                    }
                },
            )

            self.assertEqual(validate_review_attestation(attestation), [])
            self.assertEqual(attestation["summary"]["status"], "warn")
            self.assertEqual(attestation["summary"]["checks_warn"], 1)
            self.assertEqual(attestation["manifest"]["artifact_count"], 1)
            markdown = render_attestation_markdown(attestation)
            csv = render_attestation_csv(attestation)
            self.assertIn("# OpenOps Review Attestation", markdown)
            self.assertIn("Example Reviewer", markdown)
            self.assertIn("id,title,status,observed", csv)

    def test_cli_attest_review_outputs_all_formats_and_fail_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            attestation = temp / "review-attestation.json"
            markdown = temp / "review-attestation.md"
            csv = temp / "review-attestation.csv"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--scope",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "--base-evidence",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "-o",
                        str(pack),
                    ]
                ),
                0,
            )

            args = [
                "attest",
                "review",
                "--manifest",
                str(pack / "manifest.json"),
                "--report",
                str(pack / "report.json"),
                "--gate",
                str(pack / "gate-result.json"),
                "--scope-report",
                str(pack / "scope-report.json"),
                "--evidence-drift",
                str(pack / "evidence-drift.json"),
                "--privacy-scan",
                str(pack / "privacy-scan.json"),
                "--approver",
                "Example Reviewer",
                "--role",
                "Operations",
                "--statement",
                "Reviewed generated artifacts for internal handoff.",
                "--review-id",
                "RR-2026-001",
            ]
            self.assertEqual(main([*args, "-o", str(attestation)]), 0)
            self.assertEqual(main(["validate", "-i", str(attestation), "-t", "review-attestation"]), 0)
            self.assertEqual(main([*args, "-f", "markdown", "-o", str(markdown)]), 0)
            self.assertEqual(main([*args, "-f", "csv", "-o", str(csv)]), 0)
            self.assertEqual(main([*args, "--fail-on-warn", "-o", str(temp / "attestation-fail.json")]), 1)

            data = json.loads(attestation.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertEqual(data["metadata"]["review_id"], "RR-2026-001")
            self.assertIn("scope_status", {check["id"] for check in data["checks"]})
            self.assertIn("evidence_drift_status", {check["id"] for check in data["checks"]})
            self.assertIn("# OpenOps Review Attestation", markdown.read_text(encoding="utf-8"))
            self.assertIn("id,title,status,observed", csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
