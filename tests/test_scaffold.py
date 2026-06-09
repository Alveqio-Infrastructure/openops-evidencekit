import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.policy import Check
from openops_evidence.scaffold import create_evidence_scaffold
from openops_evidence.schema import validate_evidence


ROOT = Path(__file__).resolve().parents[1]


class ScaffoldTests(unittest.TestCase):
    def test_scaffold_evidence_creates_valid_placeholders_from_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            scaffold = temp / "evidence.scaffold.json"
            report = temp / "scaffold.report.json"

            self.assertEqual(
                main(
                    [
                        "scaffold",
                        "evidence",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--organization",
                        "Example Operations",
                        "--environment",
                        "production",
                        "-o",
                        str(scaffold),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(scaffold)]), 0)

            data = json.loads(scaffold.read_text(encoding="utf-8"))
            self.assertEqual(validate_evidence(data), [])
            self.assertEqual(data["metadata"]["organization"], "Example Operations")
            self.assertEqual(data["metadata"]["environment"], "production")
            self.assertEqual(data["metadata"]["policy_name"], "OpenOps baseline readiness policy")
            self.assertEqual(data["metadata"]["policy_check_count"], 12)
            self.assertEqual(set(data["signals"]), {"access", "backup", "dns", "docs", "mail", "monitoring", "tls"})
            self.assertIsNone(data["signals"]["backup"]["last_success_at"])
            self.assertIsNone(data["signals"]["backup"]["restore_test_at"])
            self.assertIsNone(data["signals"]["monitoring"]["targets"])
            self.assertEqual(data["signals"]["monitoring"]["alert_channels"], [])
            self.assertIsNone(data["signals"]["access"]["ssh_public_exposed"])
            self.assertIsNone(data["signals"]["access"]["mfa_required"])
            self.assertIsNone(data["signals"]["tls"]["certificates"][0]["not_after"])
            self.assertIsNone(data["signals"]["docs"]["inventory_updated_at"])
            self.assertIsNone(data["signals"]["docs"]["runbooks"][0]["name"])
            self.assertIsNone(data["signals"]["mail"]["domains"][0]["dmarc"])
            self.assertEqual(data["signals"]["dns"]["domains"][0]["nameservers"], [])
            self.assertEqual(data["signals"]["dns"]["domains"][0]["caa"], [])

            self.assertEqual(
                main(
                    [
                        "check",
                        "-i",
                        str(scaffold),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(report),
                    ]
                ),
                1,
            )
            report_data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(report_data["summary"]["status"], "fail")
            self.assertLess(report_data["summary"]["score"], 100)

    def test_scaffold_skips_missing_operator_paths(self):
        evidence = create_evidence_scaffold(
            [
                Check(
                    id="missing_required_docs",
                    title="No missing required docs",
                    path="signals.docs.missing_required[*]",
                    operator="missing",
                ),
                Check(
                    id="inventory_recent",
                    title="Inventory is recent",
                    path="signals.docs.inventory_updated_at",
                    operator="within_days",
                    value=14,
                ),
            ]
        )

        self.assertEqual(validate_evidence(evidence), [])
        self.assertNotIn("missing_required", evidence["signals"]["docs"])
        self.assertIsNone(evidence["signals"]["docs"]["inventory_updated_at"])


if __name__ == "__main__":
    unittest.main()
