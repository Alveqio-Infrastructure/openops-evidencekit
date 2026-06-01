import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.evidence_diff import (
    compare_evidence,
    render_evidence_diff_csv,
    render_evidence_diff_markdown,
)
from openops_evidence.schema import validate_evidence_drift


ROOT = Path(__file__).resolve().parents[1]


class EvidenceDiffTests(unittest.TestCase):
    def test_compare_evidence_detects_asset_and_domain_drift(self):
        base = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "metadata": {"source": "base", "environment": "prod"},
            "assets": [
                {"id": "web-01", "type": "host", "hostname": "web-01", "roles": ["web"], "tags": ["linux"]},
                {"id": "old-01", "type": "host", "hostname": "old-01", "roles": ["worker"], "tags": ["retired"]},
            ],
            "signals": {
                "backup": {"last_success_at": "2026-06-01T09:00:00+00:00"},
                "monitoring": {"targets": 2},
            },
        }
        current = {
            "schema_version": "0.1",
            "generated_at": "2026-06-02T10:00:00+00:00",
            "metadata": {"source": "current", "environment": "prod"},
            "assets": [
                {
                    "id": "web-01",
                    "type": "host",
                    "hostname": "web-01",
                    "roles": ["web"],
                    "tags": ["customer-facing", "linux"],
                },
                {"id": "new-01", "type": "host", "hostname": "new-01", "roles": ["worker"], "tags": ["linux"]},
            ],
            "signals": {
                "backup": {"last_success_at": "2026-06-02T09:00:00+00:00", "repository_count": 1},
                "access": {"mfa_required": True},
            },
        }

        diff = compare_evidence(base, current)

        self.assertEqual(validate_evidence_drift(diff), [])
        self.assertEqual(diff["summary"]["status"], "warn")
        self.assertEqual(diff["summary"]["asset_added_count"], 1)
        self.assertEqual(diff["summary"]["asset_removed_count"], 1)
        self.assertEqual(diff["summary"]["asset_changed_count"], 1)
        self.assertEqual(diff["summary"]["domain_added_count"], 1)
        self.assertEqual(diff["summary"]["domain_removed_count"], 1)
        self.assertEqual(diff["summary"]["domain_changed_count"], 1)
        asset_changes = {item["id"]: item for item in diff["asset_changes"]}
        domain_changes = {item["name"]: item for item in diff["domain_changes"]}
        self.assertEqual(asset_changes["web-01"]["changed_fields"], ["tags", "value"])
        self.assertIn("fields", domain_changes["backup"]["changed_fields"])
        self.assertIn("value", domain_changes["backup"]["changed_fields"])

    def test_render_evidence_diff_outputs_markdown_and_csv(self):
        diff = compare_evidence(
            json.loads((ROOT / "examples" / "evidence.previous.json").read_text(encoding="utf-8")),
            json.loads((ROOT / "examples" / "evidence.sample.json").read_text(encoding="utf-8")),
        )

        markdown = render_evidence_diff_markdown(diff)
        csv = render_evidence_diff_csv(diff)

        self.assertIn("# OpenOps Evidence Drift", markdown)
        self.assertIn("## Asset Changes", markdown)
        self.assertIn("Signal domain fingerprints", markdown)
        self.assertIn("record_type,id,change_type", csv)

    def test_cli_evidence_diff_all_formats_and_fail_on_drift(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            drift = temp / "evidence-drift.json"
            markdown = temp / "evidence-drift.md"
            csv = temp / "evidence-drift.csv"

            self.assertEqual(
                main(
                    [
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-o",
                        str(drift),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(drift), "-t", "evidence-drift"]), 0)
            self.assertEqual(
                main(
                    [
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-f",
                        "markdown",
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(ROOT / "examples" / "evidence.sample.json"),
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
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--fail-on-drift",
                        "-o",
                        str(temp / "drift-fail.json"),
                    ]
                ),
                1,
            )

            data = json.loads(drift.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["status"], "warn")
            self.assertIn("# OpenOps Evidence Drift", markdown.read_text(encoding="utf-8"))
            self.assertIn("record_type,id,change_type", csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
