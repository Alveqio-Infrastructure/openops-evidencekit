import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.inventory import create_evidence_inventory, render_inventory_csv, render_inventory_markdown
from openops_evidence.schema import validate_inventory


def _evidence():
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {
            "source": "test",
            "organization": "Example Team",
            "environment": "production",
        },
        "assets": [
            {
                "id": "web-01",
                "type": "host",
                "hostname": "web-01.example.invalid",
                "roles": ["web"],
                "tags": ["linux", "public"],
            },
            {
                "id": "backup-repo-01",
                "type": "backup-repository",
                "roles": ["backup"],
                "tags": ["restic"],
            },
        ],
        "signals": {
            "backup": {
                "tool": "restic",
                "repository_count": 1,
            },
            "monitoring": {
                "targets": 12,
            },
        },
    }


class InventoryTests(unittest.TestCase):
    def test_create_evidence_inventory_summarizes_assets_and_signal_domains(self):
        inventory = create_evidence_inventory(_evidence())

        self.assertEqual(validate_inventory(inventory), [])
        self.assertEqual(inventory["summary"]["assets_total"], 2)
        self.assertEqual(inventory["summary"]["asset_type_count"], 2)
        self.assertEqual(inventory["summary"]["signal_domain_count"], 2)
        self.assertEqual(inventory["assets"][0]["id"], "web-01")
        self.assertEqual(inventory["signal_domains"][0]["name"], "backup")
        self.assertEqual(inventory["signal_domains"][0]["fields"], ["repository_count", "tool"])

    def test_render_inventory_markdown_and_csv(self):
        inventory = create_evidence_inventory(_evidence())

        markdown = render_inventory_markdown(inventory)
        csv_output = render_inventory_csv(inventory)

        self.assertIn("# OpenOps Evidence Inventory", markdown)
        self.assertIn("web", markdown)
        self.assertIn("record_type,id,type,hostname,roles,tags,signal_kind,item_count,fields", csv_output)
        self.assertIn("asset,web-01,host,web-01.example.invalid,web,\"linux, public\"", csv_output)
        self.assertIn("signal,backup", csv_output)

    def test_cli_inventory_evidence_writes_json_and_validates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence_path = temp / "evidence.json"
            inventory_path = temp / "inventory.json"
            evidence_path.write_text(json.dumps(_evidence()), encoding="utf-8")

            self.assertEqual(
                main(["inventory", "evidence", "-i", str(evidence_path), "-f", "json", "-o", str(inventory_path)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(inventory_path), "-t", "inventory"]), 0)

            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            self.assertEqual(inventory["summary"]["assets_total"], 2)


if __name__ == "__main__":
    unittest.main()
