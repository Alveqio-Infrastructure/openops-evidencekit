import json
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.policy import parse_policy, validate_policy_document
from openops_evidence.policypacks import (
    get_policy_pack,
    list_policy_packs,
    parse_policy_pack_reference,
    read_policy_pack,
    render_policy_pack_list,
)


class PolicyPackTests(unittest.TestCase):
    def test_lists_bundled_policy_packs(self):
        packs = list_policy_packs()
        names = [pack["name"] for pack in packs]
        self.assertEqual(names, ["baseline", "documentation", "security-minimum"])

    def test_all_bundled_policy_packs_parse(self):
        for pack in list_policy_packs():
            with self.subTest(pack=pack["name"]):
                raw = tomllib.loads(read_policy_pack(pack["name"]))
                self.assertEqual(validate_policy_document(raw), [])
                checks = parse_policy(raw)
                self.assertGreater(len(checks), 0)

    def test_policy_pack_references_can_pin_versions(self):
        self.assertEqual(parse_policy_pack_reference("baseline"), ("baseline", None))
        self.assertEqual(parse_policy_pack_reference("baseline@0.1"), ("baseline", "0.1"))
        pack = get_policy_pack("baseline@0.1")
        raw = tomllib.loads(read_policy_pack("baseline@0.1"))
        self.assertEqual(pack["name"], "baseline")
        self.assertEqual(raw["metadata"]["version"], "0.1")

    def test_policy_pack_reference_rejects_unknown_version(self):
        with self.assertRaises(ValueError) as raised:
            read_policy_pack("baseline@9.9")
        self.assertIn("baseline@0.1", str(raised.exception))

    def test_render_policy_pack_list_as_json(self):
        payload = json.loads(render_policy_pack_list("json"))
        self.assertEqual(payload["packs"][0]["name"], "baseline")
        self.assertEqual(payload["packs"][0]["version"], "0.1")

    def test_cli_policy_show_writes_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "policy.toml"
            self.assertEqual(main(["policy", "show", "documentation@0.1", "-o", str(output)]), 0)
            raw = tomllib.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(raw["metadata"]["name"], "OpenOps documentation readiness policy")

    def test_cli_policy_list_writes_table(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["policy", "list"]), 0)
        self.assertIn("baseline", stdout.getvalue())
        self.assertIn("security-minimum", stdout.getvalue())

    def test_cli_policy_validate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "policy.toml"
            self.assertEqual(main(["policy", "show", "baseline", "-o", str(output)]), 0)
            with redirect_stdout(StringIO()) as stdout:
                self.assertEqual(main(["policy", "validate", str(output)]), 0)
        self.assertIn("valid", stdout.getvalue())

    def test_cli_policy_validate_reports_invalid_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "policy.toml"
            output.write_text("[[checks]]\nid = \"bad\"\noperator = \"unknown\"\n", encoding="utf-8")
            with redirect_stdout(StringIO()) as stdout:
                self.assertEqual(main(["policy", "validate", str(output)]), 1)
        self.assertIn("unsupported", stdout.getvalue())

    def test_init_can_use_policy_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["init", temp_dir, "--policy-pack", "security-minimum@0.1"]), 0)
            policy_path = Path(temp_dir) / "policy.security-minimum.toml"
            evidence_path = Path(temp_dir) / "evidence.sample.json"
            self.assertTrue(policy_path.exists())
            self.assertTrue(evidence_path.exists())


if __name__ == "__main__":
    unittest.main()
