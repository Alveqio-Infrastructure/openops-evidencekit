import json
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.policy import parse_policy
from openops_evidence.policypacks import (
    list_policy_packs,
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
                checks = parse_policy(raw)
                self.assertGreater(len(checks), 0)

    def test_render_policy_pack_list_as_json(self):
        payload = json.loads(render_policy_pack_list("json"))
        self.assertEqual(payload["packs"][0]["name"], "baseline")

    def test_cli_policy_show_writes_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "policy.toml"
            self.assertEqual(main(["policy", "show", "documentation", "-o", str(output)]), 0)
            raw = tomllib.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(raw["metadata"]["name"], "OpenOps documentation readiness policy")

    def test_cli_policy_list_writes_table(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["policy", "list"]), 0)
        self.assertIn("baseline", stdout.getvalue())
        self.assertIn("security-minimum", stdout.getvalue())

    def test_init_can_use_policy_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["init", temp_dir, "--policy-pack", "security-minimum"]), 0)
            policy_path = Path(temp_dir) / "policy.security-minimum.toml"
            evidence_path = Path(temp_dir) / "evidence.sample.json"
            self.assertTrue(policy_path.exists())
            self.assertTrue(evidence_path.exists())


if __name__ == "__main__":
    unittest.main()
