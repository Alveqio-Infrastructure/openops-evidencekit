import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from openops_evidence.cli import main


class CliExitCodeTests(unittest.TestCase):
    def test_version_exits_successfully(self):
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)

    def test_validate_returns_one_for_invalid_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text(json.dumps({"schema_version": "0.1"}), encoding="utf-8")
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["validate", "-i", str(path)]), 1)

    def test_user_facing_error_returns_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{", encoding="utf-8")
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["validate", "-i", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
