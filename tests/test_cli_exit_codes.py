import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


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

    def test_python_module_entrypoint_propagates_exit_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text(json.dumps({"schema_version": "0.1"}), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            result = subprocess.run(
                [sys.executable, "-m", "openops_evidence", "validate", "-i", str(path)],
                cwd=str(ROOT),
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)

    def test_user_facing_error_returns_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{", encoding="utf-8")
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["validate", "-i", str(path)]), 2)

    def test_check_returns_two_for_invalid_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            policy = temp / "policy.toml"
            report = temp / "report.json"
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
            policy.write_text("[[checks]]\nid = \"bad\"\noperator = \"unknown\"\n", encoding="utf-8")
            with redirect_stderr(StringIO()):
                self.assertEqual(
                    main(["check", "-i", str(evidence), "-p", str(policy), "-o", str(report)]),
                    2,
                )

    def test_gate_returns_two_for_invalid_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "summary": {
                            "score": 100,
                            "status": "pass",
                            "checks_total": 0,
                            "checks_passed": 0,
                            "checks_failed": 0,
                            "checks_warn": 0,
                        },
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["gate", "report", "-i", str(report), "--min-score", "101"]), 2)

    def test_verify_signature_fail_on_invalid_returns_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            manifest = temp / "manifest.json"
            signature = temp / "signature.json"
            key = temp / "key.txt"
            wrong_key = temp / "wrong-key.txt"
            verification = temp / "signature-verification.json"
            manifest.write_text('{"schema_version":"0.1"}\n', encoding="utf-8")
            key.write_text("right-key", encoding="utf-8")
            wrong_key.write_text("wrong-key", encoding="utf-8")
            self.assertEqual(
                main(["bundle", "sign", str(manifest), "--key-file", str(key), "-o", str(signature)]),
                0,
            )
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    main(
                        [
                            "bundle",
                            "verify-signature",
                            str(manifest),
                            str(signature),
                            "--key-file",
                            str(wrong_key),
                            "--fail-on-invalid",
                            "-o",
                            str(verification),
                        ]
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
