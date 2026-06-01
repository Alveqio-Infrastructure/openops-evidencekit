import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from openops_evidence.bundle import (
    classify_artifact,
    create_bundle_archive,
    create_bundle_manifest,
    create_bundle_signature,
    verify_bundle_manifest,
    verify_bundle_signature,
)
from openops_evidence.schema import (
    validate_bundle_manifest,
    validate_bundle_signature,
    validate_bundle_verification,
)


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

    def test_verify_bundle_manifest_detects_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "report.md"
            artifact.write_text("# Report\n", encoding="utf-8", newline="\n")
            manifest = create_bundle_manifest([str(artifact)], base_dir=str(temp))
            artifact.write_text("# Changed\n", encoding="utf-8", newline="\n")

            verification = verify_bundle_manifest(manifest, base_dir=str(temp))

        self.assertEqual(validate_bundle_verification(verification), [])
        self.assertEqual(verification["summary"]["status"], "fail")
        self.assertEqual(verification["summary"]["mismatched_count"], 1)
        self.assertEqual(verification["results"][0]["status"], "mismatch")

    def test_verify_bundle_manifest_rejects_path_traversal(self):
        manifest = {
            "metadata": {"name": "bad"},
            "artifacts": [
                {
                    "path": "../outside.txt",
                    "role": "artifact",
                    "size_bytes": 1,
                    "sha256": "a" * 64,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            verification = verify_bundle_manifest(manifest, base_dir=temp_dir)
        self.assertEqual(verification["results"][0]["status"], "missing")

    def test_create_bundle_archive_from_verified_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "report.md"
            artifact.write_text("# Report\n", encoding="utf-8", newline="\n")
            manifest_path = temp / "manifest.json"
            manifest = create_bundle_manifest([str(artifact)], base_dir=str(temp))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            archive_path = temp / "bundle.zip"

            summary = create_bundle_archive(
                manifest,
                str(manifest_path),
                str(archive_path),
                base_dir=str(temp),
            )

            self.assertTrue(archive_path.is_file())
            self.assertEqual(summary["metadata"]["file_count"], 2)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(sorted(archive.namelist()), ["manifest.json", "report.md"])
                self.assertEqual(archive.read("report.md"), b"# Report\n")

    def test_create_bundle_archive_rejects_missing_artifact(self):
        manifest = {
            "artifacts": [
                {
                    "path": "missing.md",
                    "role": "report-markdown",
                    "size_bytes": 1,
                    "sha256": "a" * 64,
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            manifest_path = temp / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                create_bundle_archive(manifest, str(manifest_path), str(temp / "bundle.zip"), base_dir=str(temp))

    def test_create_and_verify_bundle_signature(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "report.md"
            artifact.write_text("# Report\n", encoding="utf-8", newline="\n")
            manifest_path = temp / "manifest.json"
            manifest_path.write_text(
                json.dumps(create_bundle_manifest([str(artifact)], base_dir=str(temp))),
                encoding="utf-8",
            )

            signature = create_bundle_signature(str(manifest_path), b"shared-secret", key_id="ops-2026")
            verification = verify_bundle_signature(str(manifest_path), signature, b"shared-secret")

        self.assertEqual(validate_bundle_signature(signature), [])
        self.assertEqual(signature["metadata"]["key_id"], "ops-2026")
        self.assertEqual(signature["signature"]["algorithm"], "hmac-sha256")
        self.assertEqual(verification["summary"]["status"], "pass")
        self.assertEqual(verification["results"][0]["status"], "verified")
        self.assertEqual(verification["results"][1]["status"], "verified")

    def test_bundle_signature_detects_changed_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            manifest_path = temp / "manifest.json"
            manifest_path.write_text('{"schema_version":"0.1"}\n', encoding="utf-8")
            signature = create_bundle_signature(str(manifest_path), b"shared-secret")
            manifest_path.write_text('{"schema_version":"0.1","changed":true}\n', encoding="utf-8")

            verification = verify_bundle_signature(str(manifest_path), signature, b"shared-secret")

        self.assertEqual(verification["summary"]["status"], "fail")
        self.assertFalse(verification["summary"]["manifest_hash_match"])
        self.assertFalse(verification["summary"]["signature_match"])

    def test_bundle_signature_detects_wrong_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            manifest_path = temp / "manifest.json"
            manifest_path.write_text('{"schema_version":"0.1"}\n', encoding="utf-8")
            signature = create_bundle_signature(str(manifest_path), b"shared-secret")

            verification = verify_bundle_signature(str(manifest_path), signature, b"wrong-secret")

        self.assertEqual(verification["summary"]["status"], "fail")
        self.assertTrue(verification["summary"]["manifest_hash_match"])
        self.assertFalse(verification["summary"]["signature_match"])

    def test_classifies_reports_and_policies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            report = temp / "report.json"
            inventory = temp / "inventory.json"
            gate = temp / "gate.json"
            badge = temp / "badge.json"
            brief = temp / "executive-brief.json"
            sarif = temp / "report.sarif.json"
            prometheus = temp / "report.prom"
            comparison = temp / "comparison.json"
            history = temp / "history.json"
            signature = temp / "signature.json"
            report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-31T10:00:00+00:00",
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
            inventory.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "assets_total": 1,
                            "asset_type_count": 1,
                            "hostnames_total": 1,
                            "role_count": 1,
                            "tag_count": 1,
                            "signal_domain_count": 1,
                        },
                        "assets": [
                            {
                                "id": "web-01",
                                "type": "host",
                                "hostname": "web-01.example.invalid",
                                "roles": ["web"],
                                "tags": ["linux"],
                            }
                        ],
                        "signal_domains": [
                            {
                                "name": "backup",
                                "kind": "object",
                                "item_count": 1,
                                "fields": ["tool"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            sarif.write_text(
                json.dumps({"version": "2.1.0", "runs": []}),
                encoding="utf-8",
            )
            prometheus.write_text(
                "openops_readiness_score 100\n",
                encoding="utf-8",
            )
            gate.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "conditions_total": 0,
                            "conditions_failed": 0,
                            "source_score": 100,
                            "source_failed": 0,
                            "source_warnings": 0,
                        },
                        "conditions": [],
                    }
                ),
                encoding="utf-8",
            )
            badge.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "label": "openops",
                        "message": "pass 100",
                        "color": "brightgreen",
                    }
                ),
                encoding="utf-8",
            )
            brief.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "score": 100,
                            "health": "on_track",
                            "message": "Readiness is on track.",
                            "checks_total": 10,
                            "checks_passed": 10,
                            "checks_failed": 0,
                            "checks_warn": 0,
                            "top_findings_count": 0,
                            "critical_count": 0,
                            "high_count": 0,
                            "medium_count": 0,
                            "low_count": 0,
                        },
                        "top_findings": [],
                        "next_steps": ["Keep reviewing evidence."],
                    }
                ),
                encoding="utf-8",
            )
            comparison.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-31T10:00:00+00:00",
                        "summary": {},
                        "regressions": [],
                        "improvements": [],
                        "neutral_changes": [],
                        "added": [],
                        "removed": [],
                    }
                ),
                encoding="utf-8",
            )
            history.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "entries_total": 1,
                            "latest_status": "pass",
                            "latest_score": 100,
                            "previous_score": 100,
                            "score_change": 0,
                            "best_score": 100,
                            "worst_score": 100,
                            "latest_failed": 0,
                            "latest_warnings": 0,
                            "failed_delta": 0,
                            "warnings_delta": 0,
                        },
                        "entries": [
                            {
                                "recorded_at": "2026-06-01T10:00:00+00:00",
                                "report_generated_at": "2026-06-01T09:00:00+00:00",
                                "source": "ci",
                                "note": "",
                                "status": "pass",
                                "score": 100,
                                "checks_total": 10,
                                "checks_passed": 10,
                                "checks_failed": 0,
                                "checks_warn": 0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            signature.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-31T10:00:00+00:00",
                        "metadata": {},
                        "manifest": {
                            "path": "manifest.json",
                            "size_bytes": 128,
                            "sha256": "a" * 64,
                        },
                        "signature": {
                            "algorithm": "hmac-sha256",
                            "value": "b" * 64,
                        },
                    }
                ),
                encoding="utf-8",
            )
            policy = temp / "policy.toml"
            policy.write_text("[[checks]]\nid = \"x\"\n", encoding="utf-8")
            waivers = temp / "waivers.toml"
            waivers.write_text(
                "\n".join(
                    [
                        "[[waivers]]",
                        'check_id = "mail_dmarc_policy"',
                        'owner = "ops@example.invalid"',
                        'reason = "Synthetic accepted risk."',
                        'expires_at = "2099-12-31T00:00:00+00:00"',
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(classify_artifact(report), "report")
            self.assertEqual(classify_artifact(inventory), "inventory")
            self.assertEqual(classify_artifact(gate), "gate-result")
            self.assertEqual(classify_artifact(badge), "badge")
            self.assertEqual(classify_artifact(brief), "executive-brief")
            self.assertEqual(classify_artifact(sarif), "report-sarif")
            self.assertEqual(classify_artifact(prometheus), "report-prometheus")
            self.assertEqual(classify_artifact(comparison), "report-comparison")
            self.assertEqual(classify_artifact(history), "report-history")
            self.assertEqual(classify_artifact(signature), "bundle-signature")
            self.assertEqual(classify_artifact(policy), "policy")
            self.assertEqual(classify_artifact(waivers), "waivers")


if __name__ == "__main__":
    unittest.main()
