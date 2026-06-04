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
            coverage = temp / "policy-coverage.json"
            risk_register = temp / "risk-register.json"
            gate = temp / "gate.json"
            badge = temp / "badge.json"
            brief = temp / "executive-brief.json"
            evidence_drift = temp / "evidence-drift.json"
            attestation = temp / "review-attestation.json"
            review_summary = temp / "review-summary.json"
            review_checklist = temp / "review-checklist.json"
            restore_report = temp / "restore-report.json"
            mail_report = temp / "mail-report.json"
            tls_report = temp / "tls-report.json"
            access_report = temp / "access-report.json"
            monitoring_report = temp / "monitoring-report.json"
            service_level_report = temp / "service-level-report.json"
            incident_report = temp / "incident-report.json"
            scorecard = temp / "scorecard.json"
            scope_report = temp / "scope-report.json"
            service_catalog = temp / "service-catalog.json"
            runbook_report = temp / "runbook-report.json"
            freshness_report = temp / "freshness-report.json"
            sarif = temp / "report.sarif.json"
            prometheus = temp / "report.prom"
            svg = temp / "history.svg"
            comparison = temp / "comparison.json"
            history = temp / "history.json"
            questionnaire = temp / "questionnaire.json"
            quality_report = temp / "quality-report.json"
            completeness_report = temp / "completeness-report.json"
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
            coverage.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "coverage_percent": 100,
                            "evidence_domains_total": 1,
                            "policy_domains_total": 1,
                            "domains_total": 1,
                            "covered_domains_count": 1,
                            "unreviewed_evidence_domains_count": 0,
                            "missing_evidence_domains_count": 0,
                            "checks_total": 1,
                        },
                        "domains": [
                            {
                                "domain": "backup",
                                "status": "covered",
                                "evidence_present": True,
                                "policy_present": True,
                                "check_count": 1,
                                "required_count": 1,
                                "optional_count": 0,
                                "check_ids": ["backup_recent"],
                                "paths": ["signals.backup.last_success_at"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            risk_register.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "action_required",
                            "risks_total": 1,
                            "open_count": 1,
                            "accepted_count": 0,
                            "closed_count": 0,
                            "expired_acceptance_count": 0,
                            "fail_count": 1,
                            "warn_count": 0,
                            "pass_count": 0,
                            "critical_count": 1,
                            "high_count": 0,
                            "medium_count": 0,
                            "low_count": 0,
                        },
                        "risks": [
                            {
                                "priority": "P0",
                                "id": "backup_recent",
                                "title": "Recent backup",
                                "risk_status": "open",
                                "source_status": "fail",
                                "severity": "critical",
                                "required": True,
                                "path": "signals.backup.last_success_at",
                                "operator": "within_days",
                                "observed_count": 0,
                                "owner": "",
                                "waiver_status": "none",
                                "waiver_expires_at": "",
                                "acceptance_reason": "",
                                "recommended_action": "Configure backups.",
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
            svg.write_text("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n", encoding="utf-8")
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
            evidence_drift.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "warn",
                            "base_assets": 1,
                            "current_assets": 1,
                            "asset_changes_count": 1,
                            "asset_added_count": 0,
                            "asset_removed_count": 0,
                            "asset_changed_count": 1,
                            "base_domains": 1,
                            "current_domains": 1,
                            "domain_changes_count": 0,
                            "domain_added_count": 0,
                            "domain_removed_count": 0,
                            "domain_changed_count": 0,
                        },
                        "asset_changes": [
                            {
                                "id": "web-01",
                                "change_type": "changed",
                                "before": {"id": "web-01", "tags": ["linux"]},
                                "after": {"id": "web-01", "tags": ["linux", "web"]},
                                "changed_fields": ["tags"],
                            }
                        ],
                        "domain_changes": [],
                    }
                ),
                encoding="utf-8",
            )
            attestation.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {
                            "approver": "Example Reviewer",
                            "role": "Operations",
                            "statement": "Reviewed generated artifacts.",
                            "review_id": "RR-2026-001",
                        },
                        "summary": {
                            "status": "pass",
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "artifact_count": 1,
                        },
                        "manifest": {
                            "path": "manifest.json",
                            "name": "openops-evidence-bundle",
                            "artifact_count": 1,
                            "size_bytes": 128,
                            "sha256": "a" * 64,
                        },
                        "checks": [
                            {
                                "id": "manifest_recorded",
                                "title": "Manifest hash is recorded",
                                "status": "pass",
                                "observed": "Manifest path, size, artifact count, and SHA-256 are recorded.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            review_summary.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "decision": {
                            "status": "pass",
                            "recommendation": "ready_for_handoff",
                            "reason": "No blocking review conditions were found.",
                        },
                        "metrics": {
                            "readiness_score": 100,
                            "report_status": "pass",
                            "gate_status": "pass",
                            "checks_failed": 0,
                            "checks_warn": 0,
                            "open_risks": 0,
                            "accepted_risks": 0,
                            "expired_acceptances": 0,
                            "stale_timestamps": 0,
                            "invalid_timestamps": 0,
                            "restore_failures": 0,
                            "restore_warnings": 0,
                            "mail_failures": 0,
                            "mail_warnings": 0,
                            "tls_failures": 0,
                            "tls_warnings": 0,
                            "access_failures": 0,
                            "access_warnings": 0,
                            "monitoring_failures": 0,
                            "monitoring_warnings": 0,
                            "incident_failures": 0,
                            "incident_warnings": 0,
                            "privacy_findings": 0,
                            "quality_failures": 0,
                            "quality_warnings": 0,
                            "completeness_missing": 0,
                            "completeness_optional_missing": 0,
                            "scope_warnings": 0,
                            "drift_changes": 0,
                            "catalog_warnings": 0,
                            "service_level_failures": 0,
                            "service_level_warnings": 0,
                            "runbook_warnings": 0,
                        },
                        "highlights": [],
                        "next_steps": ["Share the review pack."],
                    }
                ),
                encoding="utf-8",
            )
            restore_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "tool": "restic",
                            "repository_count": 1,
                            "last_success_at": "2026-06-01T01:00:00+00:00",
                            "last_success_age_days": 0,
                            "restore_tests_total": 1,
                            "successful_restore_tests": 1,
                            "failed_restore_tests": 0,
                            "stale_restore_tests": 0,
                            "unknown_restore_tests": 0,
                            "invalid_timestamp_count": 0,
                            "future_restore_tests": 0,
                            "latest_restore_test_at": "2026-05-18T13:30:00+00:00",
                            "latest_restore_test_age_days": 14,
                            "protected_hosts_count": 1,
                            "protected_paths_count": 0,
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                        },
                        "checks": [
                            {
                                "id": "restore_drill_recorded",
                                "title": "Restore drill evidence is recorded",
                                "status": "pass",
                                "severity": "critical",
                                "path": "signals.backup.restore_test_at",
                                "reason": "Restore drill evidence is present.",
                                "recommended_action": "Keep restore drill evidence current.",
                            }
                        ],
                        "restore_tests": [
                            {
                                "id": "restore_test_at",
                                "status": "current",
                                "outcome": "pass",
                                "target": "",
                                "tested_at": "2026-05-18T13:30:00+00:00",
                                "age_days": 14,
                                "max_age_days": 90,
                                "timestamp_valid": True,
                                "verifier": "",
                                "path": "signals.backup.restore_test_at",
                                "reason": "Restore drill is current and successful.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            mail_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "domains_total": 1,
                            "domains_passed": 1,
                            "domains_warn": 0,
                            "domains_failed": 0,
                            "spf_passed": 1,
                            "spf_missing": 0,
                            "dkim_passed": 1,
                            "dkim_missing": 0,
                            "dmarc_enforced": 1,
                            "dmarc_monitoring": 0,
                            "dmarc_missing": 0,
                            "dmarc_unknown": 0,
                        },
                        "domains": [
                            {
                                "domain": "example.invalid",
                                "status": "pass",
                                "spf": True,
                                "dkim": True,
                                "dmarc": "reject",
                                "dmarc_policy": "reject",
                                "dmarc_status": "enforced",
                                "reason": "SPF, DKIM, and enforced DMARC evidence are present.",
                                "recommended_action": "Keep mail authentication evidence current.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tls_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "certificates_total": 1,
                            "certificates_passed": 1,
                            "certificates_warn": 0,
                            "certificates_failed": 0,
                            "expired_count": 0,
                            "expiring_soon_count": 0,
                            "invalid_count": 0,
                            "unknown_count": 0,
                        },
                        "certificates": [
                            {
                                "hostname": "www.example.invalid",
                                "port": 443,
                                "status": "pass",
                                "certificate_status": "current",
                                "not_after": "2026-08-20T12:00:00+00:00",
                                "days_remaining": 78,
                                "issuer": "Example CA",
                                "reason": "TLS certificate expiry is outside the warning window.",
                                "recommended_action": "Keep certificate renewal automation and evidence current.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "ssh_public_exposed": False,
                            "mfa_required": True,
                            "entrypoints_total": 2,
                            "safe_entrypoints": 2,
                            "risky_entrypoints": 0,
                            "unknown_entrypoints": 0,
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                        },
                        "checks": [
                            {
                                "id": "public_ssh_closed",
                                "title": "Public SSH exposure is closed",
                                "status": "pass",
                                "severity": "critical",
                                "path": "signals.access.ssh_public_exposed",
                                "reason": "Public SSH exposure is recorded as closed.",
                                "recommended_action": "Keep public SSH behind controlled access.",
                            }
                        ],
                        "entrypoints": [
                            {
                                "name": "vpn",
                                "status": "safe",
                                "reason": "Entrypoint is a controlled administrative access layer.",
                            },
                            {
                                "name": "sso",
                                "status": "safe",
                                "reason": "Entrypoint is a controlled administrative access layer.",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            monitoring_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {
                            "evaluated_at": "2026-06-01T10:00:00+00:00",
                            "max_alert_test_age_days": 90,
                        },
                        "summary": {
                            "status": "pass",
                            "system": "prometheus",
                            "targets": 2,
                            "targets_total": 2,
                            "targets_up": 2,
                            "targets_down": 0,
                            "down_targets_count": 0,
                            "alert_channels_total": 1,
                            "last_alert_test_at": "2026-05-25T08:15:00+00:00",
                            "last_alert_test_age_days": 7,
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                        },
                        "checks": [
                            {
                                "id": "monitoring_targets_present",
                                "title": "Monitoring targets are recorded",
                                "status": "pass",
                                "severity": "critical",
                                "path": "signals.monitoring.targets",
                                "reason": "2 monitoring target(s) recorded.",
                                "recommended_action": "Keep monitoring evidence current.",
                            }
                        ],
                        "down_targets": [],
                    }
                ),
                encoding="utf-8",
            )
            service_level_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "services_total": 1,
                            "services_passed": 1,
                            "services_warn": 0,
                            "services_failed": 0,
                            "services_missing_evidence": 0,
                            "critical_services": 0,
                            "high_services": 1,
                        },
                        "services": [
                            {
                                "id": "public-web",
                                "name": "Public website",
                                "owner": "platform",
                                "criticality": "high",
                                "status": "pass",
                                "evidence_status": "present",
                                "target_percent": 99.5,
                                "observed_percent": 99.9,
                                "window": "30d",
                                "error_budget_remaining_percent": 80.0,
                                "reason": "Observed availability meets target.",
                                "recommended_action": "Keep service-level evidence current.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            incident_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "incident_runbooks_total": 1,
                            "services_total": 1,
                            "critical_services": 0,
                            "high_services": 1,
                            "services_missing_contacts": 0,
                            "high_impact_services_missing_contacts": 0,
                            "high_impact_services_missing_incident_runbooks": 0,
                            "alert_channels_total": 1,
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                        },
                        "checks": [
                            {
                                "id": "incident_runbook_present",
                                "title": "Incident response runbook is present",
                                "status": "pass",
                                "severity": "critical",
                                "path": "signals.docs.runbooks",
                                "reason": "1 incident runbook(s) found.",
                                "recommended_action": "Keep incident runbooks current.",
                            }
                        ],
                        "services": [
                            {
                                "id": "web",
                                "name": "Website",
                                "owner": "platform",
                                "criticality": "high",
                                "contacts_total": 1,
                                "contacts": ["platform@example.invalid"],
                                "incident_runbooks": ["incident-escalation"],
                                "status": "pass",
                                "reason": "Service has contacts and incident response runbook references.",
                            }
                        ],
                        "incident_runbooks": [
                            {
                                "name": "incident-escalation",
                                "path": "runbooks/incident.md",
                                "updated_at": "2026-05-20T00:00:00+00:00",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scorecard.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "source_score": 100,
                            "domains_total": 1,
                            "domains_passed": 1,
                            "domains_failed": 0,
                            "domains_warn": 0,
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_failed": 0,
                            "checks_warn": 0,
                        },
                        "domains": [
                            {
                                "domain": "backup",
                                "title": "Backup",
                                "status": "pass",
                                "score": 100,
                                "checks_total": 1,
                                "checks_passed": 1,
                                "checks_failed": 0,
                                "checks_warn": 0,
                                "critical_count": 0,
                                "high_count": 0,
                                "medium_count": 0,
                                "low_count": 0,
                                "checks": [
                                    {
                                        "id": "backup_recent",
                                        "title": "Recent backup",
                                        "status": "pass",
                                        "severity": "critical",
                                        "required": True,
                                        "path": "signals.backup.last_success_at",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scope_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "assets_declared": 1,
                            "evidence_assets": 1,
                            "in_scope_assets": 1,
                            "out_of_scope_assets": 0,
                            "missing_in_scope_assets": 0,
                            "unclassified_evidence_assets": 0,
                            "out_of_scope_evidence_assets": 0,
                            "domains_declared": 1,
                            "evidence_domains": 1,
                            "in_scope_domains": 1,
                            "out_of_scope_domains": 0,
                            "missing_required_domains": 0,
                            "unclassified_evidence_domains": 0,
                            "out_of_scope_evidence_domains": 0,
                        },
                        "assets": [
                            {
                                "id": "web-01",
                                "scope_status": "in_scope",
                                "status": "present_in_scope",
                                "present": True,
                                "declared": True,
                                "type": "host",
                                "hostname": "web-01.example.invalid",
                                "owner": "platform",
                                "reason": "Production web service.",
                            }
                        ],
                        "domains": [
                            {
                                "name": "backup",
                                "scope_status": "in_scope",
                                "status": "present_in_scope",
                                "present": True,
                                "declared": True,
                                "required": True,
                                "kind": "object",
                                "item_count": 1,
                                "fields": ["last_success_at"],
                                "owner": "backup",
                                "reason": "Backup evidence is required.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            service_catalog.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "services_total": 1,
                            "services_passed": 1,
                            "services_warn": 0,
                            "critical_services": 0,
                            "high_services": 1,
                            "catalog_assets_total": 1,
                            "evidence_assets_total": 1,
                            "missing_catalog_assets_count": 0,
                            "unassigned_evidence_assets_count": 0,
                            "missing_domains_count": 0,
                            "missing_runbooks_count": 0,
                        },
                        "services": [
                            {
                                "id": "public-web",
                                "name": "Public website",
                                "owner": "platform",
                                "criticality": "high",
                                "status": "pass",
                                "contacts": ["platform@example.invalid"],
                                "assets": ["web-01"],
                                "present_assets": ["web-01"],
                                "missing_assets": [],
                                "domains": ["backup"],
                                "present_domains": ["backup"],
                                "missing_domains": [],
                                "runbooks": [],
                                "present_runbooks": [],
                                "missing_runbooks": [],
                            }
                        ],
                        "unassigned_assets": [],
                    }
                ),
                encoding="utf-8",
            )
            runbook_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "runbooks_total": 1,
                            "observed_runbooks": 1,
                            "expected_runbooks": 1,
                            "missing_runbooks_count": 0,
                            "stale_runbooks_count": 0,
                            "unreferenced_runbooks_count": 0,
                            "invalid_timestamp_count": 0,
                            "services_total": 1,
                            "services_with_missing_runbooks": 0,
                        },
                        "runbooks": [
                            {
                                "name": "backup-restore",
                                "status": "current",
                                "path": "runbooks/backup-restore.md",
                                "updated_at": "2026-06-01T10:00:00+00:00",
                                "age_days": 0,
                                "timestamp_valid": True,
                                "expected": True,
                                "observed": True,
                                "referenced_by": ["public-web"],
                                "reason": "Runbook is present.",
                            }
                        ],
                        "services": [
                            {
                                "id": "public-web",
                                "name": "Public website",
                                "owner": "platform",
                                "status": "pass",
                                "runbooks": ["backup-restore"],
                                "present_runbooks": ["backup-restore"],
                                "missing_runbooks": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            freshness_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "timestamps_total": 1,
                            "current_count": 1,
                            "stale_count": 0,
                            "future_count": 0,
                            "invalid_count": 0,
                            "oldest_age_days": 0,
                            "newest_age_days": 0,
                        },
                        "timestamps": [
                            {
                                "path": "generated_at",
                                "status": "current",
                                "value": "2026-06-01T10:00:00+00:00",
                                "age_days": 0,
                                "future_days": None,
                                "max_age_days": 30,
                                "timestamp_valid": True,
                                "reason": "Timestamp is current.",
                            }
                        ],
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
            questionnaire.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "questions_total": 1,
                            "domain_count": 1,
                            "required_count": 1,
                            "optional_count": 0,
                            "critical_count": 1,
                            "high_count": 0,
                            "medium_count": 0,
                            "low_count": 0,
                        },
                        "questions": [
                            {
                                "id": "backup_recent",
                                "domain": "backup",
                                "title": "Recent backup",
                                "required": True,
                                "severity": "critical",
                                "path": "signals.backup.last_success_at",
                                "operator": "within_days",
                                "request": "Provide a recent backup timestamp.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            quality_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "checks_total": 1,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                            "assets_total": 1,
                            "signals_total": 1,
                        },
                        "checks": [
                            {
                                "id": "signals_present",
                                "title": "Evidence contains signal domains",
                                "status": "pass",
                                "severity": "critical",
                                "path": "signals",
                                "reason": "1 signal domain(s) recorded.",
                                "recommended_action": "Keep evidence current.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            completeness_report.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "checks_total": 1,
                            "checks_present": 1,
                            "checks_expected_absent": 0,
                            "checks_missing": 0,
                            "required_missing": 0,
                            "optional_missing": 0,
                            "checks_passed": 1,
                            "checks_warn": 0,
                            "checks_failed": 0,
                        },
                        "items": [
                            {
                                "id": "backup_recent",
                                "title": "Recent backup",
                                "status": "pass",
                                "evidence_status": "present",
                                "required": True,
                                "severity": "critical",
                                "path": "signals.backup.last_success_at",
                                "operator": "exists",
                                "observed_count": 1,
                                "request": "Evidence is present for this policy path.",
                                "remediation": "Keep backup evidence current.",
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
            review_checklist.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "summary": {
                            "status": "pass",
                            "items_total": 1,
                            "required_items": 1,
                            "pass_count": 1,
                            "warn_count": 0,
                            "fail_count": 0,
                        },
                        "items": [
                            {
                                "id": "read_review_summary",
                                "title": "Read the review summary",
                                "status": "pass",
                                "required": True,
                                "artifact": "review-summary.md",
                                "reason": "Start with the generated one-page decision summary.",
                            }
                        ],
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
            self.assertEqual(classify_artifact(coverage), "policy-coverage")
            self.assertEqual(classify_artifact(risk_register), "risk-register")
            self.assertEqual(classify_artifact(gate), "gate-result")
            self.assertEqual(classify_artifact(badge), "badge")
            self.assertEqual(classify_artifact(brief), "executive-brief")
            self.assertEqual(classify_artifact(evidence_drift), "evidence-drift")
            self.assertEqual(classify_artifact(attestation), "review-attestation")
            self.assertEqual(classify_artifact(review_summary), "review-summary")
            self.assertEqual(classify_artifact(review_checklist), "review-checklist")
            self.assertEqual(classify_artifact(restore_report), "restore-report")
            self.assertEqual(classify_artifact(mail_report), "mail-report")
            self.assertEqual(classify_artifact(tls_report), "tls-report")
            self.assertEqual(classify_artifact(access_report), "access-report")
            self.assertEqual(classify_artifact(monitoring_report), "monitoring-report")
            self.assertEqual(classify_artifact(service_level_report), "service-level-report")
            self.assertEqual(classify_artifact(incident_report), "incident-report")
            self.assertEqual(classify_artifact(scorecard), "scorecard")
            self.assertEqual(classify_artifact(scope_report), "scope-report")
            self.assertEqual(classify_artifact(service_catalog), "service-catalog")
            self.assertEqual(classify_artifact(runbook_report), "runbook-report")
            self.assertEqual(classify_artifact(freshness_report), "freshness-report")
            self.assertEqual(classify_artifact(sarif), "report-sarif")
            self.assertEqual(classify_artifact(prometheus), "report-prometheus")
            self.assertEqual(classify_artifact(svg), "visual")
            self.assertEqual(classify_artifact(comparison), "report-comparison")
            self.assertEqual(classify_artifact(history), "report-history")
            self.assertEqual(classify_artifact(questionnaire), "questionnaire")
            self.assertEqual(classify_artifact(quality_report), "quality-report")
            self.assertEqual(classify_artifact(completeness_report), "completeness-report")
            self.assertEqual(classify_artifact(signature), "bundle-signature")
            self.assertEqual(classify_artifact(policy), "policy")
            self.assertEqual(classify_artifact(waivers), "waivers")


if __name__ == "__main__":
    unittest.main()
