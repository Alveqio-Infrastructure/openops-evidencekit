import unittest

from openops_evidence.schema import (
    validate_action_plan,
    validate_badge,
    validate_bundle_manifest,
    validate_bundle_signature,
    validate_bundle_verification,
    validate_evidence,
    validate_evidence_drift,
    validate_executive_brief,
    validate_freshness_report,
    validate_gate_result,
    validate_inventory,
    validate_policy_coverage,
    validate_policy_matrix,
    validate_privacy_scan,
    validate_questionnaire,
    validate_report,
    validate_report_comparison,
    validate_report_history,
    validate_review_attestation,
    validate_review_summary,
    validate_restore_report,
    validate_risk_register,
    validate_runbook_report,
    validate_scorecard,
    validate_service_catalog_report,
    validate_scope_report,
)


class SchemaTests(unittest.TestCase):
    def test_valid_minimal_evidence(self):
        errors = validate_evidence(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertEqual(errors, [])

    def test_missing_evidence_fields_are_reported(self):
        errors = validate_evidence({})
        self.assertIn("schema_version must be a non-empty string.", errors)
        self.assertIn("signals must be an object.", errors)

    def test_patch_level_schema_versions_are_compatible(self):
        errors = validate_evidence(
            {
                "schema_version": "0.1.7",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertEqual(errors, [])

    def test_unknown_schema_versions_are_rejected(self):
        errors = validate_evidence(
            {
                "schema_version": "0.2",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertIn("schema_version '0.2' is not supported; expected 0.1 or 0.1.x.", errors)

    def test_malformed_schema_versions_are_rejected(self):
        errors = validate_report(
            {
                "schema_version": "0.1-beta",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {},
                "results": [],
            }
        )
        self.assertIn("schema_version must be 0.1 or 0.1.x.", errors)

    def test_valid_report(self):
        errors = validate_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "score": 100,
                    "status": "pass",
                    "checks_total": 1,
                    "checks_passed": 1,
                    "checks_failed": 0,
                    "checks_warn": 0,
                },
                "results": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "pass",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_report_contract_is_reported(self):
        errors = validate_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "score": 101,
                    "status": "unknown",
                    "checks_total": -1,
                    "checks_passed": 0,
                    "checks_failed": 0,
                    "checks_warn": "none",
                },
                "results": [
                    {
                        "id": "",
                        "title": "Bad",
                        "status": "unknown",
                        "severity": "urgent",
                        "required": "yes",
                        "path": 123,
                        "operator": None,
                    }
                ],
            }
        )
        self.assertIn("summary.score must be at most 100.", errors)
        self.assertIn("summary.status must be one of: fail, pass.", errors)
        self.assertIn("summary.checks_total must be at least 0.", errors)
        self.assertIn("summary.checks_warn must be an integer.", errors)
        self.assertIn("results[0].id must be a non-empty string.", errors)
        self.assertIn("results[0].status must be one of: fail, pass, warn.", errors)
        self.assertIn("results[0].severity must be one of: critical, high, low, medium.", errors)
        self.assertIn("results[0].required must be a boolean.", errors)
        self.assertIn("results[0].path must be a string.", errors)
        self.assertIn("results[0].operator must be a string.", errors)

    def test_valid_action_plan(self):
        errors = validate_action_plan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "action_required",
                    "items_total": 1,
                    "action_required_count": 1,
                    "waived_count": 0,
                    "expired_waiver_count": 0,
                    "fail_count": 1,
                    "warn_count": 0,
                    "pass_count": 0,
                    "critical_count": 1,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "items": [
                    {
                        "priority": "P0",
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "observed_count": 0,
                        "waived": False,
                        "waiver": {},
                        "recommended_action": "Configure backups.",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_executive_brief(self):
        errors = validate_executive_brief(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "fail",
                    "score": 70,
                    "health": "action_required",
                    "message": "Readiness needs attention.",
                    "checks_total": 1,
                    "checks_passed": 0,
                    "checks_failed": 1,
                    "checks_warn": 0,
                    "top_findings_count": 1,
                    "critical_count": 1,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "top_findings": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "remediation": "Fix backups.",
                    }
                ],
                "next_steps": ["Fix backups."],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_executive_brief_is_reported(self):
        errors = validate_executive_brief(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "unknown",
                    "score": 101,
                    "health": "great",
                    "message": "",
                    "checks_total": -1,
                    "checks_passed": 0,
                    "checks_failed": 0,
                    "checks_warn": 0,
                    "top_findings_count": 1,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "top_findings": [
                    {
                        "id": "",
                        "title": "",
                        "status": "pass",
                        "severity": "urgent",
                        "required": "yes",
                        "path": 123,
                        "remediation": "",
                    }
                ],
                "next_steps": [""],
            }
        )
        self.assertIn("summary.status must be one of: fail, pass.", errors)
        self.assertIn("summary.health must be one of: action_required, on_track, watch.", errors)
        self.assertIn("summary.score must be at most 100.", errors)
        self.assertIn("summary.message must be a non-empty string.", errors)
        self.assertIn("summary.checks_total must be at least 0.", errors)
        self.assertIn("top_findings[0].id must be a non-empty string.", errors)
        self.assertIn("top_findings[0].status must be one of: fail, warn.", errors)
        self.assertIn("top_findings[0].required must be a boolean.", errors)
        self.assertIn("next_steps[0] must be a non-empty string.", errors)

    def test_invalid_action_plan_is_reported(self):
        errors = validate_action_plan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "unknown",
                    "items_total": -1,
                    "action_required_count": -1,
                    "waived_count": -1,
                    "expired_waiver_count": -1,
                    "fail_count": 0,
                    "warn_count": 0,
                    "pass_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "items": [
                    {
                        "priority": "P9",
                        "id": "",
                        "title": "Bad",
                        "status": "unknown",
                        "severity": "urgent",
                        "required": "yes",
                        "path": 123,
                        "operator": None,
                        "observed_count": -1,
                        "waived": "no",
                        "recommended_action": "",
                    }
                ],
            }
        )
        self.assertIn("summary.status must be one of: action_required, pass.", errors)
        self.assertIn("summary.items_total must be at least 0.", errors)
        self.assertIn("summary.action_required_count must be at least 0.", errors)
        self.assertIn("summary.waived_count must be at least 0.", errors)
        self.assertIn("summary.expired_waiver_count must be at least 0.", errors)
        self.assertIn("items[0].priority must be one of: P0, P1, P2, P3.", errors)
        self.assertIn("items[0].id must be a non-empty string.", errors)
        self.assertIn("items[0].required must be a boolean.", errors)
        self.assertIn("items[0].waived must be a boolean when present.", errors)
        self.assertIn("items[0].observed_count must be at least 0.", errors)

    def test_valid_policy_matrix(self):
        errors = validate_policy_matrix(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "check_count": 1,
                    "required_count": 1,
                    "optional_count": 0,
                    "path_count": 1,
                    "critical_count": 1,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "checks": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "value": 2,
                        "severity": "critical",
                        "mode": "any",
                        "required": True,
                        "remediation": "Configure backups.",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_policy_coverage(self):
        errors = validate_policy_coverage(
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
        )
        self.assertEqual(errors, [])

    def test_valid_questionnaire(self):
        errors = validate_questionnaire(
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
                        "expected": 2,
                        "request": "Provide a recent backup timestamp.",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_policy_matrix_is_reported(self):
        errors = validate_policy_matrix(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "check_count": -1,
                    "required_count": 0,
                    "optional_count": 0,
                    "path_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "checks": [
                    {
                        "id": "",
                        "title": "Bad",
                        "path": 123,
                        "operator": None,
                        "value": None,
                        "severity": "urgent",
                        "mode": "sometimes",
                        "required": "yes",
                        "remediation": None,
                    }
                ],
            }
        )
        self.assertIn("summary.check_count must be at least 0.", errors)
        self.assertIn("checks[0].id must be a non-empty string.", errors)
        self.assertIn("checks[0].path must be a string.", errors)
        self.assertIn("checks[0].operator must be a string.", errors)
        self.assertIn("checks[0].severity must be one of: critical, high, low, medium.", errors)
        self.assertIn("checks[0].mode must be one of: all, any, none.", errors)
        self.assertIn("checks[0].required must be a boolean.", errors)
        self.assertIn("checks[0].remediation must be a string.", errors)

    def test_valid_inventory(self):
        errors = validate_inventory(
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
                        "item_count": 2,
                        "fields": ["tool", "last_success_at"],
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_evidence_drift(self):
        errors = validate_evidence_drift(
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
                    "domain_changes_count": 1,
                    "domain_added_count": 0,
                    "domain_removed_count": 0,
                    "domain_changed_count": 1,
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
                "domain_changes": [
                    {
                        "name": "backup",
                        "change_type": "changed",
                        "before": {"kind": "object", "sha256": "a" * 64},
                        "after": {"kind": "object", "sha256": "b" * 64},
                        "changed_fields": ["value"],
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_inventory_is_reported(self):
        errors = validate_inventory(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "assets_total": -1,
                    "asset_type_count": 0,
                    "hostnames_total": 0,
                    "role_count": 0,
                    "tag_count": 0,
                    "signal_domain_count": 0,
                },
                "assets": [
                    {
                        "id": "",
                        "type": "",
                        "hostname": 123,
                        "roles": "web",
                        "tags": "linux",
                    }
                ],
                "signal_domains": [
                    {
                        "name": "",
                        "kind": "table",
                        "item_count": -1,
                        "fields": "tool",
                    }
                ],
            }
        )
        self.assertIn("summary.assets_total must be at least 0.", errors)
        self.assertIn("assets[0].id must be a non-empty string.", errors)
        self.assertIn("assets[0].hostname must be a string.", errors)
        self.assertIn("assets[0].roles must be a list.", errors)
        self.assertIn("signal_domains[0].name must be a non-empty string.", errors)
        self.assertIn("signal_domains[0].kind must be one of: array, object, scalar.", errors)
        self.assertIn("signal_domains[0].item_count must be at least 0.", errors)

    def test_valid_privacy_scan(self):
        errors = validate_privacy_scan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "summary": {
                    "status": "fail",
                    "files_scanned": 1,
                    "files_skipped": 0,
                    "findings_count": 1,
                    "high_count": 1,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "findings": [
                    {
                        "path": "evidence.json",
                        "line": 1,
                        "kind": "token",
                        "severity": "high",
                        "excerpt": "token=<match>",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_scorecard(self):
        errors = validate_scorecard(
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
        )
        self.assertEqual(errors, [])

    def test_valid_review_attestation(self):
        errors = validate_review_attestation(
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
        )
        self.assertEqual(errors, [])

    def test_valid_review_summary(self):
        errors = validate_review_summary(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "decision": {
                    "status": "warn",
                    "recommendation": "review_required",
                    "reason": "Accepted risks need review.",
                },
                "metrics": {
                    "readiness_score": 90,
                    "report_status": "pass",
                    "gate_status": "pass",
                    "checks_failed": 0,
                    "checks_warn": 1,
                    "open_risks": 0,
                    "accepted_risks": 1,
                    "expired_acceptances": 0,
                    "stale_timestamps": 0,
                    "invalid_timestamps": 0,
                    "restore_failures": 0,
                    "restore_warnings": 0,
                    "privacy_findings": 0,
                    "scope_warnings": 0,
                    "drift_changes": 0,
                    "catalog_warnings": 0,
                    "runbook_warnings": 0,
                },
                "highlights": ["One accepted risk needs expiry tracking."],
                "next_steps": ["Review accepted risks."],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_scope_report(self):
        errors = validate_scope_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "warn",
                    "assets_declared": 1,
                    "evidence_assets": 1,
                    "in_scope_assets": 1,
                    "out_of_scope_assets": 0,
                    "missing_in_scope_assets": 0,
                    "unclassified_evidence_assets": 0,
                    "out_of_scope_evidence_assets": 0,
                    "domains_declared": 1,
                    "evidence_domains": 1,
                    "in_scope_domains": 0,
                    "out_of_scope_domains": 1,
                    "missing_required_domains": 0,
                    "unclassified_evidence_domains": 0,
                    "out_of_scope_evidence_domains": 1,
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
                        "name": "mail",
                        "scope_status": "out_of_scope",
                        "status": "present_out_of_scope",
                        "present": True,
                        "declared": True,
                        "required": False,
                        "kind": "object",
                        "item_count": 1,
                        "fields": ["domains"],
                        "owner": "customer",
                        "reason": "Reviewed separately.",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_service_catalog_report(self):
        errors = validate_service_catalog_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "warn",
                    "services_total": 1,
                    "services_passed": 0,
                    "services_warn": 1,
                    "critical_services": 1,
                    "high_services": 0,
                    "catalog_assets_total": 1,
                    "evidence_assets_total": 0,
                    "missing_catalog_assets_count": 1,
                    "unassigned_evidence_assets_count": 0,
                    "missing_domains_count": 0,
                    "missing_runbooks_count": 1,
                },
                "services": [
                    {
                        "id": "database",
                        "name": "Primary database",
                        "owner": "platform",
                        "criticality": "critical",
                        "status": "warn",
                        "contacts": ["database@example.invalid"],
                        "assets": ["db-01"],
                        "present_assets": [],
                        "missing_assets": ["db-01"],
                        "domains": ["backup"],
                        "present_domains": ["backup"],
                        "missing_domains": [],
                        "runbooks": ["database-restore"],
                        "present_runbooks": [],
                        "missing_runbooks": ["database-restore"],
                    }
                ],
                "unassigned_assets": [],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_runbook_report(self):
        errors = validate_runbook_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "warn",
                    "runbooks_total": 1,
                    "observed_runbooks": 0,
                    "expected_runbooks": 1,
                    "missing_runbooks_count": 1,
                    "stale_runbooks_count": 0,
                    "unreferenced_runbooks_count": 0,
                    "invalid_timestamp_count": 0,
                    "services_total": 1,
                    "services_with_missing_runbooks": 1,
                },
                "runbooks": [
                    {
                        "name": "database-restore",
                        "status": "missing",
                        "path": "",
                        "updated_at": "",
                        "age_days": None,
                        "timestamp_valid": None,
                        "expected": True,
                        "observed": False,
                        "referenced_by": ["database"],
                        "reason": "Expected by service catalog but not found in evidence.",
                    }
                ],
                "services": [
                    {
                        "id": "database",
                        "name": "Primary database",
                        "owner": "platform",
                        "status": "warn",
                        "runbooks": ["database-restore"],
                        "present_runbooks": [],
                        "missing_runbooks": ["database-restore"],
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_risk_register(self):
        errors = validate_risk_register(
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
        )
        self.assertEqual(errors, [])

    def test_valid_freshness_report(self):
        errors = validate_freshness_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "warn",
                    "timestamps_total": 1,
                    "current_count": 0,
                    "stale_count": 1,
                    "future_count": 0,
                    "invalid_count": 0,
                    "oldest_age_days": 31,
                    "newest_age_days": 31,
                },
                "timestamps": [
                    {
                        "path": "signals.backup.last_success_at",
                        "status": "stale",
                        "value": "2026-05-01T00:00:00+00:00",
                        "age_days": 31,
                        "future_days": None,
                        "max_age_days": 30,
                        "timestamp_valid": True,
                        "reason": "Timestamp is older than 30 day(s).",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_restore_report(self):
        errors = validate_restore_report(
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
        )
        self.assertEqual(errors, [])

    def test_invalid_privacy_scan_is_reported(self):
        errors = validate_privacy_scan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "summary": {
                    "status": "unknown",
                    "files_scanned": -1,
                    "files_skipped": 0,
                    "findings_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "findings": [
                    {
                        "path": "",
                        "line": 0,
                        "kind": "",
                        "severity": "urgent",
                        "excerpt": "",
                    }
                ],
            }
        )
        self.assertIn("summary.status must be one of: fail, pass.", errors)
        self.assertIn("summary.files_scanned must be at least 0.", errors)
        self.assertIn("findings[0].path must be a non-empty string.", errors)
        self.assertIn("findings[0].line must be at least 1.", errors)
        self.assertIn("findings[0].kind must be a non-empty string.", errors)
        self.assertIn("findings[0].severity must be one of: high, low, medium.", errors)
        self.assertIn("findings[0].excerpt must be a non-empty string.", errors)

    def test_valid_gate_result(self):
        errors = validate_gate_result(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "pass",
                    "conditions_total": 1,
                    "conditions_failed": 0,
                    "source_score": 100,
                    "source_failed": 0,
                    "source_warnings": 0,
                },
                "conditions": [
                    {
                        "id": "min_score",
                        "title": "Readiness score is at least 90",
                        "status": "pass",
                        "observed": 100,
                        "operator": "at_least",
                        "expected": 90,
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_gate_result_is_reported(self):
        errors = validate_gate_result(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "unknown",
                    "conditions_total": -1,
                    "conditions_failed": 0,
                    "source_score": 0,
                    "source_failed": 0,
                    "source_warnings": 0,
                },
                "conditions": [
                    {
                        "id": "",
                        "title": "",
                        "status": "unknown",
                        "operator": "",
                    }
                ],
            }
        )
        self.assertIn("summary.status must be one of: fail, pass.", errors)
        self.assertIn("summary.conditions_total must be at least 0.", errors)
        self.assertIn("conditions[0].id must be a non-empty string.", errors)
        self.assertIn("conditions[0].title must be a non-empty string.", errors)
        self.assertIn("conditions[0].status must be one of: fail, pass.", errors)
        self.assertIn("conditions[0].operator must be a non-empty string.", errors)
        self.assertIn("conditions[0].observed is required.", errors)
        self.assertIn("conditions[0].expected is required.", errors)

    def test_valid_badge(self):
        errors = validate_badge(
            {
                "schemaVersion": 1,
                "label": "openops",
                "message": "pass 100",
                "color": "brightgreen",
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_badge_is_reported(self):
        errors = validate_badge(
            {
                "schemaVersion": 2,
                "label": "",
                "message": "",
                "color": "",
            }
        )
        self.assertIn("schemaVersion must be 1.", errors)
        self.assertIn("label must be a non-empty string.", errors)
        self.assertIn("message must be a non-empty string.", errors)
        self.assertIn("color must be a non-empty string.", errors)

    def test_valid_report_history(self):
        errors = validate_report_history(
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
                        "note": "Release check",
                        "status": "pass",
                        "score": 100,
                        "checks_total": 10,
                        "checks_passed": 10,
                        "checks_failed": 0,
                        "checks_warn": 0,
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_report_history_is_reported(self):
        errors = validate_report_history(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "entries_total": 0,
                    "latest_status": "unknown",
                    "latest_score": 101,
                    "previous_score": 100,
                    "score_change": "better",
                    "best_score": 100,
                    "worst_score": 0,
                    "latest_failed": -1,
                    "latest_warnings": 0,
                    "failed_delta": 0,
                    "warnings_delta": 0,
                },
                "entries": [],
            }
        )
        self.assertIn("entries must contain at least one item.", errors)
        self.assertIn("summary.entries_total must be at least 1.", errors)
        self.assertIn("summary.latest_status must be one of: fail, pass.", errors)
        self.assertIn("summary.latest_score must be at most 100.", errors)
        self.assertIn("summary.score_change must be an integer.", errors)
        self.assertIn("summary.latest_failed must be at least 0.", errors)

    def test_valid_bundle_manifest(self):
        errors = validate_bundle_manifest(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "artifacts": [
                    {
                        "path": "evidence.json",
                        "filename": "evidence.json",
                        "role": "evidence",
                        "media_type": "application/json",
                        "size_bytes": 128,
                        "sha256": "a" * 64,
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_bundle_manifest_hash_is_reported(self):
        errors = validate_bundle_manifest(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "artifacts": [
                    {
                        "path": "evidence.json",
                        "filename": "evidence.json",
                        "role": "evidence",
                        "media_type": "application/json",
                        "size_bytes": 128,
                        "sha256": "not-a-hash",
                    }
                ],
            }
        )
        self.assertIn("artifacts[0].sha256 must be a lowercase SHA-256 hex digest.", errors)

    def test_valid_bundle_verification(self):
        errors = validate_bundle_verification(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {},
                "results": [{"path": "evidence.json", "status": "verified"}],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_bundle_signature(self):
        errors = validate_bundle_signature(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {"key_id": "ops-2026"},
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
        )
        self.assertEqual(errors, [])

    def test_invalid_bundle_signature_is_reported(self):
        errors = validate_bundle_signature(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "manifest": {
                    "path": "manifest.json",
                    "size_bytes": -1,
                    "sha256": "not-a-hash",
                },
                "signature": {
                    "algorithm": "none",
                    "value": "not-a-signature",
                },
            }
        )
        self.assertIn("manifest.size_bytes must be a non-negative integer.", errors)
        self.assertIn("manifest.sha256 must be a lowercase SHA-256 hex digest.", errors)
        self.assertIn("signature.algorithm must be hmac-sha256.", errors)
        self.assertIn("signature.value must be a lowercase SHA-256 hex digest.", errors)

    def test_valid_report_comparison(self):
        errors = validate_report_comparison(
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
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
