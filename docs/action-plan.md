# Action Plans

Action plans turn a machine report into a compact remediation queue. They are
designed for ticket creation, customer handoff, recurring readiness reviews, and
small teams that need the next practical step without rereading the full report.

## Create A Plan

```powershell
python -m openops_evidence plan -i report.local.json -o action-plan.json
python -m openops_evidence plan -i report.local.json -f markdown -o action-plan.md
python -m openops_evidence plan -i report.local.json -f csv -o action-plan.csv
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence plan -i report.local.json --waivers examples/waivers.sample.toml -o action-plan.json
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
```

By default, the plan includes failed and warning checks. Use `--fail-only` when
CI should focus only on required failures. Use `--include-pass` when you need a
complete exported checklist.

## Exit Code

`plan` returns `1` when the generated plan contains at least one non-waived
action item and `0` when there are no action items that currently need work.
Invalid input returns `2`.

This makes the command useful in scheduled jobs:

```powershell
python -m openops_evidence plan -i report.local.json --fail-only -o action-plan.json
```

## Priority Mapping

Action item priority is deterministic:

| Severity | Priority |
| --- | --- |
| `critical` | `P0` |
| `high` | `P1` |
| `medium` | `P2` |
| `low` | `P3` |

Items are sorted by priority, then by status, then by check ID.

## Risk Waivers

Waivers document accepted risk without deleting the underlying finding. They are
intended for temporary exceptions, customer-approved deferrals, staged rollouts,
and other cases where a failed or warning check is known but not immediately
remediated.

```toml
[[waivers]]
check_id = "mail_dmarc_policy"
owner = "ops@example.invalid"
reason = "Domain is in a staged DMARC monitoring rollout."
expires_at = "2099-12-31T00:00:00+00:00"
```

Active waivers set the item `waived` flag, include the waiver metadata in JSON
and CSV output, and do not contribute to `action_required_count`. Expired
waivers stay visible, but the finding returns to the active remediation queue.

## Ticket Export

Use `ticket export` when findings should become concrete ticket drafts without
binding the workflow to one vendor API:

```powershell
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence ticket export -i action-plan.json -o action-tickets --include-waived
```

The command writes an `index.md` and one Markdown file per non-waived failing or
warning item. Pass `--include-waived` when accepted risks should also become
review tickets. Existing files with the same generated names are overwritten;
unrelated files in the output directory are left untouched.

## JSON Shape

```json
{
  "schema_version": "0.1",
  "generated_at": "2026-05-31T10:00:00+00:00",
  "metadata": {
    "source_report_generated_at": "2026-05-31T10:00:00+00:00",
    "source_status": "fail",
    "source_score": 70,
    "item_count": 1
  },
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
    "low_count": 0
  },
  "items": [
    {
      "priority": "P0",
      "id": "backup_recent",
      "title": "Recent successful backup exists",
      "status": "fail",
      "severity": "critical",
      "required": true,
      "path": "signals.backup.last_success_at",
      "operator": "within_days",
      "observed_count": 0,
      "waived": false,
      "waiver": {},
      "recommended_action": "Configure backups and record the last successful backup timestamp."
    }
  ]
}
```

The schema is published as `schemas/action-plan.schema.json`.
