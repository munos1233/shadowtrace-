## Summary

Closes #65

ISSUE-064 P0 E2E response-loop: analysis → action → disposition writeback closure with synchronous outbox delivery and MockXDR readback confirmation.

## Production changes (test-driven, required for P0 acceptance)

| File | Why |
|------|-----|
| `event_disposition_service.py` | After `activate_and_submit`, synchronously `deliver_outbox` so outbox leaves READY and CONFIRMED receipt (readback_verified) is produced |
| `disposition_sync_service.py` | `deliver_outbox` + EVENT_STATUS_UPDATE readback → `confirm_readback` |
| `mock_xdr.py` / `base.py` | Two-phase readback simulation for P0 MockXDR contract |
| `workflow_runtime.py` | FP disposition-only creates deferred Action; INSIDER_THREAT guard |
| `events.schema.json` | `writeback_readback_failed` event type (17 total) |

These are **not scope creep** — without them outbox stays READY forever and CONFIRMED receipts cannot be asserted.

## Test coverage (this PR)

- **Scenario 1**: IMMEDIATE entity `ENTITY_ACTION_SUBMIT` outbox count == 1 + MockXDR submit count
- **Scenario 2**: `ApprovalEngine.evaluate()` drives L3 → WAITING_APPROVAL (not DB seed)
- **Scenario 2 gate**: same `plan_revision` IMMEDIATE + deferred — partial approval blocks `activate_and_submit`; full approval succeeds
- **Scenario 5 hook**: `test_scenario_5_via_rule_based_fp_hook` via real `RuleBasedFalsePositiveHook`
- Scenarios 3–4: fault matrix + recovery (DB contract layer documented; orchestration recovery in ISSUE-062)

## How to run

Requires Compose (PostgreSQL + Redis + MockXDR):

```bash
cd backend
pytest tests/integration/test_e2e_response_loop.py -m e2e_response -v
```

Full backend CI:

```bash
# from repo root — same as GitHub Actions backend-test job
```

## Notes

- Mock-only; no live XDR switches
- `.env.example`: `MIN_READBACK_DELAY_MS` documents readback timing for tests
- Scenario 2 approval uses `ApprovalEngine.approve()` (service layer), not REST — consistent with B2 fix
