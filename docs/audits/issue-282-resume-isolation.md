# ISSUE-282 resume isolation artifact

Status: checkpoint `NOT REPRODUCED`; approval `NOT REPRODUCED`

## Fixed baseline and isolation

- Audit issue: GitHub #878 / internal ISSUE-282 (`ID-REL-001`).
- Original audit reference: `main@9e09029`; isolated verification baseline:
  upstream `main@3514f06`.
- Relevant fixes already present on the verified baseline:
  - `8d8fcd2` — resume investigation from the LangGraph checkpoint after approval.
  - `73232bd` — harden rejection/writeback resume paths.
  - `37300f4` and `f08b170` — make production resume failures observable and add CI coverage.
  - `d8b31a4` — prevent unsafe full-graph restart when a reporting checkpoint is missing.
- Host: macOS arm64; Docker Desktop Engine 29.1.2.
- Services: dedicated Compose project `shadowtrace-issue878-baseline`,
  `pgvector/pgvector:pg16` and `redis:7`.
- Runner: one local pytest worker; no xdist and no parallel DB probes.
- Isolation: `clean_state` truncates all business tables and clears `shadowtrace:*`
  Redis keys before and after every attempt.
- Python: CPython 3.13.12 locally; GitHub CI independently exercises Python 3.11.

The tests record `halted`, checkpoint `next`, `node_trace`, pending Action IDs,
event status, and execution substate at the relevant boundaries. The production
approval path also records lease ownership; the direct checkpoint scenario does
not create a production `EventLease`, so ownership is not applicable there.

## A. Checkpoint resume before `risk_node`

```bash
cd backend
python -m pytest tests/integration/test_orchestration.py -q -k checkpoint_resume
```

| Boundary | halted | next | node trace | pending IDs | status | substate | owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Paused | `false` | `risk_node` | triage/planner/evidence; no risk | `[]` | `analyzing` | `none` | N/A |
| Resumed | `false` | empty | risk exactly once; `close_node` present | `[]` | `closed` | `none` | N/A |

| Attempt | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Result | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

Conclusion: **NOT REPRODUCED**. Product checkpoint code is unchanged. The regression
now runs ten isolated attempts and fails on missing `close_node`, replayed nodes, stale
`next`, unexpected Actions, or inconsistent status/substate.

## B. Production-owned approval resume

```bash
cd backend
python -m pytest tests/integration/test_production_graph_resume.py -q -k approval_wait
```

This is the real production dependency path: task entrypoint, production `SuperAgent`,
Redis checkpoint, `ApprovalEngine`, `EventLease`, PostgreSQL state, and approval callback.
The runner never invokes the graph resume or action executor directly.

| Boundary | halted | next | pending IDs | status/substate | owner |
| --- | --- | --- | --- | --- | --- |
| Approval wait | `true` | empty | one or more waiting Actions | `waiting_approval` / `waiting_approval` | none (initial owner released) |
| Approval resume | false unless a later legal manual hold occurs | empty | `[]` | never `failed`; verify tail reached | none |

Every attempt additionally proves:

- the approval API invokes the production resume hook exactly once;
- `needs_approval_wait=false` after the decision;
- `execute_node` is present and verify is reached by node trace, AgentTrace, or persisted result;
- no lease owner remains after either run;
- a later `manual_hold_node` is distinguished from the suspected stale approval halt.

| Attempt | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Result | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

Conclusion: **NOT REPRODUCED** on the rebased production implementation. No speculative
product semantics were changed and the two original observations are not claimed to share
a root cause. The committed artifact and ten-attempt CI regressions preserve the evidence.
