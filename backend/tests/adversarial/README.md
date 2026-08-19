# Adversarial agent audit

Independent Mock XDR scenario for **dynamic** evaluation — not registered in
`SCENARIO_REGISTRY` and not used by `make bootstrap`.

## Scenario

**`adversarial_credential_db_staging_exfil`** — multi-stage attack without obvious
keyword labels in the incident title:

1. Service account `svc-analytics-47` VPN login from unusual geo (`198.51.100.44`)
2. Credential tooling (`ntdsutil.exe`) on `WKS-DATA-031`
3. RDP pivot to `SRV-DB-STG-02`, `mysqldump` + `rclone.exe`
4. ~890MB HTTPS upload to `storage-sync-cdn.example`
5. Red herring: legitimate backup job on `BACKUP-SRV-01`

### High-noise layer (added)

Poll ingests **6 incidents** (5 decoy + 1 true positive) and **~600+ telemetry rows**:

| Layer | Count |
|-------|------:|
| Decoy incidents (benign/maintenance) | 5 |
| Alert storm on last decoy | 10 alerts |
| Network noise (`is_noise=true`) | 280 |
| Identity noise | 90 |
| Endpoint noise | 140 |
| DNS noise | 60 |
| Suspicious-looking decoy key events | 6 |
| True-positive key events | 17 |

The test selects the true incident by `true_positive_incident_id=88190001`, simulating
an analyst picking one case from a noisy queue.

Ground truth lives in `scenario_credential_db_staging_exfil.py` (`GROUND_TRUTH`) when the
adversarial pytest suite is present locally.

## Golden packs (in repository)

Scenario-specific Mock LLM goldens ship under:

```text
backend/app/core/llm/golden/*/default.json
backend/app/core/llm/golden/*/insider_data_exfiltration.json
backend/app/core/llm/golden/*/adversarial_credential_db_staging_exfil.json
```

Use `scenario_id=None` for neutral defaults (ISSUE-201) or pass an explicit scenario id
to load the matching pack.

## Run (adversarial pytest — optional / local)

The dynamic audit **pytest modules** (`test_agent_adversarial_audit.py`,
`test_agent_adversarial_full_loop.py`) are excluded by pyproject ``addopts``
(local bare ``pytest`` and CI ``backend-test`` both skip them).
CI Checks display **`backend-closure-gates-mock`** (ISSUE-350). The YAML job **id**
stays `backend-closure-gates` so `needs:` keys remain stable; the job pins
**`LLM_MODE=mock`**. A green check is **Mock plumbing** (golden / scripted paths +
Mock disposition). It is **not** Live reasoning proof and **not** EntitySet
containment-coverage proof. Local full-loop still needs Postgres + Redis.

```bash
cd backend

# Helper / scorecard unit tests (default pytest; no Postgres)
uv run --frozen pytest tests/adversarial/test_adversarial_helpers.py -q

# Analysis-only audit (→ REPORTING) — deselects unless -o addopts= (pyproject excludes adversarial_audit)
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py \
  -m adversarial_audit -v -s -o addopts=

# Production full loop — only when tests/adversarial/*.py exists
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_full_loop.py \
  -m adversarial_audit -v -s -o addopts=
```

`pytest tests/adversarial/ -q` (Issue #965) runs helper/unit tests and **deselects** the two dynamic modules. Use the `-m adversarial_audit -o addopts=` commands above for analysis-only / full-loop.

When the adversarial pytest tree is **not** checked in, validate golden packs via:

```bash
cd backend
uv run --frozen python -m pytest tests/test_core/test_golden_defaults.py -q
```

## Mock vs Live evaluation boundary

This suite has **two layers**:

| Layer | Role | Pass means |
|-------|------|------------|
| **Plumbing** | Agents run, traces persist, tools/LLM logs exist | Wiring works — not capability proof |
| **Quality gate** (`test_agent_adversarial_full_loop.py`, ISSUE-203) | Hard asserts on terminal status, report, disposition targets, Mock writeback, no sunset shims | Production graph reached `REPORTING`/`CLOSED` with **scripted-golden-aligned** containment targets + terminal `CONFIRMED` receipt |

Mock full loop typically finishes in **~20–40s** (see artifact `elapsed_s`). Runner default
timeout is **120s**; set ``ADVERSARIAL_FULL_LOOP_TIMEOUT_S`` for Live runs (default 600s when
``LLM_MODE=openai_compatible``). Adversarial conftest sets ``BUDGET_ENABLED=false`` so token
budget does not truncate the audit path.

Do **not** claim autonomous investigation quality from Mock plumbing alone. Live LLM runs add reasoning signal but remain non-deterministic.

| Mode | What it measures | What it does **not** measure |
|------|------------------|------------------------------|
| **Mock** (`LLM_MODE=mock`, default) | Deterministic pipeline wiring, agent orchestration, evidence projection, degraded flags, report structure | Real LLM reasoning, novel scenario generalization, or production adjudication quality |
| **Mock + no DI override** | Agents use ``resolve_llm_scenario_id()``: when the ingested event carries ``normalized.scenario`` (adversarial poll does), Mock loads ``adversarial_credential_db_staging_exfil`` goldens — not ``default.json`` | Same as Mock — golden content is scripted for this scenario pack |
| **Mock + explicit `scenario_id=None` on pipeline** | Analysis-only audit (`build_analysis_pipeline(scenario_id=None)`) skips DI override; routing still follows event ``source_snapshot`` / ``raw_alert_snapshot`` when present (ISSUE-199) | Agent capability ceiling on unseen narratives without scenario label |
| **Mock + scenario golden** | Regression / demo packs (e.g. `insider_data_exfiltration`, `adversarial_credential_db_staging_exfil`) | Same as Mock — golden content is scripted, not emergent reasoning |
| **Live** (`LLM_MODE=openai_compatible` + API key) | Closer-to-production LLM behavior on unseen narratives | Vendor availability, cost, non-determinism |

**Do not** interpret Mock adversarial audit **PASS** as proof of autonomous investigation quality. Mock results validate plumbing and scripted paths only; Live runs (or human red-team review) are required for capability claims.

### Certification cards (ISSUE-350)

| Card | How it runs | What a green result means | What it does **not** mean |
|------|-------------|---------------------------|---------------------------|
| **Mock plumbing** | CI Checks `backend-closure-gates-mock` (job id `backend-closure-gates`, `LLM_MODE=mock` pinned). Local: same as CI — `pytest tests/adversarial/test_agent_adversarial_full_loop.py -m adversarial_audit -o addopts=` (needs Postgres + Redis). Helper pytest ≠ this card. | Pipeline wiring, golden-scripted agents, Mock disposition CLOSED | Live glm reasoning, novel-narrative capability, or containment coverage beyond scripted golden + ISSUE-328 gates |
| **Live reasoning** | Manual / nightly `LLM_MODE=openai_compatible` + API key, then `EVAL_REQUIRE_LLM_QUALITY=1 make eval-full-loop` (`scripts/dynamic_eval_full_loop.py --require-llm-quality`). **Not a PR gate.** Do **not** use GET `/health` 60min `success_rate` as the event conclusion. | Per-event `llm_call_log` core-prompt success (`triage_extract` / `plan_generate` / `risk_score` / `response_plan`). 9/9 timeout = FAIL. `generated_by=template` on data-exfil `confirmed_threat` = FAIL. | Must not block daily Mock plumbing; golden `isolate_host` is not glm skill; `--require-closed` green is not this card |

The scorecard JSON field `scorecard_header` records `llm_mode`, `certification_card` (from `scorecard_contract_for_llm_mode()["kind"]`), and `summary` (the card interpretation). Golden `response_plan` for this pack includes EntitySet hosts (`WKS-DATA-031` and `SRV-DB-STG-02`) so Mock LLM and ISSUE-328 rules stay aligned — that is still a **scripted** pack, not Live reasoning.

Do **not** open ISSUEs that only add scorecard `unscored` buckets, extra `degraded_flag`s, or new eval profiles unless they directly fix a real hole (scenario stamp, rule superset, timeout short-circuit, or this Live card). Do not change ISSUE-328 coverage to include domains, do not make `validate_closed_gate` consult GT, do not FAIL the scorecard on coverage GAP, and do not make `--require-closed` reject `degraded_template`.

### Provenance-aware quality audit (ISSUE-334)

Entity/indicator **text understanding** in `quality_audit` counts only when the token appears in original alert narrative (`title` / `description`). Structured source merge (`attributes.provenance=source`) is tracked separately as `source_projection_hits` and does **not** fill text-understanding credit. Prompt-appendix echo in LLM narrative fields is `echo_only_hits`.

`must_response_targets` includes staging DB host `SRV-DB-STG-02`. ISSUE-328 made DB isolation default-enforced (`must_response_targets_gated` is empty). Set `ADVERSARIAL_STRICT_DISPOSITION_TARGETS=1` only if new deferred targets are added to the gated list.

### Mock LLM routing (ISSUE-199 / ISSUE-201)

| Test | DI / pipeline override | Typical golden pack |
|------|------------------------|---------------------|
| `test_agent_adversarial_audit.py` | `build_analysis_pipeline(scenario_id=None)` | Event `normalized.scenario` → `adversarial_credential_db_staging_exfil.json` |
| `test_agent_adversarial_full_loop.py` | Production graph; `get_approval_engine()` | Same — adversarial incident always embeds `scenario` in `normalized` |

Neutral `default.json` applies only when no scenario label exists on the event. This suite always labels itself, so Mock response/triage/risk paths use the adversarial pack (including `must_response_targets`).

Optional — use a real LLM (Volcengine Ark / OpenAI-compatible) instead of Mock golden defaults.

Docker stack with `.env.live` at repo root already sets live LLM for backend/worker.
For **pytest on the host**, export the same vars (or `set -a && source ../.env.live && set +a`):

```bash
set -a && source ../.env.live && set +a
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py \
  -m adversarial_audit -v -s -o addopts=
```

Or inline:

```bash
LLM_MODE=openai_compatible \
LLM_API_BASE_URL=https://ark.cn-beijing.volces.com/api/coding/v3 \
LLM_API_KEY=... \
LLM_PRIMARY_MODEL=glm-5.2 \
  uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_full_loop.py \
  -m adversarial_audit -v -s -o addopts=
```

Live runs are slower and non-deterministic; increase timeout if needed:

```bash
ADVERSARIAL_FULL_LOOP_TIMEOUT_S=600 LLM_MODE=openai_compatible ... pytest ...
```

Optional — graph-mode SuperAgent instead of analysis-only pipeline: duplicate the
test and call `build_super_agent(scenario_id=None)` from integration fixtures.

## Output

| Test | Artifact | Terminal state |
|------|----------|----------------|
| `test_agent_adversarial_audit.py` | `artifacts/latest_audit.json` | `REPORTING` |
| `test_agent_adversarial_full_loop.py` | `artifacts/latest_full_loop_audit.json` | `CLOSED` + Mock terminal writeback `CONFIRMED` (raw `confirmation_evidence` / `simulated` exported; certification label `mock_simulated` or `adapter_acknowledged`, never live `readback_verified`) + aligned response targets |

Full-loop artifact includes `response_plan_actions`, `sunset_shims_used` (must be
empty), explicit `adversarial_di_overrides`, and `disposition_target_gaps`. Sunset
shims removed in ISSUE-203/204:
verify_tail, writeback_activation seeding, minimum disposition audit seed, and
post-loop ``final_disposition_activate``.

Mock XDR executes entity actions via ``DispositionSync`` (``entity_action_submit``),
which does **not** update ``MockEnvironmentState``. Adversarial conftest wraps
``e2e_tool_executor`` with ``XdrManagedVerifyToolExecutor`` so VerifyAgent ``check_*``
tools observe persisted Action + ``DispositionReceipt`` rows instead.

Harness-only helpers (ISSUE-204, ``tests/adversarial/xdr_verify_observation.py``):

| Component | Role |
|-----------|------|
| ``XdrManagedVerifyToolExecutor`` | Routes ``check_*`` to DB-backed XDR writeback facts |
| ``AdversarialVerifyAgent`` | Unit-test helper only; the full-loop runner uses production ``VerifyAgent`` |

Approval resumes through the production ``ApprovalEngine`` callback. The runner
simulates worker delivery by calling production ``DispositionSyncService``; confirmed
outboxes resume the graph through the service callback.

The full-loop gate intentionally uses production terminal-resolution semantics.
Non-verifiable or non-applicable actions must be projected correctly by production
``VerifyAgent``; the harness does not relax that gate with a custom resolver.

Console prints human verdict + check matrix for each run.

## Interpretation

Scorecard mode is explicit via ``AdversarialAuditChecks.audit_mode`` (ISSUE-319).

| Mode | PASS means | FAIL / notes |
|------|------------|--------------|
| ``analysis_only`` (default) | Reached **REPORTING** + expected verdict + risk ≥ ground-truth minimum (5 scored dims). **CLOSED not required.** | Did not reach reporting, or under-scored / wrong verdict (`PARTIAL` / `WEAK`) |
| ``full_loop`` | Reached **CLOSED** + expected verdict + adequate risk (6 scored dims; `closed_reached` is scored). | Any full-loop path without CLOSED is **FAIL** (never release-grade), even if analysis dims / writeback look green |

| Verdict token | Meaning |
|---------------|---------|
| **PASS** | Mode-specific gate above passed (use ``startswith("PASS")``; FAIL text never contains ``PASS``) |
| **PARTIAL** | Reached reporting with high risk but type/verdict off |
| **WEAK** | Reached reporting but under-scored |
| **FAIL** | Mode gate failed (analysis: no reporting; full-loop: no CLOSED, or no reporting) |

``disposition_writeback_ok`` and other ``production_checks`` are separate hard gates; they do **not** override ``verdict_for_human``.

### Writeback certification language (ISSUE-351)

Mock adversarial scorecards export terminal receipt **raw** fields ``confirmation_evidence`` and ``simulated`` under ``writeback_certification``. Outward labels use ``mock_simulated`` or ``adapter_acknowledged`` — **never** equate Mock ``simulated=true`` receipts with live ``readback_verified`` / 「写回已验证」. Full-loop ``verdict_for_human`` annotates ``writeback=simulated`` on Mock paths.

Optional strict profile (default off): set ``ADVERSARIAL_MOCK_WRITEBACK_CERT_STRICT=1`` to also require strong ``confirmation_evidence`` tiers on Mock receipts (independent of ``validate_closed_gate`` mock branch).

Analysis audit (`test_agent_adversarial_audit.py`) uses ``build_analysis_pipeline(scenario_id=None)``
(no DI override). Full-loop quality gate uses production graph wiring with
``get_approval_engine()`` — both paths resolve Mock goldens from the ingested event's
``normalized.scenario`` field (``adversarial_credential_db_staging_exfil`` for this suite).

Set ``LLM_MODE=openai_compatible`` for non-deterministic Live evaluation. Golden pack files:
``backend/app/core/llm/golden/*/adversarial_credential_db_staging_exfil.json``.
