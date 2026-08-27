<!-- ShadowTrace live quality audit FIX-001；main@d524a16f；CODE_CONFIRMED；CI artifact detection_ci_run.json -->

### 类型

Bug 修复（评测发布门与 fail-closed 演示切片混装）

### 优先级

P0

### 当前事实

- CI `backend-evaluation` 跑 `scripts.run_detection_evaluation`，manifest [`data/evaluation/detection_shadow_v1/threshold_manifest.json`](data/evaluation/detection_shadow_v1/threshold_manifest.json)：`required_gate: true`，`min_pass_rate: 1.0`，`max_error_count: 0`。
- run `31917018845`：`pass_rate=0.666…`，`gate_verdict=fail_closed`。artifact `detection_ci_run.json`：**7 案 pass=4 / fail=0 / unevaluable=1 / error=2**。
- **unevaluable 不进 pass_rate 分母**（[`detection/runner.py`](backend/app/evaluation/detection/runner.py) `evaluable = pass+fail+error`）。`unevaluable_partial_telemetry` 覆盖率 1.0，不是红因。
- 两例 ERROR 是故意 fail-closed 切片：
  - `threat_cold_start_insufficient_history`：`threat_detection` ERROR `missing detection feature baseline for snapshot entity`
  - `threat_resource_budget_exceeded`：`threat_detection` ERROR `observation scan cost limit exceeded` + `resource_budget` FAIL
- 单测 [`test_detection_shadow_v1_full_dataset`](backend/tests/evaluation/test_detection_runner.py)、`test_cold_start_insufficient_history_fail_closed`、`test_resource_failure_fail_closed` **断言**这两例必须 FAILED/ERROR。
- [`baseline_artifact.json`](data/evaluation/detection_shadow_v1/baseline_artifact.json) 钉死同一 FAILED 快照。CI `--compare-baseline` 无漂移，但 `required_gate` 仍让 job 退出 1。

这不是漏检，也不是 unevaluable 计错。是 **发布门混装了「必须 ERROR」的演示切片**。

### 目标

required detection job 能诚实变绿，同时冷启动/超预算切片继续 fail-closed（不得改成检出威胁）。

### 推荐修复方案（工业级）

1. **拆集（首选）**：发布门数据集只含 4 个应过 + 1 个 unevaluable；两例 fail-closed 切片放到独立 observe job（CLI 已有 `--allow-gate-fail`）。发布门 `required_gate` 仍为 true。
2. **或**给两例 `expected_outcome=fail_closed`：按设计 ERROR 时该案计 PASS，然后重钉 baseline。
3. 单测继续钉死「cold-start / budget 必须 runtime_error」，不要删。

### 文件范围

- `data/evaluation/detection_shadow_v1/`（拆集或 expected_outcome + baseline）
- `.github/workflows/ci.yml`（detection 步骤：required vs observe）
- `backend/app/evaluation/detection/`（仅当走 expected_outcome）
- `backend/tests/evaluation/test_detection_runner.py`

### 验收标准

- [ ] required detection job `gate_verdict=pass` 且 `required_gate` 仍 true
- [ ] cold-start / budget 切片仍 ERROR/FAILED（单测绿）
- [ ] unevaluable 仍不进 pass_rate 分母

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/evaluation/test_detection_runner.py -q
```

### 关联

- 审计：`审计报告.md` FIX-001 / ID-BLK-003
- CI：https://github.com/munos1233/shadowtrace-/actions/runs/31917018845

### 禁止事项

- 禁止 `required_gate: false` 直接罩住混装集
- 禁止把 `min_pass_rate` 降到 0.66 对齐现状
- 禁止让 unevaluable 变成 pass
- 禁止让 cold-start / 超预算切片 **检出威胁**（打 fail-closed 语义与现有单测）
- 禁止用 `--allow-gate-fail` 冒充 required 绿
