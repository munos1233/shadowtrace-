# ShadowTrace 部署指南（ISSUE-088）

## 前置要求

| 依赖 | 最低版本 | 说明 |
|------|----------|------|
| Docker | 24+ | 含 docker compose 插件 |
| Python | 3.11+ | 仅 bootstrap 脚本编译/迁移时需要 |
| 内存 | 4 GB | 默认 mock 模式（不含 OpenSearch / Neo4j） |
| 磁盘 | 2 GB | 主要为 PostgreSQL 数据卷 |

**无需真实的 XDR、GPU 推理机或外部 LLM API key。**  
默认全栈以 **mock 模式** 运行，所有数据、推理与处置均在容器内闭环。

---

## 一键启动（官方推荐 — ISSUE-304）

Mock 栈上**稳定可验收**的官方路径需要 **Celery investigation worker**（`TASK_MODE=celery`）。默认 `make up` 使用 `TASK_MODE=background`（进程内 BackgroundTasks，重启丢任务），仅适合短路径分析演示，**不是**全闭环金路径。

### 全闭环金路径（官方主入口 — seed → investigate → 脚本审批 → writeback → verify → CLOSED）

单场景 CLOSED（含 report + 脚本审批，**禁止**空等 `APPROVAL_TIMEOUT`）：

```bash
make up-demo
make demo-full-loop
# 等价：EVAL_REQUIRE_CLOSED=1 make eval-full-loop
# 单场景：EVAL_SCENARIO=insider_data_exfiltration make demo-full-loop
# compat 剖面（非 strict CLOSED）：make eval-full-loop
# Live 研判卡（与 CLOSED 管道卡拆开）：EVAL_REQUIRE_LLM_QUALITY=1 make eval-full-loop
# Mock LLM_MODE=mock 时研判卡必须红（mock-model 不是 live glm）。
# Live glm：写 LLM-only .env.live（含 CERTIFICATION_CARD=live_reasoning），然后
#   make down-v && make up-live-reasoning
# 不要 make up-demo + .env.live（demo-guard 会 fail-closed）。
```

分步剖面（`bootstrap-demo-full-loop` 会停在 `waiting_approval`，需脚本审批后 `eval-full-loop` 收口）：

```bash
make up-demo
make bootstrap-demo-full-loop
EVAL_REQUIRE_CLOSED=1 make eval-full-loop
```

### 分析种子 + compat 冒烟（非 CLOSED）

`make bootstrap-demo`（别名 `bootstrap-demo-analysis`）默认 `BOOTSTRAP_INCLUDE_RESPONSE=false`：**仅分析种子**，不含 response 执行，事件**不会**到达 Approve→Execute→Verify→CLOSED。全闭环请用上一节金路径。

```bash
# 1. 启动 core + investigation worker + scheduler + observability（Mock-only）
make up-demo

# 2. 迁移 + playbook + 三场景 seed/ingest + 自动 investigate（分析剖面，非 CLOSED）
make bootstrap-demo
# 或：make bootstrap-demo-analysis

# 3. 冒烟：health + worker + 每场景 compat 终态（analysis_only_complete 或 EventStatus closed/contained；非 strict CLOSED 金路径）
make smoke-demo

# 4. 打开浏览器
#    http://localhost:3000
```

`make smoke-demo` 在事件超时未达约定终态时 **非零退出**，并打印 `event_id` 状态轨迹。建议在干净 volume 上运行（`make down-v` 后再 `up-demo`）；idempotent bootstrap 会跳过 re-seed，terminal poll 仅监控 API 返回的最新 3 条事件。

三场景 matrix + 全局 strict CLOSED（与 `--profile-by-scenario` 互斥；Makefile 在开启 REQUIRE_CLOSED 时自动关闭 profile）：

```bash
EVAL_MATRIX_REQUIRE_CLOSED=1 make eval-full-loop-matrix
# 等价显式写法：
EVAL_MATRIX_REQUIRE_CLOSED=1 EVAL_MATRIX_PROFILE_BY_SCENARIO=0 make eval-full-loop-matrix
```

分步金路径见上文（`bootstrap-demo-full-loop` 停在 `waiting_approval`，再用 `EVAL_REQUIRE_CLOSED=1 make eval-full-loop` 收口；勿空等 `APPROVAL_TIMEOUT`）。

### 短路径分析演示（legacy — 非官方全闭环）

仅启动 core、无 worker；investigate 走 BackgroundTasks，三场景并行易排队/卡住；`make smoke-bootstrap` 默认 **不** 断言终态（`SMOKE_TERMINAL_MODE=off`）。

```bash
make up
make bootstrap
make smoke-bootstrap          # health + ≥3 事件；不含终态门禁
# 可选终态门禁（需 worker 栈才有意义）：
# SMOKE_TERMINAL_MODE=compat make smoke-bootstrap
```

启动后在前端 **事件看板** 可见 3 个演示事件；`make bootstrap` 会自动对 `new` 状态事件 POST `/investigate`，也可在前端手动再次触发。

**数据库迁移（ISSUE-238）：** 仅 `backend` 容器在启动时执行 `alembic upgrade head`。Celery `worker` / `scheduler-beat` / `scheduler-worker` 与 `mock-xdr` 均设置 `SKIP_DB_MIGRATE=true`，并等待 `backend` healthy 后再启动，避免空 volume 首次并行 `up` 时双份迁移竞态。

### 演示门禁：Playbook 必须 ready（ISSUE-245）

演示 / 评测前必须确认 playbook release 已激活，否则 Response/Playbook 绑定会在调查栈里 **fail-soft 降级**（仅 warning），易被误判为「完整 playbook 能力」：

```bash
curl -s localhost:8000/api/v1/health | jq .playbook_resources
# 期望：
# {
#   "status": "ready",
#   "active_release_id": "krel-...",
#   ...
# }
```

| 检查项 | 期望 |
|--------|------|
| `playbook_resources.status` | `ready` |
| `playbook_resources.active_release_id` | 非空 |
| Compose backend | `SEED_PLAYBOOK_RELEASE=true`（默认；entrypoint 在 healthy 前 seed） |
| `make up-demo` | 另设 `PLAYBOOK_REQUIRED=true` → 非 ready 时 `/health` 返回 **503** |
| 调查路径 | **不**因缺 playbook 拒绝调查（生产可无 playbook；fail-soft 保留） |

非 ready 时：`make bootstrap` / `make smoke-bootstrap` / `make smoke-demo` 会失败；可手动补种：

```bash
docker compose -f infra/docker-compose.yml exec backend \
  bash -c 'cd /app/backend && python -m scripts.load_playbook_release'
```

### Mock 全栈 Demo（ISSUE-141）

一键启动 **core + investigation worker + ingestion scheduler + observability**（Mock-only，容器内 OTEL 走 `http://otel-collector:4318`）。

**CLOSED 金路径：** `make up-demo && make demo-full-loop`（见上文）。分步等价：`make up-demo` → `make bootstrap-demo-full-loop` → `EVAL_REQUIRE_CLOSED=1 make eval-full-loop`。

**分析种子 + compat 冒烟（非 CLOSED）：**

```bash
make up-demo
make bootstrap-demo-analysis   # 同 bootstrap-demo；不含 response，非 CLOSED
make smoke-demo                # exit 0 并打印 URL/端口表
```

与默认路径的区别：

| 启动方式 | 包含服务 | OTEL |
|----------|----------|------|
| `make up` | core only | 关（默认） |
| `make up WORKER=1` | core + worker | 可选，需手工启 observability |
| `make up SCHEDULER=1` | core + scheduler | 可选 |
| `make up-observability` | otel-collector + prometheus + grafana only | 开（无 app） |
| `make up-demo` | core + worker + scheduler + otel-collector + prometheus + grafana | 默认开，in-network |

**停止 demo 栈：** 使用 `make up-demo` 后必须用 **`make down-demo`** 停止 worker/scheduler/observability；仅 `make down` 只会停 core，demo 容器可能残留（Makefile 会提示）。

**约束：** demo profile 为 Mock-only。存在 `.env.live` 或 `ALLOW_LIVE_SIDE_EFFECTS=true` / `BLOCK_LIVE_ACTION_EXECUTION=true` / `ALLOW_XDR_WRITEBACK=true` / `AUTO_*=true` / `SIMULATION_ENABLED=false` / 非 mock `SOURCE_MODE` 时 `make up-demo` / `make bootstrap-demo` / `make smoke-demo` **fail-closed**（安全策略，非 EventStatus CLOSED）。

---

## 常用命令

| 命令 | 说明 |
|------|------|
| `make up` | 启动核心服务（--build 构建镜像） |
| `make up WORKER=1` | 启动核心服务 + Celery investigation worker（Makefile 自动 `TASK_MODE=celery`） |
| `make up SCHEDULER=1` | 启动核心服务 + Mock XDR 摄取调度器（Beat + ingestion worker，见下文） |
| `make bootstrap` | 迁移 + **playbook release 激活** + mock-xdr 种子 + 摄取 + 自动触发研判 |
| `make bootstrap LOAD_KB=true` | 同上 + 加载 attack/case 知识库（约 30-60 秒） |
| `make smoke-bootstrap` | bootstrap 后冒烟：health + **playbook_resources=ready** + ≥3 事件 + 前端反代（默认 **不含** 终态门禁） |
| `SMOKE_TERMINAL_MODE=compat make smoke-bootstrap` | 同上 + 每场景 compat 终态（需 worker 栈；超时非零退出） |
| `make up-demo` | **官方 Mock 全栈 demo**（core + worker + scheduler + observability，ISSUE-141 / ISSUE-304） |
| `make bootstrap-demo` | 分析种子：`make bootstrap` + demo guard；默认不含 response，**非 CLOSED** |
| `make bootstrap-demo-analysis` | `bootstrap-demo` 显式别名（同上） |
| `make bootstrap-demo-full-loop` | bootstrap + `BOOTSTRAP_INCLUDE_RESPONSE=true` + `BOOTSTRAP_GENERATE_REPORT=true`（停 `waiting_approval`，非自动 CLOSED，需脚本审批） |
| `make smoke-demo` | 分析剖面 compat 冒烟：bootstrap 检查 + worker + scheduler + OTEL + **compat 终态门禁**（非 CLOSED） |
| `make demo-full-loop` | 单场景 CLOSED 金路径（`eval-full-loop` + demo guard） |
| `make down-demo` | 停止 demo 栈（含 worker/scheduler/observability）——**up-demo 后必用** |
| `make eval-full-loop` | **金标全闭环评测**（ISSUE-256）：mock-xdr seed → full_loop → **脚本审批**；默认 compat，strict CLOSED 需 `EVAL_REQUIRE_CLOSED=1` 或 `demo-full-loop`；Live 研判卡需 `EVAL_REQUIRE_LLM_QUALITY=1`（与 `--require-closed` 拆开） |
| `make eval-full-loop-matrix` | **官方动态评测 matrix**（ISSUE-301）：每场景独立 Compose project + fresh volumes，可选 strict CLOSED |
| `make up-observability` | 仅启动 OTEL/Prometheus/Grafana（不含 app） |
| `make down-observability` | 停止 observability 栈 |
| `make down` | 停止并移除容器（**数据卷保留**） |
| `make down-v` | 停止并移除容器 + **删除所有数据卷** |
| `make test` | 运行后端 pytest **健康检查**测试（`tests/test_infra/test_health.py`） |
| `make test-ci-lite` | 轻量本地门禁：契约漂移 + health/contracts/gold-path/smoke 单测 + lint（非完整 CI） |

### 动态评测金标剖面（ISSUE-256）

第二轮动态评测里，用手搓 `POST /events` 跑「全闭环」会在 Mock 上 **没有实体 → Evidence 失败**；靠 `APPROVAL_TIMEOUT_MINUTES=30` 空等结束会踩 R2-012 / ISSUE-247。金标剧本如下（**不改生产默认安全策略**）：

```bash
# 1) 有 investigation 执行能力的栈（demo 或 WORKER=1）
make up-demo
# 或: make up WORKER=1

# 2) 一键金标：seed_mock_xdr_and_ingest + include_response_execution + 脚本 approve
make eval-full-loop
# 等价：
# python3 scripts/dynamic_eval_full_loop.py --seed-via-compose \
#   --scenario insider_data_exfiltration --max-events 1
```

| 项 | 金标 / 评测 | 生产默认（保持不变） |
|----|-------------|----------------------|
| 事件夹具 | `scripts/seed_mock_xdr_and_ingest.py` | 同左（bootstrap 已用） |
| 禁止夹具 | 手搓 `POST /events` 冒充全闭环 | — |
| investigate | `include_response_execution=true`，通常 `generate_report=true` | bootstrap 默认二者皆 false |
| 审批收场 | `scripts/dynamic_eval_approve.py` / `make eval-full-loop` | 人工 UI 或脚本；**禁止**靠超时收场 |
| `APPROVAL_TIMEOUT_MINUTES` | 评测可在本地 `.env` 设 `2~5` | **30**（勿为评测改仓库默认） |
| `LLM_TIMEOUT_SECONDS` | 评测可设 `45~60` | `.env.example` 默认 `30` |

**Bootstrap 可选剖面**（默认行为不变）：

```bash
BOOTSTRAP_GENERATE_REPORT=true make bootstrap
BOOTSTRAP_INCLUDE_RESPONSE=true make bootstrap   # 会停在 waiting_approval，需脚本审批
```

**耗时与混跑诚实说明（R2-014 / R2-017）：**

- Compose investigation worker 使用 `celery -c 2`。一次触发 **3** 路调查会排队约数分钟；评测请优先 `--max-events 1` / `EVAL_MAX_EVENTS=1`。
- 默认 `EMBEDDING_MODE=mock`；即使 `LLM_MODE` 指向真实 openai_compatible 端点，embedding 仍可能是 mock，除非两边都显式覆盖。这是预期混跑，不是金标缺陷。
- 本剖面 **不**改变 ISSUE-206 / 计划审批 / `evidence_limited` 产品合同。

评测超时建议写在本地 `.env`（参考仓库根目录 `.env.example` 中「Dynamic eval / gold-path profile」注释块），**不要**把仓库里的 `APPROVAL_TIMEOUT_MINUTES=30` 改成 2。

**脏夹具：** 单场景 `make eval-full-loop` 复用已有 Compose 卷时，残留 connector watermark / `agent_task` 幂等键 / mock observation Redis key 会被当成脏夹具并 **fail-closed**（提示 `dirty fixture, run down-v or --fresh-volumes`）。官方路径是 `make down-v` 后 `make up-demo`，或使用 `make eval-full-loop-matrix`（每场景 fresh volumes）。不要把脏卷上的 `IntegrityError` / observation `degraded` 包装成研判失败。

**嵌套 Docker / Cloud Agent：** 在已有容器里再跑 Compose 时，宿主机 `bridge-nf-call-iptables` 可能丢掉容器互访（ICC）。这是环境问题：修 iptables/ICC 或改用 non-nested Docker。**禁止**把产品 `DATABASE_URL` / `REDIS_URL` 改成网关映射端口来“绕过”容器网络。

### 动态评测 matrix（ISSUE-301）

全闭环 matrix 是仓库内**唯一**推荐的 serial 动态评测入口：每个场景使用独立 `COMPOSE_PROJECT_NAME` 与 fresh volumes，避免 Mock XDR `control/seed` 在前一场景尚未结束时覆盖 state。

```bash
# strict CLOSED 验收（三场景串行；任一场景失败即停止）
python3 scripts/dynamic_eval_matrix.py \
  --scenarios insider_data_exfiltration,account_anomaly_fp,suspicious_domain_access \
  --fresh-volumes \
  --require-closed

# Makefile 等价（默认三场景 + fresh volumes + profile-by-scenario）
make eval-full-loop-matrix
# 全局 strict CLOSED（自动关闭 profile-by-scenario）
EVAL_MATRIX_REQUIRE_CLOSED=1 make eval-full-loop-matrix
```

| 项 | matrix compat（默认） | matrix strict（`--require-closed`） | 单场景 ISSUE-256 |
|----|----------------------|-------------------------------------|------------------|
| Compose project | 每场景唯一 `shadowtrace-eval-<scenario>-<run>` | 同左 | 固定 `COMPOSE_PROJECT_NAME` |
| Host ports | **不发布**（`infra/docker-compose.eval.yml`） | 同左 | 默认映射 8000/5432/… |
| seed → harness | seed JSON **显式 event_ids** → `--event-id` | 同左 | 单场景可 `--seed-via-compose` |
| 终态 | `reporting` / `contained` / `closed` 等 | 必须 `closed` + `GET /report` + writeback gate | strict：`closed` + report + writeback（`demo-full-loop`）；compat：`eval-full-loop` |
| Eval 超时 | `infra/docker-compose.eval.yml` 覆盖 `APPROVAL_TIMEOUT_MINUTES` / `LLM_TIMEOUT_SECONDS`（默认 5min / 60s） | 同左 | 本地 `.env` 评测 profile |
| 失败行为 | 停止后续场景；`down -v --remove-orphans` 清理 | 同左 | 依使用者手动清理 |
| Artifact | `artifacts/dynamic-eval-matrix/<run-id>/<scenario>/manifest.json` 与根目录 `summary.json` | 同左 | 无官方目录 |

Makefile 可选：`EVAL_MATRIX_FRESH_VOLUMES=0`（保留 volume）、`EVAL_MATRIX_SCENARIOS=...` 覆盖场景列表。

Matrix 在容器内通过 `docker compose exec backend` 访问 `http://127.0.0.1:8000`，**不**探测或绑定 host port。

### 场景 profile 与 FP baseline（ISSUE-313）

`account_anomaly_fp` 的 post-evidence FP adjudication 依赖 `data/organization/change_windows.json`（默认 tenant-demo）。Compose 显式设置 `CHANGE_WINDOW_BASELINE_PATH=/app/data/organization/change_windows.json`；宿主 dev 留空时会向上查找仓库 `data/organization/...`。

评测 preflight（FP 场景）在 baseline 不可读或非零退出，并打印实际解析路径（`/api/v1/health` → `change_window_baseline.resolved_path`）。

**不要把 baseline 修复误解为 full-loop early close**：graph 中 `route_after_fp_adjudication` 在 full-loop 下仍继续；FP 短闭环属于 `include_response_execution=false` 的 analysis-only profile。

### 两张认证卡（ISSUE-350）

- **管道卡（Mock / `--require-closed`）**：CLOSED + 报告壳 + 条件写回。LLM 可降级。CI `backend-closure-gates-mock`。绿 ≠ Agent 会研判。
- **研判卡（Live / `--require-llm-quality`）**：按 `event_id` 查 `llm_call_log` 核心 prompt；全 timeout = FAIL。`generated_by=template` 对外泄 `confirmed_threat` = FAIL。禁止用 `/health` 60 分钟 `success_rate` 冒充本事件结论。接到 nightly / 发布 checklist，**不是**每个 PR。

发布话术只允许在研判卡绿时说「Agent 会研判」。

不要再开「给 scorecard 加 unscored 注解 / 再加一个 degraded_flag / 再加一个 eval profile」类 ISSUE，除非直接修上述洞。不要改 ISSUE-328 coverage 含 domain、不要让 `validate_closed_gate` 查 GT、不要让 scorecard 因 coverage GAP 变 FAIL、不要让 `--require-closed` 拒绝 `degraded_template`。

`make eval-full-loop-matrix` 默认启用 `--profile-by-scenario`（`EVAL_MATRIX_PROFILE_BY_SCENARIO=1`；设 `0` 可关闭）：

```bash
python3 scripts/dynamic_eval_matrix.py \
  --scenarios insider_data_exfiltration,account_anomaly_fp,suspicious_domain_access \
  --fresh-volumes \
  --profile-by-scenario

make eval-full-loop-matrix
# opt out: make eval-full-loop-matrix EVAL_MATRIX_PROFILE_BY_SCENARIO=0
```

| 场景 | 语义门（必须通过） | 压力门（独立报告） |
|------|-------------------|-------------------|
| `insider_data_exfiltration` | full-loop strict CLOSED | 无 |
| `account_anomaly_fp` | analysis-only **CLOSED + false_positive** | compat full-loop（失败不推翻语义门） |
| `suspicious_domain_access` | analysis-only CLOSED | compat full-loop（两者均须通过） |

失败输出包含 `event_id`、elapsed、`status_trace`、`degraded_flags`、最近 transition audit，而不再统一提示 “Check evidence/entities”。

---

## 可选组件

```bash
# OpenSearch 全文搜索（ISSUE-084）
docker compose -f infra/docker-compose.yml --profile optional up -d opensearch

# Neo4j 图谱镜像（ISSUE-082）
docker compose -f infra/docker-compose.yml --profile optional up -d neo4j

# Celery worker（异步研判执行）
# 注意：需同时将 backend 的 TASK_MODE 改为 celery（默认 background）
docker compose -f infra/docker-compose.yml --profile worker up -d worker

# Mock XDR 持续摄取调度器（ISSUE-107）— 默认关闭，需显式启用 profile
# Beat 与 investigation worker 分离；不会在 investigation worker 上使用 -B
make up SCHEDULER=1
# 或：
docker compose -f infra/docker-compose.yml --profile scheduler up -d
```

启用 scheduler profile 后，Compose 会启动 `scheduler-beat` 与 `scheduler-worker`，并设置：

```ini
INGESTION_SCHEDULER_ENABLED=true
INGESTION_POLL_INTERVAL_S=60   # 可调；测试可设为 1–2
SOURCE_MODE=mock_xdr
DISPOSITION_BASE_URL=http://mock-xdr:8100
```

调度器按 interval 触发 Celery task `shadowtrace.poll_sources`，复用 `SourceIngester.poll()` 增量摄取 Mock XDR 新对象（`status=new`），**不会**自动触发 investigate（见 ISSUE-108）。

### 调查执行矩阵（ISSUE-225）

`ORCHESTRATION_MODE` × `TASK_MODE` 决定调查 runner：

| ORCHESTRATION_MODE | TASK_MODE | trigger | runner | 持久性 |
|---|---|---|---|---|
| `graph`（默认） | `background`（默认） | HTTP investigate | BackgroundTasks → SuperAgent | ❌ 进程重启丢失 |
| `graph` | `celery` | HTTP investigate | Celery → SuperAgent | ✅ worker 宕机可重试 |
| `analysis_only` | `background` | HTTP investigate | BackgroundTasks → AnalysisOnlyPipeline | ❌ 进程重启丢失 |
| `analysis_only` | `celery` | HTTP investigate | Celery → AnalysisOnlyPipeline | ✅ worker 宕机可重试 |

**注意**：`analysis_only` + `celery` 从 ISSUE-225 开始支持；之前 `analysis_only` 忽略 `TASK_MODE` 始终走 BackgroundTasks。

Auto-investigate / scheduler 触发的调查仍走 Celery → SuperAgent（LangGraph），不受 `ORCHESTRATION_MODE=analysis_only` 影响；仅 HTTP `POST …/investigate` 受上表约束。

### Durable intent 调度与 Beat 依赖（ISSUE-291）

`TASK_MODE=celery` 时，HTTP/ingest 受理会先 **commit** `investigation_intent` 再 best-effort 触发 `dispatch_pending_investigation_intents.delay()`。该立即触发失败 **不会** 撤销已落库的 PENDING intent，也 **不会** 让 API 返回 503（ISSUE-276 durable 202 语义保持不变）。

**运维必须同时满足：**

| 组件 | 作用 |
|------|------|
| Celery investigation **worker** | 消费 `shadowtrace.run_investigation` 等任务 |
| Celery **beat**（`scheduler-beat` 或 demo 栈） | 周期执行 `shadowtrace.dispatch_investigation_intents` 与 `shadowtrace.reconcile_investigation_intents`，捞起 PENDING/RETRY 与 stale intent |

仅 `make up WORKER=1` 而 **未** 启 beat 时，enqueue 失败或进程重启后 intent 可能长期 PENDING。应使用 `make up-demo` / `make up SCHEDULER=1`（含 beat），或手工调用管理 API `POST /api/v1/investigation-intents/dispatch` 补偿。

**可观测性：**

```bash
# beat 调度键 + pending 龄期 + enqueue 计数（进程内）
curl -s localhost:8000/api/v1/health | jq '.celery.investigation_intent_beat, .investigation.intent_dispatch'
```

- 指标：`shadowtrace_investigation_intent_enqueue_total{result=success|failure}`
- enqueue 失败日志含 `trigger` / `intent_id` / `event_id`；已知 `event_id` 时设置 degraded flag `auto_investigate_dispatch_unavailable`
- **禁止** 静默 fallback 到 BackgroundTasks

验证：

```bash
# 1. 启动 stack + scheduler
make up SCHEDULER=1

# 2. 仅向 mock-xdr seed 新场景（不手工 poll；由 scheduler 摄取）
docker compose -f infra/docker-compose.yml exec backend \
  python3 scripts/seed_mock_xdr_and_ingest.py \
  --scenario insider_data_exfiltration --seed-only

# 3. 观察 scheduler-worker 日志（≤2×interval 内应出现 ingest accepted）
docker compose -f infra/docker-compose.yml logs -f scheduler-worker

# 4. 确认 API 可见新事件
curl -s http://localhost:8000/api/v1/events | python3 -m json.tool
```

本地单测：

```bash
make ingestion-scheduler-test
```

**注意**：仅设置 `INGESTION_SCHEDULER_ENABLED=true` 而不启动 `--profile scheduler` **不会**启动 Beat/ingestion worker 容器；必须同时使用 profile（`make up SCHEDULER=1`）。

Redis 计数键 `shadowtrace:ingestion:stats:*` 为运维累计指标（无 TTL）。`status=completed` 且 `summary.degraded=true` 表示 connector 降级但未抛异常，需查看 scheduler-worker 日志。

启用 OpenSearch / Neo4j 后，需在 `.env` 中设置对应开关：
```ini
OPENSEARCH_ENABLED=true
NEO4J_ENABLED=true
```

---

## 端口约定

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端（nginx） | 3000 | React SPA，自动反代 /api → backend |
| 后端（FastAPI） | 8000 | API + Socket.IO |
| Mock XDR | 8100 | 模拟外部数据源与处置端点 |
| PostgreSQL | 5432 | pgvector 扩展已启用 |
| Redis | 6379 | 缓存 + 事件总线 |
| OpenSearch | 9200 | 可选，需 `--profile optional` |
| Neo4j HTTP | 7474 | 可选，需 `--profile optional` |
| Neo4j Bolt | 7687 | 可选，需 `--profile optional` |
| OTLP HTTP | 4318 | observability / `make up-demo` |
| OTLP gRPC | 4317 | observability / `make up-demo` |
| Prometheus | 9090 | observability / `make up-demo` |
| Grafana | 3001 | observability / `make up-demo`（admin / shadowtrace） |
| OTEL metrics | 8889 | collector Prometheus exporter |

端口可通过 `infra/.env` 或 Makefile 变量覆盖（见 `infra/.env.example`）。

---

## 健康检查

```bash
curl http://localhost:8000/api/v1/health
```

Mock 模式下预期响应（符合 ISSUE-001 契约）：
```json
{
  "status": "ok",
  "postgres": "ok",
  "redis": "ok",
  "source_adapter": {
    "status": "ok",
    "mode": "mock_xdr",
    "capability": {
      "LOG_INGESTION": "SUPPORTED",
      "QUERY": "SUPPORTED",
      "EVENT_DISPOSITION": "UNSUPPORTED",
      "ENTITY_RESPONSE": "UNSUPPORTED"
    }
  },
  "disposition_adapter": {
    "status": "ok",
    "mode": "mock_xdr",
    "capability": {
      "LOG_INGESTION": "UNSUPPORTED",
      "QUERY": "UNKNOWN",
      "EVENT_DISPOSITION": "SUPPORTED",
      "ENTITY_RESPONSE": "SUPPORTED"
    }
  },
  "tool_provider": {
    "status": "ok",
    "mode": "mock",
    "capability": {
      "query": "SUPPORTED",
      "response": "SUPPORTED",
      "verification": "SUPPORTED",
      "rollback": "SUPPORTED"
    }
  },
  "simulation_enabled": true,
  "version": "0.1.0"
}
```

当 PostgreSQL 或 Redis 不可达时，顶层 `status` 变为 `"degraded"` 且 HTTP 状态码为 503。

LangGraph checkpoint 在 Redis 读写失败后会 **fail-soft 降级到进程内 memory**（进程重启不可恢复）。`/api/v1/health` 的 `checkpoint` 块会反映该状态：`memory_fallback=true` 时顶层 `status` 为 `degraded`（HTTP 仍 200，除非 postgres/embedding 硬依赖失败）。

可选环境变量（默认关闭）：

| 变量 | 默认 | 说明 |
|------|------|------|
| `CHECKPOINT_ATTEMPT_REDIS_RECOVERY` | `false` | 为 `true` 时，fallback 后周期性 ping Redis；恢复成功后 **仅新 `thread_id`** 恢复 Redis 持久化 |
| `CHECKPOINT_REDIS_RECOVERY_INTERVAL_SECONDS` | `30` | 回升探测间隔（秒） |
| `CHECKPOINT_FALLBACK_REMINDER_INTERVAL_SECONDS` | `300` | fallback 持续期间 warning 日志限流间隔 |

已降级到 memory 的 `thread_id` 会保持 memory-pinned 直至事件结束，**不会**写回 Redis（避免半持久化分裂）。指标：`shadowtrace_checkpoint_memory_fallback`（0/1）、`shadowtrace_checkpoint_fallback_total`（按 reason 计数）。

---

## 切换到 Live 模式

Live 模式**不是** compose profile；通过可选 env 叠加文件启用。复制 `infra/.env.live.example` 为项目根目录 `.env.live` 并填入凭证，
然后重建 stack（compose 会自动叠加该文件，覆盖 mock 默认值）：

```bash
cp infra/.env.live.example .env.live
# 编辑 .env.live，填入 LLM_API_KEY 与 provider 凭证
make down && make up
```

也可手动修改根目录 `.env` / `.env.example` 中的关键开关：

```ini
SIMULATION_ENABLED=false
LLM_MODE=openai_compatible
LLM_API_BASE_URL=https://your-provider.example/v1
LLM_API_KEY=sk-your-key-here
LLM_PRIMARY_MODEL=your-model-id
SOURCE_MODE=live_crowdstrike    # 替换为实际 provider
TOOL_MODE=live
ALLOW_LIVE_SIDE_EFFECTS=true    # 注册 live ToolProvider，不放行 execute_plan
BLOCK_LIVE_ACTION_EXECUTION=false  # true 会冻结 ActionExecution / 写回投递
```

`LLM_API_BASE_URL` 是 **chat/completions 路径前缀**（不含 `/chat/completions` 后缀）。火山 Ark 示例：`https://ark.cn-beijing.volces.com/api/v3`。

诊断：

```bash
make llm-smoke
curl -s http://localhost:8000/api/v1/health | python3 -c "import json,sys; print(json.load(sys.stdin)['llm'])"
```

**安全栅栏**：`APP_ENV=production` 时，应用启动即拒绝任何 mock/simulation 模式组合（fail-closed）。  
Mock 模式下的 `ALLOW_*` 始终为 `false`。

### 生产认证与 Trusted Proxy（ISSUE-180）

生产环境身份来源：

| 机制 | 生产可用 | 说明 |
|------|----------|------|
| `DEV_AUTH_TOKENS` | **否** | 启动后一律拒绝，仅本地/Compose 开发用 |
| Trusted reverse proxy | **是** | 需 `TRUSTED_AUTH_PROXY_ENABLED=true` 且客户端直连地址在 allowlist 内 |

**部署硬性要求：**

1. **禁止**将 backend `:8000` 直接暴露到公网。必须由内网 ingress / 反向代理终止 TLS，并由该代理注入 `X-Auth-Subject` / `X-Auth-Roles`；backend 只信任 allowlist 中的代理直连地址。
2. `APP_ENV=production` 且 `TRUSTED_AUTH_PROXY_ENABLED=true` 时，`TRUSTED_PROXY_ALLOWLIST` 必须为非空、**不含** `*` 的显式地址列表；否则进程 **拒绝启动**（fail-closed）。
3. `X-Auth-Roles` 仅接受已知角色（`analyst` / `approver` / `disposition_operator` / `admin`）；大小写不敏感（会归一化为小写），未知角色会被丢弃，可能导致 403。
4. Mock P0 闭环默认使用 `DEV_AUTH_TOKENS`，**不依赖** trusted-proxy 路径。
5. 生产环境应启用 trusted-proxy（`TRUSTED_AUTH_PROXY_ENABLED=true`）并配置显式 allowlist；若关闭 trusted-proxy 且 `APP_ENV=production`，除 proxy 外无可用认证路径（`DEV_AUTH_TOKENS` 一律拒绝）。
6. **生产环境禁止设置前端构建变量 `VITE_AUTH_ROLES` / `VITE_DEV_AUTH_TOKEN`**。真实用户角色由 trusted-proxy 按请求注入（`X-Auth-Roles`），前端构建时共享的角色配置无法代表请求级 principal；设置了这些变量会导致内联审批等按角色门控的 UI 在合法用户上被错误禁用（ISSUE-207）。它们仅用于 Mock/Compose 单 token 开发阶段。
7. `SOCKETIO_CORS_ALLOWED_ORIGINS` 必须配置为允许访问实时通道的精确浏览器 Origin 列表（逗号分隔，例如 `https://soc.example.com`）；生产环境空值或通配符 `*` 会导致进程拒绝启动。

### Compose / 开发令牌角色（ISSUE-308）

`infra/docker-compose.yml` 预置两条 `DEV_AUTH_TOKENS`，角色职责应严格区分：

| Token | 角色 | 用途 |
|-------|------|------|
| `bootstrap-token` | `analyst` + `approver` + `disposition_operator` + **`admin`** | **仅** bootstrap / 需 admin 的运维逃生（如 `force_local_close`）；脚本 `make bootstrap` 默认使用 |
| `e2e-token` | `analyst` + `approver` | 日常 Mock 闭环、E2E、答辩演示；**不含** admin，无法 force-close |

**硬性要求：**

1. 日常 UI / API 调试优先使用 `e2e-token`（或自建仅含 analyst/approver 的 token），避免用宽权限 token 掩盖 RBAC 缺口。
2. `bootstrap-token` 保留 admin 是为 seed / force-close 逃生舱；`StateMachineService.force_close` 在服务层校验 `admin` 角色（与 API 一致），Celery/脚本直调服务也无法绕过。
3. **生产必须** `APP_ENV=production`：进程拒绝非空 `DEV_AUTH_TOKENS`，身份仅来自 trusted-proxy。

前端 `VITE_DEV_AUTH_TOKEN` 默认 `e2e-token`（Compose 日常 analyst 流程）；需 admin 逃生时在 `infra/.env` 覆盖为 `bootstrap-token`。

### 生产前端镜像构建检查清单（ISSUE-221）

独立构建生产 SPA / 前端 Docker 镜像时（**非** `infra/docker-compose.yml` 开发栈）：

- [ ] **未**向 `docker build` / CI 传入 `VITE_DEV_AUTH_TOKEN`（`frontend/Dockerfile` 默认空，forget 覆盖即无 Bearer 内嵌）
- [ ] **未**设置 `VITE_AUTH_ROLES`（见 ISSUE-207）
- [ ] 使用 trusted-proxy 注入身份；backend 不暴露 `:8000` 到公网（见上节）
- [ ] 本地 Compose 开发仍可通过 compose build-args 显式传入 `bootstrap-token` / `e2e-token`（`docker-compose.yml` 已配置）

验证示例（产物不得自动携带 dev Bearer）：

```bash
cd frontend
pnpm build   # 不 export VITE_DEV_AUTH_TOKEN
pnpm run verify:production-build
```

示例（**生产**镜像构建 — 不传 dev token）：

```bash
docker build -f frontend/Dockerfile frontend \
  --build-arg VITE_API_BASE_URL=/api/v1
# 勿加 --build-arg VITE_DEV_AUTH_TOKEN=...
```

示例（**Compose 开发** — 显式 dev token，与 Makefile/`make up` 一致）：

```bash
docker compose -f infra/docker-compose.yml build frontend
# 等价于传入 VITE_DEV_AUTH_TOKEN=bootstrap-token（可经 infra/.env 覆盖）
```

示例（内网 ingress 位于 `10.0.0.5`，backend 仅接受来自该地址的身份头）：

```ini
APP_ENV=production
TRUSTED_AUTH_PROXY_ENABLED=true
TRUSTED_PROXY_ALLOWLIST=10.0.0.5
SOCKETIO_CORS_ALLOWED_ORIGINS=https://soc.example.com
# DEV_AUTH_TOKENS 留空或不设置
```

---

## 故障排除

### 端口冲突

修改 `infra/.env`（复制自 `infra/.env.example`）中的端口映射，然后：

```bash
# 检查端口占用
# Linux / macOS:
lsof -i :3000 -i :8000 -i :5432 -i :6379 -i :8100
# Windows (PowerShell):
netstat -ano | findstr "3000 8000 5432 6379 8100"

# 修改 infra/.env 中的端口后重建
make down && make up
```

### 后端不健康

```bash
docker compose -f infra/docker-compose.yml logs backend
```

常见原因：数据库未就绪（等待 postgres healthy）、端口冲突。

### 前端无法加载数据

确认 nginx 能访问后端：`curl http://localhost:3000/api/v1/health`。  
如果返回 502，检查 backend 容器是否在运行。

### 重置所有数据

```bash
make down-v   # 删除容器 + 数据卷
make up       # 重新启动
make bootstrap
```

### Mock XDR 连接失败

```bash
curl http://localhost:8100/mock-xdr/v1/health
```

若不可达，检查 mock-xdr 容器状态：`docker compose -f infra/docker-compose.yml ps mock-xdr`

> **注意**：mock-xdr 为内存状态，容器重启后数据丢失。可通过 `make bootstrap` 重新播种。

### 前端构建失败

```bash
# 降级：仅启动 backend + 依赖（不含 frontend）
docker compose -f infra/docker-compose.yml up -d backend
make bootstrap
# 然后直接访问 API 文档：http://localhost:8000/docs
```

前端构建失败不影响后端 API 演示。

### 重复运行 bootstrap

`make bootstrap` 在数据卷上**幂等**：若已有 ≥3 个事件，会跳过 seed/ingest（alembic 仍运行）。
强制重新播种：`FORCE_BOOTSTRAP=true make bootstrap`。  
如需完全重置：`make down-v && make up && make bootstrap`。

## 可选：OpenTelemetry 可观测性（ISSUE-092）

默认关闭（`OTEL_ENABLED=false`），对业务零影响。启用时需同时配置 **API 进程**与 **Celery worker**（若使用 `--profile worker`）。

**推荐（demo 全栈）：** 使用 `make up-demo`，自动合并 app + observability compose，并将容器内 OTLP 指向 `http://otel-collector:4318`（无需 `host.docker.internal`）。

### 1. 启动 observability 栈

```bash
# 仅 observability（app 需另行 make up）
make up-observability

# 或 demo 一键（app + worker + scheduler + observability）
make up-demo
```

- Grafana: http://localhost:3001 （admin / shadowtrace）
- Prometheus: http://localhost:9090
- OTLP HTTP: http://127.0.0.1:4318

### 2. 启用 backend / worker 导出

在 `.env` 或 shell 中设置（backend 与 worker 均需一致，worker 建议使用独立 service name）：

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318   # 本机 backend
# Docker worker 默认 compose 已映射 host.docker.internal:4318
OTEL_SERVICE_NAME=shadowtrace-backend               # worker compose 内为 shadowtrace-worker
```

然后重启 stack：

```bash
make up
# 若使用 Celery worker：
docker compose -f infra/docker-compose.yml --profile worker up -d
```

### 3. 验证

```bash
cd backend && pytest tests/test_core/test_telemetry.py -v
make bootstrap   # 产生写回与研判流量
```

在 Grafana「ShadowTrace Writeback Observability」看板查看四面板（积压、确认率、重试/冲突、UNKNOWN）。

> Traces 当前由 collector 输出到 debug 日志；指标经 Prometheus 供 Grafana 使用。导出失败仅记日志，不阻塞业务。

**安全（ISSUE-310）：** 启用 OTEL 时，httpx 出站 span 会对 `Authorization` / `Cookie` / `X-Api-Key` 等敏感请求头做与日志 `RedactingFormatter` 一致的脱敏后再导出；**实际 HTTP 请求头不受影响**。生产环境仍勿将 trace 导出到不可信或未审计的 OTLP collector；若需捕获额外 HTTP 头，请确认 collector 存储与访问控制符合安全基线。
