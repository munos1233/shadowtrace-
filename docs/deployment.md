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

## 一键启动

```bash
# 1. 启动核心服务（postgres, redis, mock-xdr, backend, frontend）
make up

# 2. 数据库迁移 + playbook release 激活 + 摄入演示数据 + 自动触发研判
make bootstrap

# 3. （可选）冒烟验证（含 playbook_resources 门禁）
make smoke-bootstrap

# 4. 打开浏览器访问前端看板
#    http://localhost:3000
```

启动后在前端 **事件看板** 可见 3 个演示事件；`make bootstrap` 会自动对 `new` 状态事件 POST `/investigate`，也可在前端手动再次触发。

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

一键启动 **core + investigation worker + ingestion scheduler + observability**（Mock-only，容器内 OTEL 走 `http://otel-collector:4318`）：

```bash
make up-demo
make bootstrap-demo    # 或 make bootstrap
make smoke-demo        # exit 0 并打印 URL/端口表
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

**约束：** demo profile 为 Mock-only。存在 `.env.live` 或 `ALLOW_LIVE_SIDE_EFFECTS=true` / `AUTO_*=true` / `SIMULATION_ENABLED=false` / 非 mock `SOURCE_MODE` 时 `make up-demo` / `make bootstrap-demo` / `make smoke-demo` **fail closed**。

---

## 常用命令

| 命令 | 说明 |
|------|------|
| `make up` | 启动核心服务（--build 构建镜像） |
| `make up WORKER=1` | 启动核心服务 + Celery investigation worker（需同时设 `TASK_MODE=celery`） |
| `make up SCHEDULER=1` | 启动核心服务 + Mock XDR 摄取调度器（Beat + ingestion worker，见下文） |
| `make bootstrap` | 迁移 + **playbook release 激活** + mock-xdr 种子 + 摄取 + 自动触发研判 |
| `make bootstrap LOAD_KB=true` | 同上 + 加载 attack/case 知识库（约 30-60 秒） |
| `make smoke-bootstrap` | bootstrap 后冒烟：health + **playbook_resources=ready** + ≥3 事件 + 前端反代 |
| `make up-demo` | **Mock 全栈 demo**（core + worker + scheduler + observability，ISSUE-141） |
| `make bootstrap-demo` | 同 `make bootstrap`（demo guard + 迁移/种子） |
| `make smoke-demo` | demo 全栈冒烟：bootstrap + worker + scheduler + OTEL/Prometheus/Grafana |
| `make down-demo` | 停止 demo 栈（含 worker/scheduler/observability）——**up-demo 后必用** |
| `make up-observability` | 仅启动 OTEL/Prometheus/Grafana（不含 app） |
| `make down-observability` | 停止 observability 栈 |
| `make down` | 停止并移除容器（**数据卷保留**） |
| `make down-v` | 停止并移除容器 + **删除所有数据卷** |
| `make test` | 运行后端 pytest 健康检查测试 |

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
ALLOW_LIVE_SIDE_EFFECTS=true    # 显式授权
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
