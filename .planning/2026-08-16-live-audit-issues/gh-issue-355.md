<!-- ShadowTrace live quality audit FIX-002；main@d524a16f；CODE_CONFIRMED；CI system-test -->

### 类型

Bug 修复（10 并发调查租约丢失 / 锁争用）

### 优先级

P0

### 当前事实

- CI `backend-system-test`：`test_ten_concurrent_events_reach_terminal_state_without_cross_talk` FAILED。
- 抛出点 [`super_agent.py:130-138`](backend/app/agents/super_agent.py)：`renewal_failed` → `InvestigationLeaseLostError`。
- 测试 [`test_concurrency_smoke.py:129-131`](backend/tests/system/test_concurrency_smoke.py) `asyncio.gather` **无** `return_exceptions`：一路失败会取消其余。
- 租约 [`lease.py`](backend/app/orchestration/lease.py)：`DEFAULT_LEASE_TTL_S=600`，`RENEW_INTERVAL_S=60`。LLM 是 `FailingLLMClient()`，调查应短，**TTL 不够不是主叙事**。历史同测还打过 `DeadlockDetectedError`。
- `EventLease.renew`：Redis 不可用时 **直接 return False**。`start_renewal` 把 `ok is False` 一律当成「租约被偷」并 `on_renewal_failed.set()`。瞬时 Redis None / 网络毛刺与真丢失无法区分。
- 单事件租约丢失 fail-closed **是有意的**，不要吞。坏的是 10 路互相打死 / gather 放大。

同 run 的 `backend-test` cancelled **不是**本测 `needs` 连带，见 ISSUE-356。

### 目标

10 并发调查能到终态且无串台；真丢失租约仍 fail-closed。

### 推荐修复方案（工业级）

1. 统一事务锁顺序（event / intent / outbox）；`serialization_failure` / deadlock 有限次重试。
2. `renew()` Redis 不可用：走 `start_renewal` 已有的 consecutive-error 计数，**不要**立刻当 stolen。key 缺失 / owner mismatch 才是真丢失。
3. 测试 gather 用 `return_exceptions=True`：失败仍要使该测红，但日志能分清「1/10 丢租约」还是「9/10 被取消」。
4. 续期失败只打标该 `event_id`。

### 文件范围

- `backend/app/orchestration/lease.py`
- `backend/app/agents/super_agent.py`（仅当需要把 redis-blip 与 stolen 分开）
- 事务/outbox 相关服务（锁顺序）
- `backend/tests/system/test_concurrency_smoke.py`
- 租约单测

### 验收标准

- [ ] 该测在 CI 连续绿
- [ ] 人为弄丢单事件租约仍 `InvestigationLeaseLostError`
- [ ] Redis 短暂不可用不会在第一次 renew 就整事件 fail-closed（除非超过已有 consecutive 阈值）

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/system/test_concurrency_smoke.py tests/test_orchestration/test_lease.py -q
```

### 关联

- 审计：`审计报告.md` FIX-002 / ID-BLK-004
- CI：https://github.com/munos1233/shadowtrace-/actions/runs/31917018845

### 禁止事项

- 禁止把并发数改成 1 当修复
- 禁止 xfail 该测
- 禁止加长 sleep 碰运气
- 禁止吞掉真租约丢失（取消 fail-closed）
- 禁止与 ISSUE-356 绑成「修并发就当 backend-test 绿」
