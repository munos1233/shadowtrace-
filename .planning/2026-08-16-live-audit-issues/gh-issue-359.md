<!-- ShadowTrace live quality audit FIX-008；main@d524a16f；CODE_CONFIRMED；Live glm 12 actions -->

### 类型

质量债（单次审批面过大；需讨论身份工具去重）

### 优先级

P2·需讨论

### 当前事实

- Live glm-5.2 full_loop 一轮批准 **12** 个动作：identity 三件套（disable + force_logout + `revoke_token` L4）+ 双 isolate + 双 scan + quarantine + block 域/IP。ISSUE-328 merge **额外**补了模型不想要的 DB isolate。
- Mock XDR 全 success，**不代表** live 变更窗口可审 12 条。
- 这不是状态机 bug。328 必需的 WKS/DB isolate **必须留下**。

### 需要确认的合同

推荐默认：

1. 同一 account 的 disable / force_logout / revoke_token **去重为一条身份遏制链**（保留 disable；L4 revoke 默认要单独批注或降为可选）。
2. 不限制 isolate_host 数量（EntitySet 有几台隔几台）。
3. 不把「动作总数 ≤ N」写成硬门（会和 328 覆盖打架）。

### 目标

本场景身份动作 ≤2；isolate 仍覆盖 WKS+DB。

### 推荐修复方案（工业级）

1. Response 质量门或 policy filter：同一 `target` account 上，若已有 `disable_account`，则丢掉重复的 `force_logout` / `revoke_token`，或把后两者标为 `activation_condition` / 单独审批批注。
2. 单测：计划含三件套时 merge 后身份工具 ≤2；EntitySet 两台 host 仍都有 isolate。
3. 不改 CLOSED 门、不改 328 覆盖函数。

### 文件范围

- `backend/app/agents/rules/response_plan_quality_gate.py` 或 policy filter
- 对应单测
- 可选：`response_prompt.py` 一句「同一账号不要叠满 L3+L4」

### 验收标准

- [ ] 本对抗场景身份动作 ≤2
- [ ] isolate 仍覆盖 EntitySet 全部 host
- [ ] 诱饵仍不出现

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_response_plan_quality_gate.py -q
```

### 关联

- 审计：`审计报告.md` FIX-008
- ISSUE-328 / 本批 ISSUE-357（覆盖优先于少动作）

### 禁止事项

- 禁止为少动作删 isolate WKS/DB
- 禁止把「总数 ≤5」写成覆盖门
- 禁止改 `validate_closed_gate`
