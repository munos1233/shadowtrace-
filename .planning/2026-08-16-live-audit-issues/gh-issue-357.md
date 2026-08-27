<!-- ShadowTrace live quality audit FIX-003；main@d524a16f；CODE_CONFIRMED；Live glm-5.2 full_loop；ISSUE-328 已合入 -->

### 类型

质量债（审批叙事与已执行 isolate 打架；需讨论 prompt 口径）

### 优先级

P1·需讨论

### 当前事实

- ISSUE-328 覆盖门已合入：[`apply_containment_quality_gate`](backend/app/agents/rules/response_plan_quality_gate.py) 不再「有任意遏制即 return」；[`_merge_entity_coverage`](backend/app/agents/rules/response_plan_quality_gate.py) 只补 EntitySet 的 host/account/外网 **dest** IP。本 Live：`strict_aligned=true`，WKS+DB 均 isolate，诱饵 `BACKUP-SRV-01` 未入计划。
- glm 自己 isolate 了 WKS；DB 的 `isolate_host(SRV-DB-STG-02)` reason 是 **`rule fallback`**（门优先拷贝规则池候选，合成 reason `"entity coverage merge"` 只在无规则池匹配时使用）。strategy 仍写 **「SRV-DB-STG-02 remains online pending investigation」**，末尾才 `; containment_quality_gate: entity_coverage_merge`。
- Response system prompt [`response_prompt.py:87-97`](backend/app/agents/prompts/response_prompt.py)：`Prefer lower-risk actions first.` 有意保守。user payload 已有 `risk_severity`。
- **328 门是对的，不要拆。** 坏处大的是审批/报告会读到「库继续在线」却已 isolate。

### 需要确认的合同

推荐默认（实现前按此执行，产品可改）：

1. 覆盖仍由 328 门保证；不要求「模型单独 isolate DB 才算闭环」。
2. prompt 要求隔离的是 **EntitySet hosts**，不是资产库存每一台、不是诱饵。
3. coverage merge 之后，strategy 不得再声称某台已被 isolate 的主机 remains online。

### 目标

审批看到的 strategy 与最终计划中的 isolate 目标一致；328 覆盖与诱饵合同不回潮。

### 推荐修复方案（工业级）

1. prompt 增加：`confirmed_threat` 时每个 EntitySet host 应有 `isolate_host`；允许先低风险，但不得省略已识别失陷主机。
2. `_merge_entity_coverage` / `apply_containment_quality_gate`：若 `coverage_added`，在 strategy 后追加 **已 isolate 的主机列表**（从最终 candidates 收集 `isolate_host` target）。若原文含 `remains online` / `leave … online` 且该 host 已在 isolate 列表，删掉或改写该分句。
3. 回归：LLM 只 isolate WKS 时 merge 后仍有 DB；strategy 含 DB isolate 事实；`BACKUP-SRV-01` 仍不出现。

### 文件范围

- `backend/app/agents/prompts/response_prompt.py`
- `backend/app/agents/rules/response_plan_quality_gate.py`
- `backend/tests/test_agents/test_response_plan_quality_gate.py`
- prompt 夹具（若有）

### 验收标准

- [ ] 再跑对抗场景：strategy 不写 DB remains online（或明确列出 DB 已被 isolate）
- [ ] 诱饵仍不在计划
- [ ] 328 merge 行为不变（缺 EntitySet host 仍补 isolate）

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_response_plan_quality_gate.py tests/test_agents/test_response_agent.py -q
```

### 关联

- 审计：`审计报告.md` FIX-003 / §2.2
- 已合入：#959（ISSUE-328）

### 禁止事项

- 禁止拆掉 328 merge / 恢复「任意遏制即放行」
- 禁止把 isolate 塞进 `validate_closed_gate`（ISSUE-312）
- 禁止对资产库存 / 诱饵盲扩 isolate
- 禁止为少动作删 WKS/DB isolate（与 ISSUE-359 冲突时，以本 issue 的覆盖为准）
