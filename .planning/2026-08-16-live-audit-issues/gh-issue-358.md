<!-- ShadowTrace live quality audit FIX-005；main@d524a16f；CODE_CONFIRMED；Live glm-5.2 两路 degraded_template -->

### 类型

Bug 修复（ReportAgent LLM 缺一节就整份回模板）

### 优先级

P1

### 当前事实

- ISSUE-212：`generated_by=template` → 永远 `degraded_template`。这是诚实降级，**不要改评分器**。
- 图内 ReportAgent **已注入** `llm_client`。成功路径会 `generated_by=llm`，212 即可 `complete`。
- Live AnalysisOnly + full_loop 产物均为 `report_quality=degraded_template`；摘录是模板 `decision_brief` 腔 → LLM 路径没有成功。
- [`report_agent.py:448-460`](backend/app/agents/report_agent.py)：在 `_merge_sections` **之前**要求 LLM JSON 覆盖全部 15 个 [`SECTION_KEYS`](backend/app/agents/report_section_builder.py)。缺一节 `raise LLMError("report_generate LLM returned too few sections")` → except 回模板。merge 根本走不到。
- prompt [`report_prompt.py`](backend/app/agents/prompts/report_prompt.py) 已列出 15 个 required keys；glm 漏 `appendix_index` 一类小节就会整份降级。
- pytest stdout 未必出现 `ReportAgent LLM path failed`（logger 配置），不能用「没看到 warning」否定。

**坏处大：** Live 全闭环无法展示 complete 报告。212 合同本身好处≥坏处；本 issue 修的是「缺一节就丢掉全部 LLM 章节」。

### 目标

LLM 写出的章节能 merge 进模板草稿；核心节齐全时 `generated_by=llm` 从而 212 给 `complete`。缺节时仍可诚实 template，不要改 212。

### 推荐修复方案（工业级）

1. `_generate_with_llm`：**不要**因 `len(parsed) < 15` 整次失败。返回已解析的节（可为空）。
2. `execute`：先 `_merge_sections(draft, llm_sections)`，再决定 `generated_by`：核心节（至少 overview / executed_actions / verification_results，与 212 complete 合同对齐）有实质内容 → `llm`，否则 template + `warnings` 含 `report_llm_fallback:partial_sections`。
3. JSON 根本不是 object / chat 抛错：仍回模板（现有 except）。`SoftTimeLimitExceeded` 仍 re-raise（ISSUE-314）。
4. 不改 [`assess_report_quality`](backend/app/services/report_quality.py)：template 仍永不 complete。

### 文件范围

- `backend/app/agents/report_agent.py`
- `backend/tests/test_agents/test_report_agent.py`
- `backend/tests/test_services/test_report_quality.py`（回归：template 仍非 complete）

### 验收标准

- [ ] LLM 返回 14/15 节时 merge 后 `generated_by=llm`（若核心节在），不是整份 template
- [ ] 纯模板路径仍 `degraded_template`
- [ ] SoftTimeLimit 仍不回落模板成功
- [ ] 对抗/Live 同类路径有机会 `report_quality=complete`，或 warnings 可见 `report_llm_fallback:*`

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_report_agent.py tests/test_services/test_report_quality.py -q
```

### 关联

- 审计：`审计报告.md` FIX-005
- ISSUE-212 / #750（评分器不改）
- ISSUE-348（图内 upsert 不跑 HTTP 212 门，不在本 issue 范围）
- ISSUE-314（soft-limit 不回落模板成功）

### 禁止事项

- 禁止 `template` + 完整章节 → `complete`（打 212）
- 禁止把 HTTP 212 变成 CLOSED 硬门（312/348）
- 禁止对抗把 `report_quality_complete` 做成 CLOSED 计分
- 禁止为 complete 恢复 CoT `reasoning`
