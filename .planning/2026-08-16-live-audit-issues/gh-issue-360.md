<!-- ShadowTrace live quality audit FIX-004；main@d524a16f；CODE_CONFIRMED；ISSUE-032 有意；坏处大故发 -->

### 类型

质量债（分诊 medium vs risk 75；032 有意但本场景坏处大；需讨论）

### 优先级

P1·需讨论

### 当前事实

- [`triage_agent.py:144-155`](backend/app/agents/triage_agent.py) ISSUE-032：`data_exfiltration` 仅当 `_external_ip_in_text(alert_text)` 才 HIGH，否则 MEDIUM。糊标题无 IP → 本 Live 分诊 **medium**，risk **74–75 high**，verdict `confirmed_threat`。330 双列对外 high。
- Response user payload **已经同时给** `severity`（triage medium）和 `risk_severity`（high）。glm strategy 开篇写 *medium-severity/high-risk*，倾向不隔 DB。把「不隔 DB」**单归因**到没读 `normalized.src_ip` **过强**。
- 032 好处：避免内部外发/糊标题被规则抬成 HIGH。330 双列对外诚实。
- **坏处大于好处（本场景）**：EntitySet/证据已有外网 IP 与 confirmed+75，分诊仍 medium。审批/截图容易只看见 medium，遏制叙事被拉低。

### 需要确认的合同

推荐默认（**不改 032 分诊枚举**）：

1. 分诊规则保持 032：HIGH 仍只认告警文本外网 IP。
2. Response prompt：遏制激进度跟 `risk_severity` / `risk_score`，不要跟 triage medium 走。
3. 若产品坚持改 032：仅当 EntitySet 已有 **外网 dest**（不是 VPN 源）时抬 HIGH——必须单独立项，会改 032 测。本 issue **不要**做这一步。

### 目标

glm 看见 HIGH 风险时按 HIGH 做遏制；对外仍并列 triage medium 与 risk high（330）。

### 推荐修复方案（工业级）

1. [`response_prompt.py`](backend/app/agents/prompts/response_prompt.py) system 增加：`When risk_severity is high or risk_score >= 65, plan containment for EntitySet hosts/accounts even if triage severity is medium.`
2. 已有 `should_flag_triage_risk_inconsistency`：确保 user payload / 报告 warnings 带上该旗标（若尚未传入 Response）。
3. 单测：prompt 夹具含上述句子；032 分诊单测 **零改动**。

### 文件范围

- `backend/app/agents/prompts/response_prompt.py`
- `backend/app/agents/response_agent.py`（仅当需要把 inconsistency 旗标放进 payload）
- prompt / response 单测
- **不要改** `triage_agent.py` 的 032 规则

### 验收标准

- [ ] ISSUE-032 分诊测仍然：无文本 IP → data_exfil MEDIUM
- [ ] Response prompt 明确跟 `risk_severity`
- [ ] 330 双列仍在报告里

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_triage_agent.py tests/test_agents/test_response_agent.py -q
```

### 关联

- 审计：`审计报告.md` FIX-004
- ISSUE-032、ISSUE-330、本批 ISSUE-357

### 禁止事项

- 禁止改 `_apply_severity_rules` 让糊标题无 IP 也 HIGH（打 032）
- 禁止用分数卡对外 severity 静默吃掉分诊
- 禁止从糊标题发明 IP
- 禁止把 VPN **源** IP 当「有外网 IP 就 HIGH」
