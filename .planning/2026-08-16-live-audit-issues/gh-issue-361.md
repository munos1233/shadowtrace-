<!-- ShadowTrace live quality audit FIX-009；main@d524a16f；CODE_CONFIRMED；328/339 dest-only 有意；glm 过封源 -->

### 类型

质量债（模型封 VPN 源 IP；覆盖门故意不要求封源；需讨论 prompt）

### 优先级

P2·需讨论

### 当前事实

- Live glm 对 `198.51.100.44` 发了 `block_ip`，reason 正确写 **source**（不是 ISSUE-327 把源标成 dest）。
- 328/339 覆盖门 [`_block_ip_coverage_entities`](backend/app/agents/rules/response_plan_quality_gate.py) **故意跳过** `_BLOCK_IP_SOURCE_FIELDS`，只要求封外网 dest。dest `198.51.100.77` + 域 `storage-sync-cdn.example` 应封。
- **门是对的**（不把 VPN 出口当 exfil dest 一起封，误伤更小）。不要改覆盖合同。
- **坏处大的是模型行为**：生产封 VPN 源会锁出口，误伤面大于封 dest。

### 需要确认的合同

推荐默认：

1. 覆盖门保持 dest-only（328/339）。
2. prompt / policy：默认只 block 外网 **dest**；源 IP 需显式才封。身份路径用 disable_account。
3. 不把封源写进 EntitySet 覆盖需求。

### 目标

glm 不再把 VPN 源与 exfil dest 一起封；dest + 域仍封。

### 推荐修复方案（工业级）

1. [`response_prompt.py`](backend/app/agents/prompts/response_prompt.py) 增加：`block_ip` 仅用于 exfil/C2 **destination**；不要 block VPN/source egress IP，除非用户/规则显式要求。
2. 可选 policy filter：`block_ip` 且 `normalized_field` 属于 source 字段时降级或丢弃（保留 dest）。**禁止**靠 reason 子串 `"destination"` 过滤。
3. 不改 `_block_ip_coverage_entities`。

### 文件范围

- `backend/app/agents/prompts/response_prompt.py`
- 可选：policy filter / response 规则
- 对应单测

### 验收标准

- [ ] 覆盖门仍不要求封源
- [ ] prompt 明确 dest-only
- [ ] 339：仍不封 RFC1918

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_response_plan_quality_gate.py tests/test_agents/test_response_agent.py -q
```

### 关联

- 审计：`审计报告.md` FIX-009
- ISSUE-327 / 339 / 328

### 禁止事项

- 禁止把「封源」写进 328 覆盖需求
- 禁止靠 reason 子串 `"destination"` 过滤
- 禁止为了少动作删 dest `block_ip` / `block_domain`
