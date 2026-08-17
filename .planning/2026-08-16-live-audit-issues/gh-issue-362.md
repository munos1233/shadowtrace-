<!-- ShadowTrace live quality audit FIX-011；main@d524a16f；CODE_CONFIRMED；ISSUE-333 已知 skew；本环 Mock 未踩；live 坏处大 -->

### 类型

Bug 修复（Verify 弱证据档位与非 mock CLOSED 门不一致；需讨论）

### 优先级

P1·需讨论

### 当前事实

- [`verify_agent.py:1647-1655`](backend/app/agents/verify_agent.py) `_adjust_routing_for_weak_evidence`：仅当 `ConfirmationEvidence.ADAPTER_ACKNOWLEDGED` 时把 CONFIRMED 打回 recovery。`STATUS_QUERIED` **不降**。
- [`workflow.py:542-548`](backend/app/models/workflow.py) 注释已写明：ISSUE-333 非 mock CLOSED 要求强证据 `{readback_verified, manual_confirmed}`；CLOSED 还拒 `status_queried` / missing / invalid。Mock 走 ISSUE-227 simulated 宽门。
- 本环 `DISPOSITION_MODE=mock_xdr`，`certification_label=mock_simulated`，**未踩**。
- **故意：** 333 把强证据放在 CLOSED 门；Verify 尚未对齐全部弱档。
- **坏处大于好处：** 一旦非 mock，live XDR 若只给 `status_queried`，Verify 可能放行、CLOSED 门拒绝 → 调查卡在 VERIFYING，无法关单也无法自动 recovery。

### 需要确认的合同

推荐默认：

1. Verify 对非 mock：`status_queried` / missing / invalid 与 `adapter_acknowledged` 一样视为弱证据 → recovery，而不是当 CONFIRMED 往下走。
2. Mock 路径不改（227/351 认证口径）。
3. 不要为了让 live 好关而放宽 CLOSED 强证据集合。

### 目标

Verify 路由与 `CLOSED_TERMINAL_STRONG_CONFIRMATION_EVIDENCE` 同一套档位；非 mock 弱证据走 recovery 而不是撞 CLOSED 门。

### 推荐修复方案（工业级）

1. `_adjust_routing_for_weak_evidence`：若 evidence 不在 `{READBACK_VERIFIED, MANUAL_CONFIRMED}`，按弱证据打回 recovery（至少覆盖 `STATUS_QUERIED` 与 invalid）。
2. 单测：非 mock + `status_queried` → need_recovery；mock + simulated 收据仍可 CLOSED。
3. 不改 `validate_closed_gate` 的强证据集合。

### 文件范围

- `backend/app/agents/verify_agent.py`
- `backend/tests/test_agents/test_verify_agent.py`
- 可选：CLOSED 门单测回归

### 验收标准

- [ ] 非 mock `status_queried` 在 Verify 被降为 recovery
- [ ] mock 闭环仍能 CLOSED（本对抗路径不回归）
- [ ] CLOSED 门仍拒非 mock 弱证据

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_agents/test_verify_agent.py tests/test_models/test_workflow.py -q
```

### 关联

- 审计：`审计报告.md` FIX-011
- ISSUE-333 / 227 / 351

### 禁止事项

- 禁止放宽 CLOSED 门去迁就 Verify
- 禁止把本 Mock `readback_verified` 字段对外说成 live 已验证
- 禁止改 `mock_simulated` 认证口径（351）
