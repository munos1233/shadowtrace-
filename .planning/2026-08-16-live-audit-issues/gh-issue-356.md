<!-- ShadowTrace live quality audit FIX-010；main@d524a16f；CODE_CONFIRMED；CI backend-test timeout -->

### 类型

Bug 修复（CI `backend-test` 墙钟不够，默认套件跑不完）

### 优先级

P0

### 当前事实

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) `backend-test`：`timeout-minutes: 35`。注释写 suite-only ~20m、p95 给 35m。
- run `31917018845` job `95090484406`：00:21:53 → 00:57:06（~35min）。步骤「Pytest with coverage (ISSUE-267)」：`The operation was canceled.`
- **无** `junit-default.xml` / `coverage.xml` 工件；覆盖率门、timing、random-retest 都没走到。
- 该 job **没有** `needs: backend-system-test`。concurrency `cancel-in-progress` 只取消同 ref **更早的 run**。本 run 是当时 main 最新，后面没有更新的 main run。因此 **不是** system-test 失败连带，也不是被更新 commit 取消。

### 目标

main 上默认后端套件 + 覆盖率门能跑完并上传 junit/coverage。

### 推荐修复方案（工业级）

1. 先用 `--durations` / 分段 job 分清是套件变长还是挂死（与 ISSUE-355 锁争用是否串到默认套件）。
2. **拆 job（首选）**：pytest 与 coverage/timing/random-retest 分开，各自有实测预算。
3. 若确认只是变慢：按实测 p95 加 timeout，并更新注释里过时的「~20m」。
4. 保留 coverage fail-under 门，不要为赶时间关掉。

### 文件范围

- `.github/workflows/ci.yml`
- 若拆套件：对应 pytest 调用，不改产品代码

### 验收标准

- [ ] `backend-test`（或拆后的等价 job）在 main 上 conclusion=success
- [ ] 上传 junit + coverage
- [ ] 注释中的时间预算与实测一致

### 测试与验证

CI 绿即验收。本地可：

```bash
cd backend
uv run --frozen pytest --durations=25 --durations-min=1.0 -q
```

### 关联

- 审计：`审计报告.md` FIX-010 / ID-BLK-007
- CI：https://github.com/munos1233/shadowtrace-/actions/runs/31917018845

### 禁止事项

- 禁止 skip/xfail 砍套件来「赶上 35 分钟」
- 禁止把这次 cancel 说成 system-test / evaluation 失败导致
- 禁止关掉 coverage fail-under 当修复
- 禁止无 durations 证据就盲目把 timeout 加到很大
