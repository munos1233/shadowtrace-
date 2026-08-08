# Platform support matrix (ISSUE-286)

Audit baseline: `main@9e09029` · release audit `ID-DEMO-002` · status **SUSPECTED until matrix artifacts are collected on each target host**.

This document records **observed** compatibility for ShadowTrace demo DX tooling (Docker BuildKit builds and Playwright UI e2e). It does not change runtime product semantics.

## Summary

| Dimension | Supported (verified path) | Limited / suspected | Unsupported |
|-----------|---------------------------|---------------------|-------------|
| Workspace checkout path | ASCII-only paths (control) | Non-ASCII path segments (e.g. `副本`) — upstream BuildKit header limits | — |
| Playwright runtime | Linux x64 (GitHub Actions, native Linux) | macOS arm64 native Node; Cursor Agent sandbox (cache redirect + arch skew) | Linux non-x64/arm64; Windows ARM |
| Playwright test mode | `pnpm test:e2e:mock` (UI-only, 4 specs) | `pnpm test:e2e` (full stack, manual CI job) | — |
| Docker BuildKit | Enabled (`DOCKER_BUILDKIT=1`) on ASCII checkout | Non-ASCII checkout — run smoke to confirm | Disabling BuildKit (`DOCKER_BUILDKIT=0`) — do **not** use as a fix |

## Workspace path × BuildKit

BuildKit sends file paths in HTTP headers. Paths containing non-ASCII characters may fail with errors such as **non-printable ASCII header** (observed under audit `ID-DEMO-002` when the checkout lived under a `副本` segment).

**Recommendation:** keep the repository checkout path ASCII-only for Docker builds.

**Smoke (records version + logs, never disables BuildKit):**

```bash
python scripts/smoke_docker_buildkit_paths.py
# artifact: reports/platform-matrix/buildkit-path-smoke.json
```

Interpretation:

| `verdict.status` | Meaning | Action |
|------------------|---------|--------|
| `supported` | ASCII and non-ASCII builds succeeded | Document as supported on this host |
| `suspected_upstream_limit` | ASCII OK, non-ASCII failed | Keep SUSPECTED; use ASCII checkout |
| `ascii_control_failed` | ASCII path failed | Fix Docker/install before blaming path encoding |

Related: large build context is **ISSUE-278** (`#874`) — do not substitute path-encoding workarounds for context-size fixes.

## Playwright install/run × architecture

Playwright selects macOS browser **CPU** from `os.cpus()` (Apple Silicon → `-arm64`) even when Node runs as **x64** (Rosetta or Cursor sandbox). That yields arm64 browser binaries while the runner loads x64 — browsers never launch (8 UI cases did not start in audit `ID-DEMO-002`).

ShadowTrace pins install/run to **`process.arch`** via `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE` in `frontend/scripts/ensure-playwright-browser.mjs`.

### Cursor Agent sandbox

Cursor may inject:

- `PLAYWRIGHT_BROWSERS_PATH=/tmp/cursor-sandbox-cache/.../playwright` (often empty)
- npm `devdir` warnings (harmless noise)

The install helper falls back to the user cache (`~/.cache/ms-playwright` on Linux, `~/Library/Caches/ms-playwright` on macOS) when the sandbox cache has no Chromium builds.

### Environment matrix (collect artifacts on each row)

| Environment | Runner | Expected host platform | Collect report |
|-------------|--------|------------------------|----------------|
| GitHub Actions `frontend-e2e` | `ubuntu-latest` x64 | `ubuntu24.04-x64` | CI artifact `frontend-e2e-artifacts` |
| GitHub Actions `frontend-e2e-mock` | `ubuntu-latest` x64 | `ubuntu24.04-x64` | CI artifact `frontend-e2e-mock-artifacts` |
| Native macOS arm64 | local Node arm64 | `mac*-arm64` | `pnpm run test:e2e:platform-report` |
| Cursor Agent / cloud | linux x64 | `ubuntu24.04-x64` | same report script |
| Cursor sandbox mac x64 Node | darwin + `process.arch=x64` | `mac*` (no `-arm64`) | report shows override |

Commands:

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm run test:e2e:install          # install + validate for current runtime
pnpm run test:e2e:platform-report  # JSON only
pnpm test:e2e:mock                 # UI-only mock specs (issue verification)
```

Report path: `frontend/e2e/platform-artifacts/playwright-platform-report.json`

Merged matrix (optional):

```bash
python scripts/collect_platform_matrix_report.py
# artifact: reports/platform-matrix/platform-matrix-report.json
```

## Actionable errors

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `non-printable ASCII` during `docker build` | Non-ASCII checkout path | Move clone to ASCII path; see BuildKit smoke |
| Playwright `Executable doesn't exist` under `cursor-sandbox-cache` | Empty sandbox browser cache | Run `pnpm run test:e2e:install` (auto fallback) or set `PLAYWRIGHT_BROWSERS_PATH` to user cache |
| mac arm64 binary on x64 Node | CPU-based Playwright detection | Use repo install helper (sets platform override) |
| `Unsupported Playwright runtime` | Exotic OS/arch | See supported table above |

## CI jobs (manual matrix collection)

Triggered via **Actions → ci → Run workflow** (`workflow_dispatch`):

| Job | Purpose |
|-----|---------|
| `platform-buildkit-smoke` | BuildKit ASCII vs non-ASCII path artifact |
| `frontend-e2e-mock` | Mock UI e2e + platform report (no full stack) |
| `frontend-e2e` | Full-stack Playwright (existing) + platform report |

Blocking PR pipeline jobs (`docker-build`, `frontend-build`) remain unchanged; matrix jobs are evidence collection, not merge gates.

## Definition of Done (ISSUE-286)

- [ ] ASCII/non-ASCII BuildKit artifact captured on target Docker host
- [ ] Playwright reports for native arm64, Cursor, and GitHub rows
- [ ] Install/run architecture consistent; Chromium cache validated before e2e
- [ ] Unsupported combinations documented with errors above
- [ ] Keep **SUSPECTED** until all rows have artifacts
