/**
 * ISSUE-286: Playwright platform/cache resolution guards.
 */
import { describe, expect, it } from "vitest";

import {
  buildPlatformReport,
  cacheContainsChromium,
  detectCursorSandbox,
  macOsPlaywrightBase,
  resolveBrowserCachePath,
  resolveHostPlatform,
  unsupportedPlatformMessage,
} from "../../scripts/playwright-platform.mjs";

describe("playwright platform resolution (ISSUE-286)", () => {
  it("detects Cursor sandbox browser cache redirect", () => {
    expect(
      detectCursorSandbox({
        PLAYWRIGHT_BROWSERS_PATH: "/tmp/cursor-sandbox-cache/abc/playwright",
      }),
    ).toBe(true);
    expect(detectCursorSandbox({ PLAYWRIGHT_BROWSERS_PATH: "/home/user/.cache/ms-playwright" })).toBe(
      false,
    );
  });

  it("falls back from empty Cursor sandbox cache to default user cache", () => {
    const resolved = resolveBrowserCachePath({
      PLAYWRIGHT_BROWSERS_PATH: "/tmp/cursor-sandbox-cache/empty/playwright",
    });
    expect(resolved.cursorSandbox).toBe(true);
    expect(resolved.source).toBe("cursor-sandbox-fallback");
    expect(resolved.path).not.toContain("cursor-sandbox-cache");
  });

  it("uses runtime arch for macOS host platform (not Apple CPU marketing name)", () => {
    const arm = resolveHostPlatform("darwin", "arm64", {});
    expect(arm.hostPlatform.endsWith("-arm64")).toBe(true);

    const x64 = resolveHostPlatform("darwin", "x64", {});
    expect(x64.hostPlatform.includes("-arm64")).toBe(false);
  });

  it("maps linux x64 to ubuntu24.04-x64", () => {
    const linux = resolveHostPlatform("linux", "x64", {});
    expect(linux.hostPlatform).toBe("ubuntu24.04-x64");
    expect(linux.officiallySupported).toBe(true);
  });

  it("honours PLAYWRIGHT_HOST_PLATFORM_OVERRIDE", () => {
    const overridden = resolveHostPlatform("linux", "x64", {
      PLAYWRIGHT_HOST_PLATFORM_OVERRIDE: "mac13-arm64",
    });
    expect(overridden.hostPlatform).toBe("mac13-arm64");
    expect(overridden.source).toBe("override");
  });

  it("reports unsupported linux architectures", () => {
    const bad = resolveHostPlatform("linux", "ppc64", {});
    expect(bad.source).toBe("unsupported");
    expect(unsupportedPlatformMessage(bad)).toMatch(/platform-support-matrix/);
  });

  it("builds a platform report with chromium validation section", () => {
    const report = buildPlatformReport({});
    expect(report.issue).toBe("ISSUE-286");
    expect(report.hostPlatform).toBeTruthy();
    expect(report.chromium).toHaveProperty("ok");
    expect(report.browserCache).toHaveProperty("path");
  });

  it("derives a macOS playwright base version token", () => {
    const base = macOsPlaywrightBase("darwin");
    expect(base.startsWith("mac")).toBe(true);
    expect(base.includes("-arm64")).toBe(false);
  });

  it("treats missing cache roots as empty chromium installs", () => {
    expect(cacheContainsChromium("/tmp/shadowtrace-no-such-playwright-cache")).toBe(false);
  });
});
