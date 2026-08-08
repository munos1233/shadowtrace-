/**
 * Playwright host platform + browser cache resolution (ISSUE-286).
 *
 * Playwright picks macOS arm64 browsers from CPU model even when Node runs as
 * x64 (Rosetta / Cursor sandbox). Install and run must target process.arch.
 * Cursor Agent may redirect PLAYWRIGHT_BROWSERS_PATH to an empty sandbox cache;
 * fall back to the user cache when the sandbox path has no browser binaries.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** @typedef {{ hostPlatform: string, runtimeArch: string, osPlatform: string, source: "override" | "runtime" | "unsupported", officiallySupported: boolean }} HostPlatformResolution */

/** @typedef {{ path: string, source: "env" | "cursor-sandbox-fallback" | "default", cursorSandbox: boolean }} BrowserCacheResolution */

const CURSOR_SANDBOX_MARKER = "cursor-sandbox-cache";

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function detectCursorSandbox(env = process.env) {
  const browsersPath = env.PLAYWRIGHT_BROWSERS_PATH ?? "";
  return browsersPath.includes(CURSOR_SANDBOX_MARKER);
}

/**
 * @param {string} cacheRoot
 * @returns {boolean}
 */
export function cacheContainsChromium(cacheRoot) {
  if (!cacheRoot || !existsSync(cacheRoot)) {
    return false;
  }
  try {
    for (const entry of readdirSync(cacheRoot)) {
      if (entry.startsWith("chromium") || entry.startsWith("chromium_headless_shell")) {
        return true;
      }
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string}
 */
export function defaultBrowserCachePath(env = process.env) {
  if (env.PLAYWRIGHT_BROWSERS_PATH && !detectCursorSandbox(env)) {
    return env.PLAYWRIGHT_BROWSERS_PATH;
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Caches", "ms-playwright");
  }
  if (process.platform === "win32") {
    const localAppData = env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
    return path.join(localAppData, "ms-playwright");
  }
  return path.join(os.homedir(), ".cache", "ms-playwright");
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {BrowserCacheResolution}
 */
export function resolveBrowserCachePath(env = process.env) {
  const configured = env.PLAYWRIGHT_BROWSERS_PATH?.trim();
  const cursorSandbox = detectCursorSandbox(env);

  if (configured && !cursorSandbox) {
    return { path: configured, source: "env", cursorSandbox: false };
  }

  if (configured && cursorSandbox && cacheContainsChromium(configured)) {
    return { path: configured, source: "env", cursorSandbox: true };
  }

  const fallback = defaultBrowserCachePath(env);
  if (configured && cursorSandbox) {
    return {
      path: fallback,
      source: "cursor-sandbox-fallback",
      cursorSandbox: true,
    };
  }

  return { path: fallback, source: "default", cursorSandbox: false };
}

/**
 * Mirror Playwright hostPlatform.ts macOS major version selection.
 * @param {string} platform
 * @returns {string}
 */
export function macOsPlaywrightBase(platform = process.platform) {
  if (platform !== "darwin") {
    return "";
  }
  const ver = os.release().split(".").map((part) => parseInt(part, 10));
  if (Number.isNaN(ver[0])) {
    return "mac13";
  }
  if (ver[0] < 18) {
    return "mac10.13";
  }
  if (ver[0] === 18) {
    return "mac10.14";
  }
  if (ver[0] === 19) {
    return "mac10.15";
  }
  const lastStable = 15;
  return `mac${Math.min(ver[0] - 9, lastStable)}`;
}

/**
 * Resolve Playwright host platform from runtime arch (not CPU marketing name).
 * @param {string} [platform]
 * @param {string} [arch]
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {HostPlatformResolution}
 */
export function resolveHostPlatform(
  platform = process.platform,
  arch = process.arch,
  env = process.env,
) {
  const override = env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE?.trim();
  if (override) {
    return {
      hostPlatform: override,
      runtimeArch: arch,
      osPlatform: platform,
      source: "override",
      officiallySupported: false,
    };
  }

  if (platform === "darwin") {
    const base = macOsPlaywrightBase(platform);
    const hostPlatform = arch === "arm64" ? `${base}-arm64` : base;
    return {
      hostPlatform,
      runtimeArch: arch,
      osPlatform: platform,
      source: "runtime",
      officiallySupported: true,
    };
  }

  if (platform === "linux") {
    if (!["x64", "arm64"].includes(arch)) {
      return {
        hostPlatform: "<unknown>",
        runtimeArch: arch,
        osPlatform: platform,
        source: "unsupported",
        officiallySupported: false,
      };
    }
    return {
      hostPlatform: `ubuntu24.04-${arch}`,
      runtimeArch: arch,
      osPlatform: platform,
      source: "runtime",
      officiallySupported: true,
    };
  }

  if (platform === "win32") {
    if (arch !== "x64") {
      return {
        hostPlatform: "<unknown>",
        runtimeArch: arch,
        osPlatform: platform,
        source: "unsupported",
        officiallySupported: false,
      };
    }
    return {
      hostPlatform: "win64",
      runtimeArch: arch,
      osPlatform: platform,
      source: "runtime",
      officiallySupported: true,
    };
  }

  return {
    hostPlatform: "<unknown>",
    runtimeArch: arch,
    osPlatform: platform,
    source: "unsupported",
    officiallySupported: false,
  };
}

/**
 * @param {HostPlatformResolution} resolution
 * @returns {string | null}
 */
export function unsupportedPlatformMessage(resolution) {
  if (resolution.source !== "unsupported") {
    return null;
  }
  return (
    `Unsupported Playwright runtime: os=${resolution.osPlatform} arch=${resolution.runtimeArch}. ` +
    "ShadowTrace UI e2e supports darwin (x64/arm64), linux (x64/arm64), and win32 x64. " +
    "See docs/platform-support-matrix.md."
  );
}

/**
 * @param {string} cacheRoot
 * @returns {string[]}
 */
export function listChromiumCacheDirs(cacheRoot) {
  if (!existsSync(cacheRoot)) {
    return [];
  }
  return readdirSync(cacheRoot).filter(
    (entry) => entry.startsWith("chromium") || entry.startsWith("chromium_headless_shell"),
  );
}

/**
 * @param {string} cacheRoot
 * @returns {{ ok: boolean, message: string, dirs: string[] }}
 */
export function validateChromiumInstall(cacheRoot) {
  const dirs = listChromiumCacheDirs(cacheRoot);
  if (dirs.length === 0) {
    return {
      ok: false,
      message:
        `No Chromium browser cache under ${cacheRoot}. Run: pnpm run test:e2e:install`,
      dirs,
    };
  }
  return {
    ok: true,
    message: `Chromium cache present (${dirs.join(", ")})`,
    dirs,
  };
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Record<string, unknown>}
 */
export function buildPlatformReport(env = process.env) {
  const cache = resolveBrowserCachePath(env);
  const host = resolveHostPlatform(process.platform, process.arch, env);
  const validation = validateChromiumInstall(cache.path);
  return {
    issue: "ISSUE-286",
    collectedAt: new Date().toISOString(),
    node: process.version,
    process: {
      platform: process.platform,
      arch: process.arch,
      cwd: process.cwd(),
    },
    environment: {
      CI: env.CI ?? "",
      CURSOR_AGENT: env.CURSOR_AGENT ?? "",
      PLAYWRIGHT_BROWSERS_PATH: env.PLAYWRIGHT_BROWSERS_PATH ?? "",
      PLAYWRIGHT_HOST_PLATFORM_OVERRIDE: env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE ?? "",
    },
    browserCache: cache,
    hostPlatform: host,
    chromium: validation,
    unsupportedMessage: unsupportedPlatformMessage(host),
  };
}

/**
 * @param {string} frontendRoot
 * @param {Record<string, string>} env
 * @param {string[]} extraArgs
 */
export function runPlaywrightInstall(frontendRoot, env, extraArgs = []) {
  execFileSync("pnpm", ["exec", "playwright", "install", "chromium", ...extraArgs], {
    cwd: frontendRoot,
    env,
    stdio: "inherit",
  });
}
