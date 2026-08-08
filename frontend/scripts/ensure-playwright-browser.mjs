#!/usr/bin/env node
/**
 * Install + validate Playwright Chromium for the current runtime (ISSUE-286).
 *
 * Usage:
 *   node scripts/ensure-playwright-browser.mjs            # install if needed
 *   node scripts/ensure-playwright-browser.mjs --report   # JSON report only
 *   node scripts/ensure-playwright-browser.mjs --check    # validate, no install
 */
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildPlatformReport,
  resolveBrowserCachePath,
  resolveHostPlatform,
  runPlaywrightInstall,
  unsupportedPlatformMessage,
  validateChromiumInstall,
} from "./playwright-platform.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

const args = new Set(process.argv.slice(2));
const reportOnly = args.has("--report");
const checkOnly = args.has("--check");

function linuxWithDepsArgs() {
  return process.platform === "linux" ? ["--with-deps"] : [];
}

function buildInstallEnv() {
  const cache = resolveBrowserCachePath(process.env);
  const host = resolveHostPlatform(process.platform, process.arch, process.env);
  /** @type {Record<string, string>} */
  const env = { ...process.env, PLAYWRIGHT_BROWSERS_PATH: cache.path };
  if (host.source !== "override") {
    env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE = host.hostPlatform;
  }
  return { env, cache, host };
}

function writeReport(report) {
  const outDir = path.join(frontendRoot, "e2e", "platform-artifacts");
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "playwright-platform-report.json");
  writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  return outPath;
}

function main() {
  const unsupported = unsupportedPlatformMessage(
    resolveHostPlatform(process.platform, process.arch, process.env),
  );
  if (unsupported) {
    console.error(`[playwright-platform] ${unsupported}`);
    process.exit(2);
  }

  if (reportOnly) {
    const report = buildPlatformReport(process.env);
    const outPath = writeReport(report);
    console.log(JSON.stringify(report, null, 2));
    console.log(`[playwright-platform] report written to ${outPath}`);
    process.exit(report.chromium.ok ? 0 : 1);
  }

  const { env, cache, host } = buildInstallEnv();
  console.log(
    `[playwright-platform] cache=${cache.path} (${cache.source}) host=${host.hostPlatform} arch=${host.runtimeArch}`,
  );

  let validation = validateChromiumInstall(cache.path);
  if (!checkOnly && !validation.ok) {
    console.log("[playwright-platform] installing chromium …");
    runPlaywrightInstall(frontendRoot, env, linuxWithDepsArgs());
    validation = validateChromiumInstall(cache.path);
  }

  const report = buildPlatformReport({ ...process.env, ...env });
  const outPath = writeReport(report);

  if (!validation.ok) {
    console.error(`[playwright-platform] ${validation.message}`);
    console.error(`[playwright-platform] report: ${outPath}`);
    process.exit(1);
  }

  console.log(`[playwright-platform] ${validation.message}`);
  console.log(`[playwright-platform] report: ${outPath}`);
}

main();
