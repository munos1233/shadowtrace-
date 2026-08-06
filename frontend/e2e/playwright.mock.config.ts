/** Playwright config for UI-only e2e with mocked API (no backend seed). */
import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_BASE_URL =
  process.env.E2E_FRONTEND_URL ?? "http://127.0.0.1:5173";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

export default defineConfig({
  testDir: path.join(__dirname, "tests"),
  testMatch: [
    "**/knowledge-review.spec.ts",
    "**/event-todo-bar.spec.ts",
    "**/event-detail-approval.spec.ts",
  ],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  outputDir: path.join(__dirname, "test-results"),
  webServer: {
    command: "corepack pnpm dev",
    url: FRONTEND_BASE_URL,
    reuseExistingServer: true,
    timeout: 60_000,
    env: {
      // ISSUE-207 inline approval: single-token dev mode with a KNOWN dev token
      // makes hasKnownAuthRoles() true (roles = analyst+approver), so the e2e
      // exercises the real known-role path (config/auth.ts).
      VITE_DEV_AUTH_TOKEN: "e2e-token",
    },
  },
  use: {
    baseURL: FRONTEND_BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    extraHTTPHeaders: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
    },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
