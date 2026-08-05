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
  testMatch: ["**/knowledge-review.spec.ts", "**/event-todo-bar.spec.ts"],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  outputDir: path.join(__dirname, "test-results"),
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
