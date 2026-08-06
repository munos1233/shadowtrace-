/** Auth role hint tests (ISSUE-213). */

import { afterEach, describe, expect, it, vi } from "vitest";

describe("config/auth", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("uses VITE_AUTH_ROLES override when set", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst"]);
    expect(canPromoteKnowledgeReviews()).toBe(false);
  });

  it("derives roles from known VITE_DEV_AUTH_TOKEN when roles unset", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst", "approver"]);
    expect(canPromoteKnowledgeReviews()).toBe(true);
  });

  it("maps bootstrap-token to compose roles", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "bootstrap-token");
    const { currentAuthRoles } = await import("../../src/config/auth");
    expect(currentAuthRoles()).toContain("approver");
    expect(currentAuthRoles()).toContain("admin");
  });

  it("defaults unknown dev token to analyst-only", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "custom-analyst-token");
    const { currentAuthRoles, canPromoteKnowledgeReviews } = await import(
      "../../src/config/auth"
    );
    expect(currentAuthRoles()).toEqual(["analyst"]);
    expect(canPromoteKnowledgeReviews()).toBe(false);
  });

  it("hasKnownAuthRoles: known dev token pins roles (single-token mode)", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const { hasKnownAuthRoles } = await import("../../src/config/auth");
    expect(hasKnownAuthRoles()).toBe(true);
  });

  it("hasKnownAuthRoles: unknown dev token is not trusted", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "custom-analyst-token");
    const { hasKnownAuthRoles } = await import("../../src/config/auth");
    expect(hasKnownAuthRoles()).toBe(false);
  });

  it("hasKnownAuthRoles: VITE_AUTH_ROLES alone is not trusted (trusted-proxy production)", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "");
    const { hasKnownAuthRoles } = await import("../../src/config/auth");
    // A bundle-wide build-time override cannot represent the per-request
    // trusted-proxy principal — must not hard-disable (ISSUE-207 review).
    expect(hasKnownAuthRoles()).toBe(false);
  });

  it("hasKnownAuthRoles: no auth env at all is not trusted", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "");
    const { hasKnownAuthRoles } = await import("../../src/config/auth");
    expect(hasKnownAuthRoles()).toBe(false);
  });
});
