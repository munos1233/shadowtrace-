/** Dev-stage auth role hints for UI gating (ISSUE-213).
 *
 * Mock/Compose maps bearer tokens via backend ``DEV_AUTH_TOKENS``. The UI cannot
 * read that env, so roles are resolved in this order:
 * 1. ``VITE_AUTH_ROLES`` (explicit override — keep in sync with the token's roles)
 * 2. Known compose/dev tokens from ``VITE_DEV_AUTH_TOKEN`` (mirrors docker-compose)
 * 3. Analyst-only when token is unknown (set ``VITE_AUTH_ROLES`` to grant approver)
 */

const APPROVER_ROLE = "approver";

/** Mirrors ``DEV_AUTH_TOKENS`` entries in infra/docker-compose.yml and .env.example. */
const KNOWN_DEV_TOKEN_ROLES: Record<string, readonly string[]> = {
  "e2e-token": ["analyst", APPROVER_ROLE],
  "bootstrap-token": [
    "analyst",
    "admin",
    APPROVER_ROLE,
    "disposition_operator",
  ],
};

function parseRoleCsv(raw: string): string[] {
  return raw
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean);
}

export function currentAuthRoles(): string[] {
  const override = import.meta.env.VITE_AUTH_ROLES?.trim();
  if (override) {
    return parseRoleCsv(override);
  }

  const token = import.meta.env.VITE_DEV_AUTH_TOKEN?.trim();
  if (token && KNOWN_DEV_TOKEN_ROLES[token]) {
    return [...KNOWN_DEV_TOKEN_ROLES[token]];
  }

  // Unknown tokens: hide promote until VITE_AUTH_ROLES explicitly grants approver.
  return ["analyst"];
}

/**
 * True when the frontend can actually determine the operator's roles.
 *
 * In production the backend resolves the principal from trusted-proxy
 * ``X-Auth-Roles`` (see backend/app/core/auth.py get_principal), which the UI
 * cannot read. In that case ``currentAuthRoles()`` falls back to ``["analyst"]``
 * and must NOT be used for hard UI gating — leave the action enabled and let the
 * backend answer with 200/403 (ISSUE-207 review). Mock/Compose stages that set
 * ``VITE_AUTH_ROLES`` or a known ``VITE_DEV_AUTH_TOKEN`` do know the roles.
 */
export function hasKnownAuthRoles(): boolean {
  // Only the single-token dev/compose mode pins roles to one principal. In
  // trusted-proxy production the bundle-wide VITE_AUTH_ROLES / VITE_DEV_AUTH_TOKEN
  // cannot represent the per-request principal (backend get_principal prefers
  // X-Auth-Roles), so never trust static config for hard gating there
  // (ISSUE-207 review). Deployments must not set VITE_AUTH_ROLES in production.
  const token = import.meta.env.VITE_DEV_AUTH_TOKEN?.trim();
  return Boolean(token && KNOWN_DEV_TOKEN_ROLES[token]);
}

export function canPromoteKnowledgeReviews(): boolean {
  return currentAuthRoles().includes(APPROVER_ROLE);
}
