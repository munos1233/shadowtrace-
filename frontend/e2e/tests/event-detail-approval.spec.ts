/** ISSUE-207 e2e (mock API): inline approve in event detail with resume feedback,
 * actions-table refresh and todo-bar recompute. Runs under playwright.mock.config.ts. */

import { test, expect } from "@playwright/test";

const EVENT_ID = "evt-inline-approval";
const ACTION_ID = "act-inline";

const WAITING_ACTION = {
  action_id: ACTION_ID,
  event_id: EVENT_ID,
  action_level: "l4",
  action_category: "response",
  action_name: "block_ip",
  tool_name: "block_ip",
  execution_phase: "immediate",
  execution_owner: "xdr_managed",
  status: "waiting_approval",
  target: "198.51.100.77",
  target_type: "ip",
  parameters: {},
  updated_at: "2026-08-05T09:00:00Z",
};

const APPROVED_ACTION = {
  ...WAITING_ACTION,
  status: "approved",
  updated_at: "2026-08-05T09:05:00Z",
};

function baseDetail(status: string) {
  return {
    event: {
      event_id: EVENT_ID,
      event_type: "account_anomaly",
      title: "Inline approval e2e event",
      description: "waiting for approval",
      status,
      severity: "high",
      risk_score: 72,
      confidence: 0.88,
      final_verdict: "confirmed_threat",
      entities: { accounts: [], hosts: [], ips: [], domains: [], processes: [], files: [] },
      creation_source_ref: null,
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-05T08:00:00Z",
      created_at: "2026-08-05T08:01:00Z",
      updated_at: "2026-08-05T09:05:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {},
    },
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: null,
    pending_writeback_count: 0,
    analysis_only_complete: false,
    next_recommended_action: "none",
    phase_message: null,
    execution_substate: null as string | null,
  };
}

const DETAIL_WAITING = baseDetail("waiting_approval");
const DETAIL_EXECUTING = baseDetail("executing_response");

const emptyList = { total: 0, page: 1, page_size: 100, items: [] };

test.describe("ISSUE-207 · inline approval in event detail", () => {
  test("approves inline, shows resume feedback, refreshes actions and todo bar", async ({
    page,
  }) => {
    let approveCalled = false;
    // Mirrors backend state: once approved, refetches return approved/executing.
    let decided = false;
    let actionsCalls = 0;

    const isEventDetailUrl = (url: URL) =>
      new RegExp(`/api/v1/events/${EVENT_ID}/?$`).test(url.pathname);

    await page.route((url) => isEventDetailUrl(new URL(url)), async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(decided ? DETAIL_EXECUTING : DETAIL_WAITING),
        });
        return;
      }
      await route.fallback();
    });

    await page.route("**/api/v1/events/*/actions**", async (route) => {
      actionsCalls += 1;
      const items = decided ? [APPROVED_ACTION] : [WAITING_ACTION];
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ total: items.length, page: 1, page_size: 100, items }),
      });
    });

    await page.route("**/api/v1/actions/*/approve**", async (route) => {
      approveCalled = true;
      decided = true;
      const body = route.request().postDataJSON() as { decision_id?: string };
      expect(body.decision_id).toBeTruthy();
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          action_id: ACTION_ID,
          status: "approved",
          decision_id: body.decision_id,
          message: "approved",
          resume_status: "ok",
          degraded: false,
        }),
      });
    });

    await page.route("**/api/v1/events/*/dispositions**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ event_id: EVENT_ID, items: [] }),
      });
    });
    await page.route("**/api/v1/events/*/traces**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyList),
      });
    });
    await page.route("**/api/v1/connectors**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ items: [] }),
      });
    });
    await page.route("**/api/v1/knowledge/reviews**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ total: 0, items: [] }),
      });
    });
    await page.route("**/api/v1/events/*/decision-trace**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: EVENT_ID,
          entries: [],
          missing_sources: [],
          summary: {},
        }),
      });
    });
    await page.route("**/api/v1/events/*/trajectory**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: EVENT_ID,
          total_steps: 0,
          agent_invocations: 0,
          tool_calls: 0,
          llm_calls: 0,
          metrics: {},
          findings: [],
          insufficient_trace: false,
        }),
      });
    });

    await page.goto(`/events/${EVENT_ID}#actions`);

    // Response actions live under the 安全处置 sub-tab.
    await page.getByRole("tab", { name: /安全处置/ }).click();

    // waiting_approval row exposes inline 批准/拒绝 (ISSUE-207).
    const approveButton = page.getByTestId(`approve-action-${ACTION_ID}`);
    await expect(approveButton).toBeVisible();
    await expect(page.getByTestId(`reject-action-${ACTION_ID}`)).toBeVisible();

    // Todo bar surfaces the approval CTA before deciding.
    await expect(page.getByText("待审批处置")).toBeVisible();

    await approveButton.click();
    const dialog = page.getByRole("dialog", { name: "批准动作" });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: /批\s*准/ }).click();

    // Same API contract as the approval center (POST /actions/{id}/approve).
    await expect.poll(() => approveCalled).toBe(true);

    // resume_status=ok feedback surfaced to the operator.
    await expect(
      page.getByText("动作 act-inline 已批准，调查流程已继续"),
    ).toBeVisible();

    // Actions table was re-fetched and the row is no longer waiting_approval.
    await expect.poll(() => actionsCalls).toBeGreaterThan(1);
    await expect(page.getByText("approved")).toBeVisible();
    await expect(page.getByTestId(`approve-action-${ACTION_ID}`)).toHaveCount(0);

    // Todo bar recomputed: approval CTA gone after the event left waiting_approval.
    await expect(page.getByText("待审批处置")).toHaveCount(0);
  });
});
