import { test, expect } from "@playwright/test";

const EVENT_ID = "evt-todo-e2e";

const DETAIL_FIXTURE = {
  event: {
    event_id: EVENT_ID,
    event_type: "account_anomaly",
    title: "Todo bar e2e event",
    description: "analysis complete without report",
    status: "reporting",
    severity: "high",
    risk_score: 72,
    confidence: 0.88,
    final_verdict: "confirmed_threat",
    entities: {
      accounts: [],
      hosts: [],
      ips: [],
      domains: [],
      processes: [],
      files: [],
    },
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
    updated_at: "2026-08-05T08:05:00Z",
    closed_at: null,
    replan_count: 0,
    degraded_flags: ["llm_degraded"],
    escalated: false,
    external_unsynced: false,
    row_version: 1,
    event_context_snapshot: {
      evidence_output: {
        evidence_list: [],
        conflicts: [
          {
            conflict_id: "conf-e2e-1",
            event_id: EVENT_ID,
            description: "severity mismatch across sources",
            evidence_ids: ["ev-1", "ev-2"],
            sources: ["endpoint"],
          },
        ],
        gaps: [{ gap_id: "gap-1", description: "missing endpoint logs", sources: ["endpoint"] }],
        success_sources: [],
        failed_sources: [],
        overall_confidence: 0.5,
        collection_status: "partial",
      },
    },
  },
  writeback_required: true,
  writeback_readiness: "ready",
  writeback_overall_status: null,
  pending_writeback_count: 0,
  analysis_only_complete: true,
  next_recommended_action: "none",
  phase_message: "分析已完成，请生成报告。",
  execution_substate: null as string | null,
};

const CLOSE_READY_FIXTURE = {
  ...DETAIL_FIXTURE,
  next_recommended_action: "close",
  event: {
    ...DETAIL_FIXTURE.event,
    event_context_snapshot: {
      ...DETAIL_FIXTURE.event.event_context_snapshot,
      report: { report_id: EVENT_ID, summary: "ready to close" },
    },
  },
};

const UNKNOWN_ACTION_FIXTURE = {
  action_id: "act-unknown-e2e",
  event_id: EVENT_ID,
  action_name: "block_ip",
  action_category: "response",
  tool_name: "mock_tool",
  status: "unknown",
  target: "198.51.100.44",
  execution_owner: "xdr_managed",
  execution_phase: "immediate",
  created_at: "2026-08-05T08:03:00Z",
  updated_at: "2026-08-05T08:03:00Z",
};

function isEventDetailUrl(url: URL): boolean {
  return new RegExp(`/api/v1/events/${EVENT_ID}/?$`).test(url.pathname);
}

async function mockEventDetailApis(
  page: import("@playwright/test").Page,
  detailFixture: typeof DETAIL_FIXTURE = DETAIL_FIXTURE,
  options: { unknownAction?: boolean } = {},
) {
  await page.route(
    (url) => isEventDetailUrl(new URL(url)),
    async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(detailFixture),
        });
        return;
      }
      await route.fallback();
    },
  );

  const emptyList = { total: 0, page: 1, page_size: 100, items: [] };

  await page.route("**/api/v1/events/*/actions**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        options.unknownAction
          ? { total: 1, page: 1, page_size: 100, items: [UNKNOWN_ACTION_FIXTURE] }
          : emptyList,
      ),
    });
  });

  await page.route("**/api/v1/actions/*/resolve-unknown**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        action_id: UNKNOWN_ACTION_FIXTURE.action_id,
        status: "success",
        message: "resolved",
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
        entries: [
          {
            entry_id: "trace-1",
            entry_type: "agent_execution",
            timestamp: "2026-08-05T08:04:00Z",
            actor: "RiskAgent",
            title: "Risk assessment",
            detail: {
              structured_conclusion: "高风险登录",
              evidence_refs: ["ev-1"],
              rules_applied: ["R-1"],
              model_name: "risk-model",
              confidence: 0.9,
            },
            ref_id: null,
          },
        ],
        missing_sources: [],
        summary: {
          agent_count: 1,
          tool_call_count: 0,
          llm_call_count: 0,
          total_tokens: 0,
        },
      }),
    });
  });

  await page.route("**/api/v1/events/*/trajectory**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        event_id: EVENT_ID,
        total_steps: 1,
        agent_invocations: 1,
        tool_calls: 0,
        llm_calls: 0,
        metrics: {},
        findings: [],
        insufficient_trace: false,
      }),
    });
  });
}

test.describe("ISSUE-210 · event todo bar", () => {
  test("shows todos, operational insights, and audit deep-link", async ({ page }) => {
    await mockEventDetailApis(page);
    await page.goto(`/events/${EVENT_ID}`);

    await expect(page.getByTestId("event-todo-bar")).toBeVisible();
    await expect(page.getByText("待生成报告")).toBeVisible();
    await expect(page.getByText("证据冲突（1）")).toBeVisible();
    await expect(page.getByTestId("event-operational-insights")).toBeVisible();
    await expect(page.getByTestId("event-degraded-flags")).toContainText("llm_degraded");
    await expect(page.getByText("分析已完成，请生成报告。")).toBeVisible();

    await page.getByTestId("todo-nav-decision-basis").click();
    await expect(page).toHaveURL(new RegExp(`#audit$`));
    await expect(page.getByText("高风险登录")).toBeVisible();
  });

  test("submits close from todo bar", async ({ page }) => {
    let closeCalled = false;
    await mockEventDetailApis(page, CLOSE_READY_FIXTURE);
    await page.route("**/api/v1/events/*/close**", async (route) => {
      closeCalled = true;
      const body = route.request().postDataJSON() as { reason?: string };
      expect(body.reason).toBeTruthy();
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ event_id: EVENT_ID, status: "closed" }),
      });
    });

    await page.goto(`/events/${EVENT_ID}`);
    await expect(page.getByTestId("event-close-button")).toBeEnabled();
    await page.getByTestId("event-close-button").click();
    await page.getByRole("button", { name: "确认结案" }).click();
    await expect.poll(() => closeCalled).toBe(true);
  });

  test("disables resolve-unknown for non-admin e2e token and shows role hint", async ({
    page,
  }) => {
    await mockEventDetailApis(page, {
      ...DETAIL_FIXTURE,
      execution_substate: "manual_resolution",
      event: { ...DETAIL_FIXTURE.event, status: "executing_response" },
    }, { unknownAction: true });

    await page.goto(`/events/${EVENT_ID}`);
    await expect(page.getByText("写回待处理")).toBeVisible();
    const resolveButton = page.getByTestId("event-resolve-unknown-button");
    await expect(resolveButton).toBeVisible();
    // Default E2E_AUTH_TOKEN / e2e-token has analyst+approver, not admin.
    await expect(resolveButton).toBeDisabled();
    await expect(page.getByText("裁决 UNKNOWN 需 admin 角色")).toBeVisible();
  });
});
