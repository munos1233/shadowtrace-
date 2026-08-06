/** ApprovalCenterPage tests (ISSUE-073 / ISSUE-207). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import ApprovalPage from "../../src/pages/ApprovalPage";
import { ApiError } from "../../src/services/apiClient";

const { mockIsActionTimedOut, mockLoadRevisionProgress } = vi.hoisted(() => ({
  mockIsActionTimedOut: vi.fn(() => false),
  mockLoadRevisionProgress: vi.fn(async () => new Map()),
}));

vi.mock("../../src/stores/approvalStore", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/stores/approvalStore")>();
  return {
    ...actual,
    useApprovalStore: vi.fn(),
    loadRevisionProgress: mockLoadRevisionProgress,
    isActionTimedOut: mockIsActionTimedOut,
  };
});

import { useApprovalStore } from "../../src/stores/approvalStore";

const mockStore = {
  pendingApprovals: [] as unknown[],
  eventPendingApprovals: [] as unknown[],
  loading: false,
  error: null as string | null,
  eventLoading: false,
  eventError: null as string | null,
  approvalDeadlines: {} as Record<string, string>,
  loadPendingApprovals: vi.fn(async () => "ok"),
  loadPendingApprovalsForEvent: vi.fn(async () => "ok"),
  clearEventScope: vi.fn(),
  refreshEventIds: vi.fn(async () => ["evt-test"]),
  approve: vi.fn(),
  reject: vi.fn(),
};

function setStore(overrides: Partial<typeof mockStore>) {
  (useApprovalStore as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
    ...mockStore,
    ...overrides,
  });
}

function renderPage(initialPath = "/approvals") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <ApprovalPage />
    </MemoryRouter>,
  );
}

describe("ApprovalPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsActionTimedOut.mockReturnValue(false);
    mockLoadRevisionProgress.mockResolvedValue(new Map());
    setStore({});
  });

  it("renders page title", () => {
    renderPage();
    expect(screen.getByText("审批中心")).toBeDefined();
  });

  it("shows empty state with guidance on how approvals are produced", () => {
    renderPage();
    expect(screen.getByText("暂无待审批动作")).toBeDefined();
    expect(screen.getByText("前往事件看板发起调查")).toBeDefined();
    expect(
      screen.getByText(/仅「分析」调查不会产生待审批动作/),
    ).toBeDefined();
  });

  it("renders the scoped event's actions for ?event_id= and shows the filter hint", async () => {
    mockLoadRevisionProgress.mockResolvedValue(new Map());
    setStore({
      eventPendingApprovals: [
        {
          action_id: "act-a",
          event_id: "evt-a",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
      // A different event exists in the global queue — the deep link must not
      // render it (ISSUE-207 review: scoped state is isolated).
      pendingApprovals: [
        {
          action_id: "act-b",
          event_id: "evt-b",
          action_name: "isolate_host",
          tool_name: "isolate_host",
          action_level: "l4",
          execution_phase: "immediate",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });

    renderPage("/approvals?event_id=evt-a");
    expect(screen.getByTestId("approval-event-filter-hint")).toHaveTextContent(
      "仅显示事件 evt-a 的待审批动作",
    );
    expect(screen.getByText("block_ip")).toBeDefined();
    expect(screen.queryByText("isolate_host")).not.toBeInTheDocument();
    // Flush the async revision-progress effect so no act(...) warning leaks.
    await waitFor(() => expect(mockLoadRevisionProgress).toHaveBeenCalled());
  });

  it("deep link queries the target event directly (bypasses 200-event page limit)", async () => {
    renderPage("/approvals?event_id=evt-deep");

    // ISSUE-207 review fix: with ?event_id= the page must not rely on the global
    // first-200-events board, but fetch that event's waiting actions directly.
    await waitFor(() =>
      expect(mockStore.loadPendingApprovalsForEvent).toHaveBeenCalledWith("evt-deep"),
    );
    expect(mockStore.refreshEventIds).not.toHaveBeenCalled();
  });

  it("deep-link empty state follows scoped loading, not the global poll", async () => {
    // Global poll idle but scoped request still in flight -> no empty state yet.
    setStore({ eventLoading: true, loading: false, eventPendingApprovals: [] });
    renderPage("/approvals?event_id=evt-a");
    expect(screen.queryByText("该事件暂无待审批动作")).not.toBeInTheDocument();

    // Scoped idle while the global poll is still loading -> empty state shown.
    setStore({ eventLoading: false, loading: true, eventPendingApprovals: [] });
    renderPage("/approvals?event_id=evt-a");
    expect(screen.getByText("该事件暂无待审批动作")).toBeDefined();
  });

  it("reloads the queue when approve hits approval_decision_conflict", async () => {
    const user = userEvent.setup();
    setStore({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-test",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });
    mockStore.approve.mockRejectedValueOnce(
      new ApiError({
        error_code: "approval_decision_conflict",
        error_message: "already decided",
      }),
    );

    renderPage();
    await user.click(screen.getByText("批准", { exact: true }));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      (await screen.findAllByText("该审批已由其他审批者处理，已刷新最新状态。")).length,
    ).toBeGreaterThan(0);
    await waitFor(() =>
      expect(mockStore.refreshEventIds).toHaveBeenCalled(),
    );
    await waitFor(() =>
      expect(mockStore.loadPendingApprovals).toHaveBeenCalled(),
    );
  });

  it("deep-link 409 refreshes the scoped event, not the global queue", async () => {
    const user = userEvent.setup();
    setStore({
      eventPendingApprovals: [
        {
          action_id: "act-deep",
          event_id: "evt-deep",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });
    mockStore.approve.mockRejectedValueOnce(
      new ApiError({
        error_code: "approval_decision_conflict",
        error_message: "already decided",
      }),
    );

    renderPage("/approvals?event_id=evt-deep");
    await user.click(screen.getByText("批准", { exact: true }));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    // Scoped refresh keeps the remaining actions of the target event instead of
    // swapping to the global first-200-events board (ISSUE-207 review).
    expect(
      (await screen.findAllByText("该审批已由其他审批者处理，已刷新最新状态。")).length,
    ).toBeGreaterThan(0);
    await waitFor(() =>
      expect(mockStore.loadPendingApprovalsForEvent).toHaveBeenCalledWith("evt-deep"),
    );
    expect(mockStore.refreshEventIds).not.toHaveBeenCalled();
    expect(mockStore.loadPendingApprovals).not.toHaveBeenCalled();
  });

  it("renders approval cards and revision progress", async () => {
    mockLoadRevisionProgress.mockResolvedValue(
      new Map([
        [
          "evt-test:1",
          { eventId: "evt-test", planRevision: 1, decided: 1, total: 3 },
        ],
      ]),
    );
    setStore({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-test",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          execution_owner: "xdr_managed",
          target: "10.0.0.1",
          target_type: "ip",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });

    renderPage();
    expect(screen.getByText("block_ip")).toBeDefined();
    expect(screen.getByText("L4")).toBeDefined();
    await waitFor(() => {
      expect(screen.getByText(/本 revision 已决出 1\/3/)).toBeDefined();
    });
  });

  it("shows timed-out badge for old actions", async () => {
    mockIsActionTimedOut.mockReturnValue(true);
    setStore({
      pendingApprovals: [
        {
          action_id: "act-old",
          event_id: "evt-test",
          action_name: "isolate_host",
          tool_name: "isolate_host",
          action_level: "l4",
          execution_phase: "immediate",
          execution_owner: "direct_tool",
          target: "host-1",
          target_type: "host",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
        },
      ],
    });

    renderPage();
    expect(screen.getByText("已超时")).toBeDefined();
    // Flush the async revision-progress effect so no act(...) warning leaks.
    await waitFor(() => expect(mockLoadRevisionProgress).toHaveBeenCalled());
  });

  it("shows deferred action tag", async () => {
    setStore({
      pendingApprovals: [
        {
          action_id: "act-def",
          event_id: "evt-test",
          action_name: "update_disposition",
          tool_name: "update_disposition",
          action_level: "l2",
          execution_phase: "post_verify",
          execution_owner: "xdr_managed",
          target: null,
          target_type: null,
          status: "waiting_approval",
          plan_revision: 2,
          updated_at: new Date().toISOString(),
        },
      ],
    });

    renderPage();
    expect(screen.getByText("POST_VERIFY")).toBeDefined();
    // Flush the async revision-progress effect so no act(...) warning leaks.
    await waitFor(() => expect(mockLoadRevisionProgress).toHaveBeenCalled());
  });

  it("displays error alert when error is set", () => {
    setStore({ error: "Network Error" });
    renderPage();
    expect(screen.getByText("Network Error")).toBeDefined();
  });

  it("shows 403 permission hint when approve is forbidden by backend", async () => {
    const user = userEvent.setup();
    setStore({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-test",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });
    mockStore.approve.mockRejectedValueOnce(
      new ApiError({ error_code: "forbidden", error_message: "requires one of roles: approver" }),
    );

    renderPage();
    await user.click(screen.getByText("批准", { exact: true }));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      await screen.findByText("无审批权限（403）：需要 approver 角色，请联系管理员授权。"),
    ).toBeDefined();
  });
});
