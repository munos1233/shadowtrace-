/** ApprovalCenterPage tests (ISSUE-073). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import ApprovalPage from "../../src/pages/ApprovalPage";

// Mock zustand stores
vi.mock("../../src/stores/approvalStore", () => ({
  useApprovalStore: vi.fn(),
}));

vi.mock("../../src/stores/eventStore", () => ({
  useEventStore: vi.fn(() => ({ items: [{ event_id: "evt-test" }] })),
}));

vi.mock("../../src/services/socketClient", () => ({
  socketClient: { onEvent: vi.fn(() => vi.fn()) },
}));

import { useApprovalStore } from "../../src/stores/approvalStore";

const mockStore = {
  pendingApprovals: [] as unknown[],
  loading: false,
  error: null as string | null,
  loadPendingApprovals: vi.fn(),
  approve: vi.fn(),
  reject: vi.fn(),
  startPolling: vi.fn(),
  stopPolling: vi.fn(),
};

function setStore(overrides: Partial<typeof mockStore>) {
  (useApprovalStore as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
    ...mockStore,
    ...overrides,
  });
}

describe("ApprovalPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setStore({});
  });

  it("renders page title", () => {
    render(<ApprovalPage />);
    expect(screen.getByText("审批中心")).toBeDefined();
  });

  it("shows empty state when no pending approvals", () => {
    render(<ApprovalPage />);
    expect(screen.getByText("暂无待审批动作")).toBeDefined();
  });

  it("renders approval cards for pending actions", async () => {
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
          updated_at: new Date().toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("block_ip")).toBeDefined();
    expect(screen.getByText("L4")).toBeDefined();
  });

  it("shows timed-out badge for old actions", async () => {
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
          updated_at: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("已超时")).toBeDefined();
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
          updated_at: new Date().toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("POST_VERIFY")).toBeDefined();
  });

  it("displays error alert when error is set", () => {
    setStore({ error: "Network Error" });
    render(<ApprovalPage />);
    expect(screen.getByText("Network Error")).toBeDefined();
  });
});
