/** EventListPage tests — render, filters, socket updates, trigger (ISSUE-068). */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { App as AntApp } from "antd";
import type { EventListItem, EventListResponse } from "../../src/types/event";

// --- Mocks -------------------------------------------------------------

const mockListEvents = vi.fn();
const mockTriggerInvestigation = vi.fn();
const mockGetHealth = vi.fn();
const mockGetTask = vi.fn();

vi.mock("../../src/services/eventApi", () => ({
  listEvents: (...args: unknown[]) => mockListEvents(...args),
  triggerInvestigation: (...args: unknown[]) => mockTriggerInvestigation(...args),
  getHealth: (...args: unknown[]) => mockGetHealth(...args),
  getTask: (...args: unknown[]) => mockGetTask(...args),
}));

// Capture socket handler so tests can emit synthetic events.
let socketHandler: ((evt: unknown) => void) | undefined;
const mockSocketConnect = vi.fn();
const mockSocketDisconnect = vi.fn();
const mockSocketSubscribe = vi.fn();
const mockSocketIsConnected = { current: true };

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: () => mockSocketConnect(),
    ensureGlobalRoom: () => mockSocketConnect(),
    disconnect: () => mockSocketDisconnect(),
    subscribe: (id: string) => mockSocketSubscribe(id),
    onEvent: (h: (evt: unknown) => void) => {
      socketHandler = h;
      return () => {
        socketHandler = undefined;
      };
    },
    get isConnected() {
      return mockSocketIsConnected.current;
    },
  },
}));

// Suppress the global error toast from apiClient interceptor during tests.
vi.mock("../../src/services/apiClient", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/services/apiClient")
  >("../../src/services/apiClient");
  return {
    ...actual,
    showApiErrorToast: () => {},
    setApiErrorToastHandler: () => {},
  };
});

// --- Fixtures ----------------------------------------------------------

function makeItem(over: Partial<EventListItem> = {}): EventListItem {
  return {
    event_id: "evt-1",
    event_type: "account_anomaly",
    title: "Suspicious login",
    status: "new",
    severity: "high",
    risk_score: 65,
    final_verdict: "none",
    writeback_required: false,
    writeback_readiness: "not_required",
    writeback_overall_status: null,
    pending_writeback_count: 0,
    created_at: "2026-07-20T08:00:00Z",
    updated_at: null,
    occurred_at: null,
    ...over,
  };
}

function listResponse(items: EventListItem[], total?: number): EventListResponse {
  return {
    items,
    total: total ?? items.length,
    page: 1,
    page_size: 20,
  };
}

function renderPage(initialPath = "/events") {
  return render(
    <AntApp>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/events" element={<EventListPage />} />
          <Route path="/events/:eventId" element={<div>detail</div>} />
        </Routes>
      </MemoryRouter>
    </AntApp>,
  );
}

// Lazy import after mocks are registered.
let EventListPage: typeof import("../../src/pages/EventListPage").default;
beforeEach(async () => {
  ({ default: EventListPage } = await import("../../src/pages/EventListPage"));
});

describe("EventListPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockListEvents.mockResolvedValue({ data: listResponse([makeItem()]) });
    mockGetHealth.mockResolvedValue({
      data: { investigation: { orchestration_mode: "graph", full_loop_available: true } },
    });
    mockTriggerInvestigation.mockResolvedValue({
      data: {
        event_id: "evt-1",
        status: "triaging",
        task_id: "evt-1",
      },
    });
    mockGetTask.mockResolvedValue({
      data: { task_id: "task-celery-1", state: "STARTED", event_id: "evt-1" },
    });
    mockSocketIsConnected.current = true;
    socketHandler = undefined;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders events from mocked API", async () => {
    renderPage();
    // Wait for list to load
    await waitFor(() => expect(mockListEvents).toHaveBeenCalled());
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();
    expect(screen.getByText("evt-1")).toBeInTheDocument();
  });

  it("passes filter params to listEvents", async () => {
    renderPage(
      "/events?status=closed&severity=critical&event_type=account_anomaly&page=2&page_size=10",
    );
    await waitFor(() => {
      expect(mockListEvents).toHaveBeenCalledWith(
        expect.objectContaining({
          status: "closed",
          severity: "critical",
          event_type: "account_anomaly",
          page: 2,
          page_size: 10,
        }),
      );
    });
  });

  it("updates filter when event_type changed", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderPage();
    await waitFor(() => expect(mockListEvents).toHaveBeenCalled());

    const typeSelect = screen.getByTestId("filter-event-type");
    await user.click(within(typeSelect).getByRole("combobox"));
    await waitFor(() => {
      expect(screen.getByText("主机入侵", { exact: true })).toBeInTheDocument();
    });
    await user.click(screen.getByText("主机入侵", { exact: true }));

    await waitFor(() => {
      expect(mockListEvents).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: "host_compromise", page: 1 }),
      );
    });
  });

  it("updates filter when severity changed", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderPage();
    await waitFor(() => expect(mockListEvents).toHaveBeenCalled());

    // Open severity filter
    const severitySelect = screen.getByTestId("filter-severity");
    await user.click(within(severitySelect).getByRole("combobox"));
    // click the "紧急" option
    await waitFor(() => {
      expect(screen.getByText("紧急", { exact: true })).toBeInTheDocument();
    });
    await user.click(screen.getByText("紧急", { exact: true }));

    // Should call listEvents with severity=critical and page reset to 1
    await waitFor(() => {
      expect(mockListEvents).toHaveBeenLastCalledWith(
        expect.objectContaining({ severity: "critical", page: 1 }),
      );
    });
  });

  it("updates filter when status changed", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderPage();
    await waitFor(() => expect(mockListEvents).toHaveBeenCalled());

    const statusSelect = screen.getByTestId("filter-status");
    await user.click(within(statusSelect).getByRole("combobox"));
    await waitFor(() => {
      expect(screen.getByText("待审批", { exact: true })).toBeInTheDocument();
    });
    await user.click(screen.getByText("待审批", { exact: true }));

    await waitFor(() => {
      expect(mockListEvents).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: "waiting_approval", page: 1 }),
      );
    });
  });

  it("inserts a new row on event_created socket event", async () => {
    renderPage();
    await waitFor(() => expect(mockListEvents).toHaveBeenCalled());
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    // Emit a synthetic event_created
    expect(socketHandler).toBeDefined();
    socketHandler?.({
      type: "event_created",
      event_id: "evt-new",
      payload: {
        event_id: "evt-new",
        severity: "critical",
        event_type: "host_compromise",
        created_at: "2026-07-26T10:00:00Z",
      },
    });

    await waitFor(() => {
      expect(screen.getByText("evt-new")).toBeInTheDocument();
    });
  });

  it("updates local status in place on state_change", async () => {
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();
    // Initially shows "新建"
    expect(screen.getByText("新建")).toBeInTheDocument();

    socketHandler?.({
      type: "state_change",
      event_id: "evt-1",
      payload: { from_status: "new", to_status: "triaging" },
    });

    await waitFor(() => {
      expect(screen.getByText("研判中")).toBeInTheDocument();
    });
  });

  it("shows unsynced hints when state_change marks CLOSED external_unsynced", async () => {
    const item = makeItem({
      status: "reporting",
      writeback_required: true,
      writeback_overall_status: "pending",
    });
    mockListEvents.mockResolvedValue({ data: listResponse([item]) });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    socketHandler?.({
      type: "state_change",
      event_id: "evt-1",
      payload: {
        from_status: "reporting",
        to_status: "closed",
        external_unsynced: true,
      },
    });

    await waitFor(() => {
      expect(screen.getAllByText("本地已关/外部未确认").length).toBeGreaterThan(0);
    });
  });

  it("updates writeback badge on writeback_updated", async () => {
    const item = makeItem({
      writeback_required: true,
      writeback_overall_status: "pending",
    });
    mockListEvents.mockResolvedValue({ data: listResponse([item]) });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();
    expect(screen.getByText("待发送")).toBeInTheDocument();

    socketHandler?.({
      type: "writeback_updated",
      event_id: "evt-1",
      payload: {
        disposition_id: "disp-1",
        writeback_id: "wb-1",
        status: "CONFIRMED",
      },
    });

    // After CONFIRMED with no readback evidence -> "已同步（弱证据）"
    await waitFor(() => {
      expect(screen.getByText("已同步（弱证据）")).toBeInTheDocument();
    });
  });

  it("calls triggerInvestigation and moves row to TRIAGING", async () => {
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const btn = screen.getByTestId("trigger-investigation-evt-1");
    await user.click(btn);
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    // ISSUE-206/204: the report-generation toggle defaults OFF, and checking
    // it sends generate_report=true to the investigate API.
    const toggle = screen.getByTestId("investigate-generate-report");
    expect(toggle).not.toBeChecked();
    await user.click(toggle);
    expect(toggle).toBeChecked();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() =>
      expect(mockTriggerInvestigation).toHaveBeenCalledWith("evt-1", {
        includeResponseExecution: false,
        generateReport: true,
      }),
    );
    await waitFor(() => {
      expect(screen.getByText("研判中")).toBeInTheDocument();
    });
  });

  it("shows in-progress hint on 409 investigation_in_progress", async () => {
    const { ApiError } = await import("../../src/services/apiClient");
    mockTriggerInvestigation.mockRejectedValueOnce(
      new ApiError({
        error_code: "investigation_in_progress",
        error_message: "Already in progress",
      }),
    );
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() =>
      expect(mockTriggerInvestigation).toHaveBeenCalledWith("evt-1", {
        includeResponseExecution: false,
        generateReport: false,
      }),
    );
    // Warning hint should appear
    await waitFor(() => {
      expect(screen.getByText(/已在研判流程中/)).toBeInTheDocument();
    });
    // Dedicated branch only — the catch fallback must not fire a second toast.
    expect(screen.queryByText("Already in progress")).not.toBeInTheDocument();
  });

  it("shows warning toast on 409 conflict", async () => {
    const { ApiError } = await import("../../src/services/apiClient");
    mockTriggerInvestigation.mockRejectedValueOnce(
      new ApiError({ error_code: "conflict", error_message: "Conflict" }),
    );
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() => {
      expect(screen.getByText(/已在研判流程中/)).toBeInTheDocument();
    });
    // Dedicated branch only — the catch fallback must not fire a second toast.
    expect(screen.queryByText("Conflict")).not.toBeInTheDocument();
  });

  it("shows dedicated error toast on full_loop_unavailable", async () => {
    const { ApiError } = await import("../../src/services/apiClient");
    mockTriggerInvestigation.mockRejectedValueOnce(
      new ApiError({
        error_code: "full_loop_unavailable",
        error_message: "analysis_only mode",
      }),
    );
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() => {
      expect(screen.getByText(/analysis_only 模式/)).toBeInTheDocument();
    });
    expect(screen.queryByText("analysis_only mode")).not.toBeInTheDocument();
  });

  it("shows error toast with backend message on 503 task_unavailable", async () => {
    const { ApiError } = await import("../../src/services/apiClient");
    mockTriggerInvestigation.mockRejectedValueOnce(
      new ApiError({
        error_code: "task_unavailable",
        error_message: "Task unavailable",
      }),
    );
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() => {
      expect(screen.getByText("Task unavailable")).toBeInTheDocument();
    });
  });

  it("shows fallback toast on unknown error_code", async () => {
    const { ApiError } = await import("../../src/services/apiClient");
    mockTriggerInvestigation.mockRejectedValueOnce(
      new ApiError({
        error_code: "unknown_error",
        error_message: "",
      }),
    );
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    // Empty backend message -> falls back to error_code.
    await waitFor(() => {
      expect(screen.getByText("unknown_error")).toBeInTheDocument();
    });
  });

  it("shows fallback toast on unexpected non-API error", async () => {
    mockTriggerInvestigation.mockRejectedValueOnce(new Error("boom"));
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByText("开始调查"));

    await waitFor(() => {
      expect(screen.getByText("调查触发失败")).toBeInTheDocument();
    });
  });

  it("triggers full-loop investigation when selected", async () => {
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    await user.click(screen.getByTestId("investigate-mode-full-loop"));
    await user.click(screen.getByText("开始调查"));

    await waitFor(() =>
      expect(mockTriggerInvestigation).toHaveBeenCalledWith("evt-1", {
        includeResponseExecution: true,
        generateReport: false,
      }),
    );
  });

  it("disables full-loop option when deployment is analysis_only", async () => {
    mockGetHealth.mockResolvedValue({
      data: {
        investigation: {
          orchestration_mode: "analysis_only",
          full_loop_available: false,
        },
      },
    });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    const fullLoop = screen.getByTestId("investigate-mode-full-loop");
    expect(fullLoop).toBeDisabled();
  });

  it("shows approval policy version in investigate modal", async () => {
    mockGetHealth.mockResolvedValue({
      data: {
        investigation: {
          orchestration_mode: "graph",
          full_loop_available: true,
          approval_policy_version: "issue109_v1",
          auto_response_enabled: true,
        },
      },
    });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    expect(await screen.findByTestId("investigate-mode-modal")).toBeInTheDocument();
    expect(screen.getByTestId("investigation-policy-version")).toHaveTextContent(
      "issue109_v1",
    );
    expect(screen.getByTestId("investigation-policy-version")).toHaveTextContent(
      "自动响应已启用",
    );
  });

  it("disables trigger button when event already in-progress", async () => {
    const item = makeItem({ status: "triaging" });
    mockListEvents.mockResolvedValue({ data: listResponse([item]) });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();
    const btn = screen.getByTestId("trigger-investigation-evt-1") as HTMLButtonElement;
    expect(btn).toBeDisabled();
  });

  it("disables trigger button when event is waiting for approval", async () => {
    const item = makeItem({ status: "waiting_approval" });
    mockListEvents.mockResolvedValue({ data: listResponse([item]) });
    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();
    const btn = screen.getByTestId("trigger-investigation-evt-1") as HTMLButtonElement;
    expect(btn).toBeDisabled();
  });

  it("polls listEvents when socket stays disconnected", async () => {
    mockSocketIsConnected.current = false;
    renderPage();
    await waitFor(() => expect(mockListEvents).toHaveBeenCalledTimes(1));

    await vi.advanceTimersByTimeAsync(5_000);
    await vi.advanceTimersByTimeAsync(10_000);

    await waitFor(() => expect(mockListEvents.mock.calls.length).toBeGreaterThan(1));
  });

  it("tracks celery task_id/intent_id and polls GET /tasks in celery mode", async () => {
    mockGetHealth.mockResolvedValue({
      data: {
        investigation: {
          orchestration_mode: "graph",
          full_loop_available: true,
          task_mode: "celery",
        },
      },
    });
    mockTriggerInvestigation.mockResolvedValue({
      data: {
        event_id: "evt-1",
        status: "new",
        task_id: "task-celery-1",
        intent_id: "iin-evt-1",
      },
    });
    mockGetTask
      .mockResolvedValueOnce({
        data: { task_id: "task-celery-1", state: "STARTED", event_id: "evt-1" },
      })
      .mockResolvedValue({
        data: { task_id: "task-celery-1", state: "SUCCESS", event_id: "evt-1" },
      });

    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    await user.click(screen.getByText("开始调查"));

    await waitFor(() =>
      expect(mockTriggerInvestigation).toHaveBeenCalledWith("evt-1", {
        includeResponseExecution: false,
        generateReport: false,
      }),
    );
    expect(await screen.findByTestId("celery-task-evt-1")).toHaveTextContent(
      "Celery PENDING",
    );

    await vi.advanceTimersByTimeAsync(3_000);
    await waitFor(() => expect(mockGetTask).toHaveBeenCalledWith("task-celery-1"));
    await waitFor(() =>
      expect(screen.getByTestId("celery-task-evt-1")).toHaveTextContent("Celery STARTED"),
    );

    await vi.advanceTimersByTimeAsync(3_000);
    await waitFor(() =>
      expect(screen.getByTestId("celery-task-evt-1")).toHaveTextContent("Celery SUCCESS"),
    );
  });

  it("does not poll celery tasks in background task_mode", async () => {
    mockGetHealth.mockResolvedValue({
      data: {
        investigation: {
          orchestration_mode: "graph",
          full_loop_available: true,
          task_mode: "background",
        },
      },
    });
    mockTriggerInvestigation.mockResolvedValue({
      data: {
        event_id: "evt-1",
        status: "triaging",
        task_id: "task-bg-1",
        intent_id: "iin-evt-1",
      },
    });

    renderPage();
    expect(await screen.findByText("Suspicious login")).toBeInTheDocument();

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByTestId("trigger-investigation-evt-1"));
    await user.click(screen.getByText("开始调查"));

    await waitFor(() => expect(mockTriggerInvestigation).toHaveBeenCalled());
    expect(screen.queryByTestId("celery-task-evt-1")).not.toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(6_000);
    expect(mockGetTask).not.toHaveBeenCalled();
  });
});
