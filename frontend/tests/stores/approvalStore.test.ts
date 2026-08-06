/** approvalStore unit tests (ISSUE-073). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { notification } from "antd";

vi.mock("../../src/services/eventApi", () => ({
  listEvents: vi.fn(),
  listActions: vi.fn(),
  approveAction: vi.fn(),
  rejectAction: vi.fn(),
}));

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    onEvent: vi.fn(() => vi.fn()),
  },
}));

import { listEvents, listActions, approveAction, rejectAction } from "../../src/services/eventApi";
import { socketClient } from "../../src/services/socketClient";
import { useApprovalStore } from "../../src/stores/approvalStore";
import type { Action } from "../../src/types/action";
import type { SocketEvent } from "../../src/types/socket";

describe("approvalStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useApprovalStore.setState({
      pendingApprovals: [],
      loading: false,
      error: null,
      unreadCount: 0,
      approvalDeadlines: {},
      eventPendingApprovals: [],
      eventLoading: false,
      eventError: null,
      eventScope: null,
      _eventGen: 0,
      _queueGen: 0,
      _pollTimer: null,
      _globalSocketUnsub: null,
      _eventIds: [],
    });
    vi.spyOn(notification, "info").mockImplementation(() => ({}) as never);
  });

  it("loadPendingApprovals requests waiting_approval status filter", async () => {
    vi.mocked(listActions).mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          {
            action_id: "act-1",
            event_id: "evt-1",
            action_name: "block_ip",
            tool_name: "block_ip",
            action_level: "l4",
            action_category: "response",
            execution_phase: "immediate",
            status: "waiting_approval",
            parameters: {},
            updated_at: new Date().toISOString(),
          },
        ],
      },
    } as never);

    await useApprovalStore.getState().loadPendingApprovals(["evt-1"]);

    expect(listActions).toHaveBeenCalledWith("evt-1", {
      page_size: 200,
      status: "waiting_approval",
    });
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(1);
    expect(useApprovalStore.getState().error).toBeNull();
  });

  it("loadPendingApprovals reports ok/partial/failed and keeps data accordingly", async () => {
    const makeAction = (eventId: string) => ({
      action_id: `act-${eventId}`,
      event_id: eventId,
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });

    // All succeed -> ok, queue replaced.
    vi.mocked(listActions).mockImplementation((eventId: string) =>
      Promise.resolve({
        data: { total: 1, page: 1, page_size: 200, items: [makeAction(eventId)] },
      }) as never,
    );
    const okResult = await useApprovalStore.getState().loadPendingApprovals(["evt-a", "evt-b"]);
    expect(okResult).toBe("ok");
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(2);
    expect(useApprovalStore.getState().error).toBeNull();

    // Partial failure -> partial: successful event replaced, failed event's old
    // actions kept so none are silently lost (ISSUE-207 review).
    vi.mocked(listActions)
      .mockResolvedValueOnce({
        data: { total: 1, page: 1, page_size: 200, items: [makeAction("evt-a")] },
      } as never)
      .mockRejectedValueOnce(new Error("evt-b 500"));
    const partialResult = await useApprovalStore.getState().loadPendingApprovals(["evt-a", "evt-b"]);
    expect(partialResult).toBe("partial");
    const partialIds = useApprovalStore
      .getState()
      .pendingApprovals.map((a) => a.event_id)
      .sort();
    expect(partialIds).toEqual(["evt-a", "evt-b"]); // evt-b kept from before
    expect(useApprovalStore.getState().error).toContain("部分事件加载失败");

    // Total failure -> failed, previous queue kept (not wiped), error surfaced.
    vi.mocked(listActions)
      .mockRejectedValueOnce(new Error("500"))
      .mockRejectedValueOnce(new Error("500"));
    const failedResult = await useApprovalStore.getState().loadPendingApprovals(["evt-a", "evt-b"]);
    expect(failedResult).toBe("failed");
    const failedIds = useApprovalStore
      .getState()
      .pendingApprovals.map((a) => a.event_id)
      .sort();
    expect(failedIds).toEqual(["evt-a", "evt-b"]);
    expect(useApprovalStore.getState().error).toContain("全部请求失败");
  });

  it("a failed scoped re-load keeps the previous scoped actions", async () => {
    const firstAction = {
      action_id: "act-deep-1",
      event_id: "evt-deep",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    };
    vi.mocked(listActions).mockResolvedValueOnce({
      data: { total: 1, page: 1, page_size: 200, items: [firstAction] },
    } as never);
    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");
    expect(useApprovalStore.getState().eventPendingApprovals).toHaveLength(1);

    // A second load of the same event fails — old scoped items must survive.
    vi.mocked(listActions).mockRejectedValueOnce(new Error("evt-deep 500"));
    const result = await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");

    expect(result).toBe("failed");
    expect(useApprovalStore.getState().eventPendingApprovals.map((a) => a.action_id)).toEqual([
      "act-deep-1",
    ]);
    expect(useApprovalStore.getState().eventError).toContain("evt-deep 500");
  });

  it("a scope switch clears stale data but a same-scope reload keeps it", async () => {
    const makeAction = (eventId: string) => ({
      action_id: `act-${eventId}`,
      event_id: eventId,
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });
    vi.mocked(listActions).mockImplementation((eventId: string) =>
      Promise.resolve({
        data: { total: 1, page: 1, page_size: 200, items: [makeAction(eventId)] },
      }) as never,
    );

    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-a");
    expect(useApprovalStore.getState().eventScope).toBe("evt-a");

    // Same-scope reload with failure keeps evt-a items.
    vi.mocked(listActions).mockRejectedValueOnce(new Error("500"));
    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-a");
    expect(useApprovalStore.getState().eventPendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-a",
    ]);

    // Switch to evt-b clears the stale evt-a data before loading.
    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-b");
    expect(useApprovalStore.getState().eventScope).toBe("evt-b");
    expect(useApprovalStore.getState().eventPendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-b",
    ]);
  });

  it("scoped load keeps its own loading/error away from the global state", async () => {
    let resolveScoped!: (value: unknown) => void;
    vi.mocked(listActions).mockImplementation(
      (() =>
        new Promise((res) => {
          resolveScoped = res;
        })) as never,
    );

    const pending = useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");
    expect(useApprovalStore.getState().eventLoading).toBe(true);
    expect(useApprovalStore.getState().loading).toBe(false); // global untouched

    // A global poll completes while the scoped request is still in flight —
    // it must not end the scoped spinner or leak its state (ISSUE-207 review).
    vi.mocked(listActions).mockResolvedValueOnce({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);
    await useApprovalStore.getState().loadPendingApprovals(["evt-other"]);
    expect(useApprovalStore.getState().eventLoading).toBe(true);

    resolveScoped({
      data: { total: 1, page: 1, page_size: 200, items: [] },
    });
    await pending;
    expect(useApprovalStore.getState().eventLoading).toBe(false);
    expect(useApprovalStore.getState().eventScope).toBe("evt-deep");
  });

  it("scoped failure sets eventError only and clears it on clearEventScope", async () => {
    vi.mocked(listActions).mockRejectedValueOnce(new Error("evt-deep 500"));
    const result = await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");

    expect(result).toBe("failed");
    expect(useApprovalStore.getState().eventError).toContain("evt-deep 500");
    expect(useApprovalStore.getState().error).toBeNull(); // global untouched

    useApprovalStore.getState().clearEventScope();
    expect(useApprovalStore.getState().eventError).toBeNull();
    expect(useApprovalStore.getState().eventLoading).toBe(false);
    expect(useApprovalStore.getState().eventScope).toBeNull();
  });

  it("loadPendingApprovalsForEvent queries the target event directly", async () => {
    vi.mocked(listActions).mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          {
            action_id: "act-deep",
            event_id: "evt-deep",
            action_name: "block_ip",
            tool_name: "block_ip",
            action_level: "l4",
            action_category: "response",
            execution_phase: "immediate",
            status: "waiting_approval",
            parameters: {},
            updated_at: new Date().toISOString(),
          },
        ],
      },
    } as never);

    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");

    // ISSUE-207 deep link: bypasses the 200-event page limit of the global queue.
    expect(listActions).toHaveBeenCalledWith("evt-deep", {
      page_size: 200,
      status: "waiting_approval",
    });
    // Scoped result lives in eventPendingApprovals; the global queue is untouched.
    expect(useApprovalStore.getState().eventPendingApprovals).toHaveLength(1);
    expect(useApprovalStore.getState().eventPendingApprovals[0].action_id).toBe("act-deep");
    expect(useApprovalStore.getState().eventScope).toBe("evt-deep");
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });

  it("scoped load does not narrow the global queue or _eventIds", async () => {
    const globalAction = {
      action_id: "act-global",
      event_id: "evt-a",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    };
    const deepAction = {
      action_id: "act-deep",
      event_id: "evt-deep",
      action_name: "isolate_host",
      tool_name: "isolate_host",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    };

    vi.mocked(listActions).mockImplementation(
      (eventId: string) =>
        Promise.resolve({
          data: {
            total: 1,
            page: 1,
            page_size: 200,
            items:
              eventId === "evt-deep"
                ? [deepAction]
                : eventId === "evt-a"
                  ? [globalAction]
                  : [],
          },
        }) as never,
    );
    await useApprovalStore.getState().loadPendingApprovals(["evt-a", "evt-b"]);
    expect(useApprovalStore.getState()._eventIds).toEqual(["evt-a", "evt-b"]);
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-a",
    ]);

    // Deep-link load must NOT touch the global queue or polling _eventIds
    // (ISSUE-207 review blocker).
    await useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");

    expect(useApprovalStore.getState()._eventIds).toEqual(["evt-a", "evt-b"]);
    expect(useApprovalStore.getState().eventScope).toBe("evt-deep");
    expect(useApprovalStore.getState().eventPendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-deep",
    ]);
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-a",
    ]);
  });

  it("clearEventScope invalidates an in-flight scoped load", async () => {
    let resolveList!: (value: unknown) => void;
    vi.mocked(listActions).mockImplementation(
      (() =>
        new Promise((res) => {
          resolveList = res;
        })) as never,
    );

    const pending = useApprovalStore.getState().loadPendingApprovalsForEvent("evt-deep");
    useApprovalStore.getState().clearEventScope();
    resolveList({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          {
            action_id: "act-deep",
            event_id: "evt-deep",
            action_name: "block_ip",
            tool_name: "block_ip",
            action_level: "l4",
            execution_phase: "immediate",
            status: "waiting_approval",
            parameters: {},
            updated_at: new Date().toISOString(),
          },
        ],
      },
    });
    await pending;

    // The response arrived after the scope was cleared — it must be dropped.
    expect(useApprovalStore.getState().eventScope).toBeNull();
    expect(useApprovalStore.getState().eventPendingApprovals).toHaveLength(0);
  });

  it("a stale scoped response is dropped when a newer scope supersedes it", async () => {
    let resolveFirst!: (value: unknown) => void;
    vi.mocked(listActions)
      .mockImplementationOnce(
        (() =>
          new Promise((res) => {
            resolveFirst = res;
          })) as never,
      )
      .mockResolvedValueOnce({
        data: {
          total: 1,
          page: 1,
          page_size: 200,
          items: [
            {
              action_id: "act-b",
              event_id: "evt-b",
              action_name: "block_ip",
              tool_name: "block_ip",
              action_level: "l4",
              execution_phase: "immediate",
              status: "waiting_approval",
              parameters: {},
              updated_at: new Date().toISOString(),
            },
          ],
        },
      } as never);

    const first = useApprovalStore.getState().loadPendingApprovalsForEvent("evt-a");
    const second = useApprovalStore.getState().loadPendingApprovalsForEvent("evt-b");
    resolveFirst({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          {
            action_id: "act-a",
            event_id: "evt-a",
            action_name: "block_ip",
            tool_name: "block_ip",
            action_level: "l4",
            execution_phase: "immediate",
            status: "waiting_approval",
            parameters: {},
            updated_at: new Date().toISOString(),
          },
        ],
      },
    });
    await Promise.all([first, second]);

    expect(useApprovalStore.getState().eventScope).toBe("evt-b");
    expect(useApprovalStore.getState().eventPendingApprovals.map((a) => a.event_id)).toEqual([
      "evt-b",
    ]);
  });

  it("approve passes comment and decision_id to API", async () => {
    useApprovalStore.setState({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-1",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          action_category: "response",
          execution_phase: "immediate",
          status: "waiting_approval",
          parameters: {},
          updated_at: new Date().toISOString(),
        },
      ],
    });
    vi.mocked(approveAction).mockResolvedValue({
      data: {
        action_id: "act-1",
        status: "approved",
        message: "approved",
        resume_status: "ok",
        degraded: false,
      },
    } as never);

    const result = await useApprovalStore.getState().approve("act-1", {
      decision_id: "dec-123",
      comment: "ok",
    });

    expect(approveAction).toHaveBeenCalledWith("act-1", {
      decision_id: "dec-123",
      comment: "ok",
    });
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
    // ISSUE-207: response body (resume_status/degraded) must be surfaced, not dropped.
    expect(result.resume_status).toBe("ok");
    expect(result.degraded).toBe(false);
  });

  it("reject returns resume_status/degraded from response body", async () => {
    vi.mocked(rejectAction).mockResolvedValue({
      data: {
        action_id: "act-1",
        status: "rejected",
        message: "rejected",
        resume_status: "skipped",
        degraded: true,
      },
    } as never);

    const result = await useApprovalStore.getState().reject("act-1", {
      decision_id: "dec-456",
      comment: "not allowed",
    });

    expect(rejectAction).toHaveBeenCalledWith("act-1", {
      decision_id: "dec-456",
      comment: "not allowed",
    });
    expect(result.resume_status).toBe("skipped");
    expect(result.degraded).toBe(true);
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });

  it("initGlobalListener registers socket handler once", () => {
    useApprovalStore.getState().initGlobalListener();
    useApprovalStore.getState().initGlobalListener();
    expect(socketClient.connect).toHaveBeenCalled();
    expect(socketClient.onEvent).toHaveBeenCalledTimes(1);
  });

  it("approval_required increments unread and stores deadline", async () => {
    vi.mocked(listEvents).mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);
    vi.mocked(listActions).mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);

    let handler: ((event: SocketEvent) => void) | undefined;
    vi.mocked(socketClient.onEvent).mockImplementation((fn) => {
      handler = fn;
      return vi.fn();
    });

    useApprovalStore.getState().initGlobalListener();
    expect(handler).toBeDefined();

    handler?.({
      type: "approval_required",
      event_id: "evt-1",
      payload: {
        action_id: "act-new",
        deadline: "2099-01-01T00:00:00.000Z",
        summary: "isolate host",
      },
    });

    expect(useApprovalStore.getState().unreadCount).toBe(1);
    expect(useApprovalStore.getState().approvalDeadlines["act-new"]).toBe(
      "2099-01-01T00:00:00.000Z",
    );
    expect(notification.info).toHaveBeenCalled();
  });

  it("approval_updated removes pending action", () => {
    useApprovalStore.setState({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-1",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          action_category: "response",
          execution_phase: "immediate",
          status: "waiting_approval",
          parameters: {},
          updated_at: new Date().toISOString(),
        },
      ],
    });

    useApprovalStore.getState()._applySocketEvent({
      type: "approval_updated",
      event_id: "evt-1",
      payload: { action_id: "act-1" },
    });

    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });

  it("a stale global refresh response is dropped when a newer refresh supersedes it", async () => {
    const makeAction = (actionId: string): Action => ({
      action_id: actionId,
      event_id: "evt-a",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });

    let resolveOld!: (value: unknown) => void;
    vi.mocked(listActions)
      .mockImplementationOnce(
        (() =>
          new Promise((res) => {
            resolveOld = res;
          })) as never,
      )
      .mockResolvedValueOnce({
        data: { total: 1, page: 1, page_size: 200, items: [makeAction("act-new")] },
      } as never);

    const first = useApprovalStore.getState().loadPendingApprovals(["evt-a"]); // slow, old data
    const second = useApprovalStore.getState().loadPendingApprovals(["evt-a"]); // fast, new data
    await second;
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.action_id)).toEqual([
      "act-new",
    ]);

    // The slow response arrives last with old data — it must be dropped.
    resolveOld({
      data: { total: 1, page: 1, page_size: 200, items: [makeAction("act-old")] },
    });
    await first;
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.action_id)).toEqual([
      "act-new",
    ]);
  });

  it("a late poll response cannot restore an action removed by socket approval_updated", async () => {
    const makeAction = (actionId: string): Action => ({
      action_id: actionId,
      event_id: "evt-a",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });
    useApprovalStore.setState({
      pendingApprovals: [makeAction("act-x"), makeAction("act-y")],
    });

    let resolvePoll!: (value: unknown) => void;
    vi.mocked(listActions).mockImplementation(
      (() =>
        new Promise((res) => {
          resolvePoll = res;
        })) as never,
    );
    const poll = useApprovalStore.getState().loadPendingApprovals(["evt-a"]); // in flight

    // Socket removes act-x while the poll is still running.
    useApprovalStore.getState()._applySocketEvent({
      type: "approval_updated",
      event_id: "evt-a",
      payload: { action_id: "act-x" },
    });
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.action_id)).toEqual([
      "act-y",
    ]);
    // The authoritative socket update ends the loading spinner too.
    expect(useApprovalStore.getState().loading).toBe(false);

    // The stale poll response (which still contains act-x) must not resurrect it.
    resolvePoll({
      data: { total: 2, page: 1, page_size: 200, items: [makeAction("act-x"), makeAction("act-y")] },
    });
    await poll;
    expect(useApprovalStore.getState().pendingApprovals.map((a) => a.action_id)).toEqual([
      "act-y",
    ]);
  });

  it("an in-flight poll snapshot cannot resurrect an action decided via approve", async () => {
    const makeAction = (actionId: string): Action => ({
      action_id: actionId,
      event_id: "evt-a",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });
    useApprovalStore.setState({
      pendingApprovals: [makeAction("act-x")],
    });

    let resolvePoll!: (value: unknown) => void;
    vi.mocked(listActions).mockImplementation(
      (() =>
        new Promise((res) => {
          resolvePoll = res;
        })) as never,
    );
    const poll = useApprovalStore.getState().loadPendingApprovals(["evt-a"]); // in flight

    // The operator approves act-x while the poll is still running.
    vi.mocked(approveAction).mockResolvedValue({
      data: { action_id: "act-x", status: "approved", message: "approved" },
    } as never);
    await useApprovalStore.getState().approve("act-x", { decision_id: "dec-1" });
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
    expect(useApprovalStore.getState().loading).toBe(false);

    // The stale poll response (still containing act-x) must not resurrect it.
    resolvePoll({
      data: { total: 1, page: 1, page_size: 200, items: [makeAction("act-x")] },
    });
    await poll;
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });

  it("an empty event list refresh invalidates an in-flight non-empty refresh", async () => {
    const makeAction = (actionId: string): Action => ({
      action_id: actionId,
      event_id: "evt-a",
      action_name: "block_ip",
      tool_name: "block_ip",
      action_level: "l4",
      action_category: "response",
      execution_phase: "immediate",
      status: "waiting_approval",
      parameters: {},
      updated_at: new Date().toISOString(),
    });

    let resolveOld!: (value: unknown) => void;
    vi.mocked(listActions).mockImplementation(
      (() =>
        new Promise((res) => {
          resolveOld = res;
        })) as never,
    );
    const pending = useApprovalStore.getState().loadPendingApprovals(["evt-a"]); // in flight

    // The event list refreshes to empty — the queue must clear and the in-flight
    // non-empty refresh must be invalidated (ISSUE-207 review).
    const emptyResult = await useApprovalStore.getState().loadPendingApprovals([]);
    expect(emptyResult).toBe("ok");
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
    expect(useApprovalStore.getState().loading).toBe(false);

    // The slow old response must not resurrect approvals for removed events.
    resolveOld({
      data: { total: 1, page: 1, page_size: 200, items: [makeAction("act-old")] },
    });
    await pending;
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
    expect(useApprovalStore.getState().eventScope).toBeNull();
  });

  it("an empty queue refresh clears _eventIds so polling stops requesting old events", async () => {
    vi.mocked(listActions).mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);
    await useApprovalStore.getState().loadPendingApprovals(["evt-a"]);
    expect(useApprovalStore.getState()._eventIds).toEqual(["evt-a"]);

    // Event list turns empty — the polling event set must be cleared with the
    // queue, otherwise the timer keeps re-fetching the removed event.
    await useApprovalStore.getState().loadPendingApprovals([]);
    expect(useApprovalStore.getState()._eventIds).toEqual([]);
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);

    // Advance one polling cycle: no listActions call may happen for old events.
    vi.useFakeTimers();
    try {
      vi.clearAllMocks();
      useApprovalStore.getState().startPolling();
      vi.advanceTimersByTime(10_000);
      expect(listActions).not.toHaveBeenCalled();
      useApprovalStore.getState().stopPolling();
    } finally {
      vi.useRealTimers();
    }
  });
});
