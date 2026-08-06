/** socketClient envelope parsing tests (ISSUE-067 / ISSUE-040). */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mockOn = vi.fn();
const mockOff = vi.fn();
const mockEmit = vi.fn();
const mockConnect = vi.fn();
const mockDisconnect = vi.fn();

let connectHandler: (() => void) | undefined;
let eventHandler: ((envelope: unknown) => void) | undefined;

vi.mock("socket.io-client", () => ({
  io: vi.fn(() => ({
    on: (event: string, handler: (...args: unknown[]) => void) => {
      mockOn(event, handler);
      if (event === "connect") connectHandler = handler as () => void;
      if (event === "event") eventHandler = handler as (envelope: unknown) => void;
    },
    off: mockOff,
    emit: mockEmit,
    connect: mockConnect,
    disconnect: mockDisconnect,
    connected: false,
  })),
}));

describe("socketClient", () => {
  beforeEach(async () => {
    vi.resetModules();
    mockOn.mockClear();
    mockOff.mockClear();
    mockEmit.mockClear();
    mockConnect.mockClear();
    mockDisconnect.mockClear();
    connectHandler = undefined;
    eventHandler = undefined;
  });

  afterEach(async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.disconnect();
  });

  it("connects to /events namespace", async () => {
    const { io } = await import("socket.io-client");
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    expect(io).toHaveBeenCalledWith(
      expect.stringContaining("/events"),
      expect.objectContaining({ transports: ["websocket", "polling"] }),
    );
  });

  it("registers single envelope listener on repeated connect", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    socketClient.connect();
    const eventCalls = mockOn.mock.calls.filter(([name]) => name === "event");
    expect(eventCalls).toHaveLength(1);
  });

  it("subscribe emits subscribe with event_id", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    connectHandler?.();
    socketClient.subscribe("evt-99");
    expect(mockEmit).toHaveBeenCalledWith("subscribe", { event_id: "evt-99" });
  });

  it("queues subscribe until connect then flushes", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    socketClient.subscribe("evt-queued");
    expect(mockEmit).not.toHaveBeenCalled();
    connectHandler?.();
    expect(mockEmit).toHaveBeenCalledWith("subscribe", {
      event_id: "evt-queued",
    });
  });

  it("forgetEvent drops pending room so reconnect does not rejoin it", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    socketClient.subscribe("evt-old");
    socketClient.forgetEvent("evt-old");
    mockEmit.mockClear();
    connectHandler?.();
    expect(mockEmit).not.toHaveBeenCalled();
  });

  it("ensureGlobalRoom emits join_global and clears pending event rooms", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    socketClient.connect();
    connectHandler?.();
    socketClient.subscribe("evt-detail");
    mockEmit.mockClear();

    socketClient.ensureGlobalRoom();

    expect(mockEmit).toHaveBeenCalledWith("join_global", {});
    mockEmit.mockClear();
    // Reconnect should re-join global, not the forgotten event room.
    connectHandler?.();
    expect(mockEmit).toHaveBeenCalledWith("join_global", {});
    expect(mockEmit).not.toHaveBeenCalledWith("subscribe", {
      event_id: "evt-detail",
    });
  });

  it("maps state_change envelope to to_status payload", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    const handler = vi.fn();
    socketClient.connect();
    socketClient.onEvent(handler);

    eventHandler?.({
      type: "state_change",
      event_id: "evt-1",
      sequence: 2,
      timestamp: "2026-01-01T00:00:00Z",
      payload: { from_status: "new", to_status: "investigating", operator: "system" },
    });

    expect(handler).toHaveBeenCalledWith({
      type: "state_change",
      event_id: "evt-1",
      payload: expect.objectContaining({
        from_status: "new",
        to_status: "investigating",
        operator: "system",
      }),
    });
  });

  it("maps writeback_updated envelope with uppercase status", async () => {
    const { socketClient } = await import("../../src/services/socketClient");
    const handler = vi.fn();
    socketClient.connect();
    socketClient.onEvent(handler);

    eventHandler?.({
      type: "writeback_updated",
      event_id: "evt-2",
      sequence: 3,
      timestamp: "2026-01-01T00:00:00Z",
      payload: {
        disposition_id: "disp-1",
        writeback_id: "wb-1",
        status: "CONFIRMED",
      },
    });

    expect(handler).toHaveBeenCalledWith({
      type: "writeback_updated",
      event_id: "evt-2",
      payload: expect.objectContaining({
        writeback_id: "wb-1",
        status: "CONFIRMED",
      }),
    });
  });

  it.each([
    "risk_updated",
    "final_verdict_updated",
    "action_executed",
    "action_verified",
    "disposition_submitted",
    "tool_call_started",
    "tool_call_completed",
    "agent_progress",
    "agent_completed",
    "agent_failed",
    "report_generated",
  ])("passes through %s detail resource events", async (type) => {
    const { socketClient } = await import("../../src/services/socketClient");
    const handler = vi.fn();
    socketClient.connect();
    socketClient.onEvent(handler);

    eventHandler?.({
      type,
      event_id: "evt-detail",
      sequence: 4,
      timestamp: "2026-01-01T00:00:00Z",
      payload: { resource_id: "resource-1" },
    });

    expect(handler).toHaveBeenCalledWith({
      type,
      event_id: "evt-detail",
      payload: { resource_id: "resource-1" },
    });
  });
});
