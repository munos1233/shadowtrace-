/** Socket.IO client wrapper with poll fallback (ISSUE-067 / ISSUE-040). */

import { io, Socket } from "socket.io-client";
import type { SocketEvent, SocketEventEnvelope } from "../types/socket";

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL ?? "http://localhost:8000";
const EVENTS_NAMESPACE = "/events";

type EventHandler = (event: SocketEvent) => void;

class SocketClient {
  private socket: Socket | null = null;
  private handlers: Set<EventHandler> = new Set();
  private connected = false;
  private envelopeListenerAttached = false;
  /** Event rooms to (re)join once the transport is up. */
  private pendingEventIds = new Set<string>();
  /** When true, emit join_global on (re)connect — SOC dashboard / list. */
  private preferGlobalRoom = false;

  /** Connect to /events namespace. Safe to call multiple times (dedup). */
  connect(): void {
    try {
      if (this.socket?.connected) {
        return;
      }

      if (!this.socket) {
        this.socket = io(`${SOCKET_URL}${EVENTS_NAMESPACE}`, {
          transports: ["websocket", "polling"],
          reconnection: true,
          reconnectionDelay: 1000,
          reconnectionAttempts: 10,
          timeout: 5000,
          autoConnect: true,
        });
        this.socket.on("connect", () => {
          this.connected = true;
          this.flushSubscriptions();
        });
        this.socket.on("disconnect", () => {
          this.connected = false;
        });
      } else {
        this.socket.connect();
      }

      if (!this.envelopeListenerAttached && this.socket) {
        this.socket.on("event", (envelope: SocketEventEnvelope) => {
          this.handleEnvelope(envelope);
        });
        this.envelopeListenerAttached = true;
      }
    } catch {
      this.connected = false;
    }
  }

  disconnect(): void {
    if (this.socket && this.envelopeListenerAttached) {
      this.socket.off("event");
      this.envelopeListenerAttached = false;
    }
    this.socket?.disconnect();
    this.socket = null;
    this.connected = false;
    this.pendingEventIds.clear();
    this.preferGlobalRoom = false;
  }

  get isConnected(): boolean {
    return this.connected;
  }

  /**
   * Subscribe to a specific event room (ISSUE-040).
   * Queues until connected so callers need not wait for the handshake.
   * Clears preferGlobalRoom — detail watch leaves global on the server.
   */
  subscribe(eventId: string): void {
    this.preferGlobalRoom = false;
    this.pendingEventIds.add(eventId);
    // Use the connect-handler flag: socket.io mocks / race windows may leave
    // ``socket.connected`` false briefly while ``this.connected`` is already true.
    if (this.connected && this.socket) {
      this.socket.emit("subscribe", { event_id: eventId });
    }
  }

  /** Drop a queued/watched event id (detail-page unmount / event switch). */
  forgetEvent(eventId: string): void {
    this.pendingEventIds.delete(eventId);
  }

  /**
   * Re-join the global room after a detail ``subscribe`` left it (ISSUE-085).
   * Clears pending event rooms so reconnect does not re-subscribe to them.
   */
  ensureGlobalRoom(): void {
    this.preferGlobalRoom = true;
    this.pendingEventIds.clear();
    this.connect();
    if (this.connected && this.socket) {
      this.socket.emit("join_global", {});
    }
  }

  private flushSubscriptions(): void {
    if (!this.connected || !this.socket) return;
    if (this.preferGlobalRoom) {
      this.socket.emit("join_global", {});
      return;
    }
    for (const eventId of this.pendingEventIds) {
      this.socket.emit("subscribe", { event_id: eventId });
    }
  }

  onEvent(handler: EventHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  private handleEnvelope(envelope: SocketEventEnvelope): void {
    const { type, event_id, payload } = envelope;
    if (type === "event_created") {
      this.emit({
        type: "event_created",
        event_id,
        payload: {
          event_id: String(payload.event_id ?? event_id),
          severity: payload.severity as string | undefined,
          event_type: payload.event_type as string | undefined,
          source_product: payload.source_product as string | undefined,
          created_at: payload.created_at as string | undefined,
        },
      });
      return;
    }
    if (type === "state_change") {
      this.emit({
        type: "state_change",
        event_id,
        payload: {
          from_status: String(payload.from_status ?? ""),
          to_status: String(payload.to_status ?? ""),
          operator: payload.operator as string | undefined,
          external_unsynced: payload.external_unsynced as boolean | undefined,
          reason: payload.reason as string | undefined,
        },
      });
      return;
    }
    if (type === "writeback_updated") {
      this.emit({
        type: "writeback_updated",
        event_id,
        payload: {
          disposition_id: String(payload.disposition_id ?? ""),
          writeback_id: String(payload.writeback_id ?? ""),
          status: String(payload.status ?? "UNKNOWN"),
          provider_code: payload.provider_code as string | undefined,
          created_at: payload.created_at as string | undefined,
          updated_at: payload.updated_at as string | undefined,
        },
      });
      return;
    }
    if (type === "approval_required" || type === "approval_updated") {
      this.emit({
        type,
        event_id,
        payload: {
          action_id: String(payload.action_id ?? ""),
          event_id: String(payload.event_id ?? event_id),
          status: payload.status as string | undefined,
          approval_cycle: payload.approval_cycle as number | undefined,
          deadline: payload.deadline as string | undefined,
          summary: payload.summary as string | undefined,
          impact_assessment: payload.impact_assessment as
            | Record<string, unknown>
            | null
            | undefined,
        },
      });
      return;
    }
    if (
      type === "risk_updated" ||
      type === "final_verdict_updated" ||
      type === "action_executed" ||
      type === "action_verified" ||
      type === "disposition_submitted" ||
      type === "tool_call_started" ||
      type === "tool_call_completed" ||
      type === "agent_progress" ||
      type === "agent_completed" ||
      type === "agent_failed" ||
      type === "report_generated"
    ) {
      this.emit({ type, event_id, payload });
    }
  }

  private emit(event: SocketEvent): void {
    for (const h of this.handlers) {
      try {
        h(event);
      } catch {
        // best-effort delivery
      }
    }
  }
}

export const socketClient = new SocketClient();
