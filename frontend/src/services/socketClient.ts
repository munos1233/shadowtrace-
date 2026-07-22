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
  }

  get isConnected(): boolean {
    return this.connected;
  }

  /** Subscribe to a specific event room (ISSUE-040 subscribe handler). */
  subscribe(eventId: string): void {
    this.socket?.emit("subscribe", { event_id: eventId });
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
