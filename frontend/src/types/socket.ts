/** Socket.IO types — ISSUE-040 envelope + payloads from events.schema.json */

import type { WritebackStatus } from "./event";

/** Wire envelope emitted on namespace /events as event name "event". */
export interface SocketEventEnvelope {
  type: string;
  event_id: string;
  sequence: number;
  timestamp: string;
  payload: Record<string, unknown>;
}

export interface SocketEventCreatedPayload {
  event_id: string;
  severity?: string;
  event_type?: string;
  source_product?: string;
  created_at?: string;
}

export interface SocketStateChangePayload {
  from_status: string;
  to_status: string;
  operator?: string;
  external_unsynced?: boolean;
  reason?: string;
}

/** Socket schema uses uppercase provider codes; map to API WritebackStatus. */
export type SocketWritebackStatusCode =
  | "PENDING"
  | "ACCEPTED"
  | "CONFIRMED"
  | "FAILED"
  | "CONFLICT"
  | "UNKNOWN";

export interface SocketWritebackUpdatedPayload {
  disposition_id: string;
  writeback_id: string;
  status: SocketWritebackStatusCode | string;
  provider_code?: string;
  created_at?: string;
  updated_at?: string;
}

export type SocketEvent =
  | { type: "event_created"; event_id: string; payload: SocketEventCreatedPayload }
  | { type: "state_change"; event_id: string; payload: SocketStateChangePayload }
  | { type: "writeback_updated"; event_id: string; payload: SocketWritebackUpdatedPayload };

export function mapSocketWritebackStatus(status: string): WritebackStatus {
  return status.toLowerCase() as WritebackStatus;
}
