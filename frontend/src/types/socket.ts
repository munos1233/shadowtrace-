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

export interface SocketToolCallPayload {
  call_id: string;
  tool_name: string;
  status?: string;
  tool_category?: string;
  provider_code?: string;
  duration_ms?: number;
  retry_count?: number;
}

export interface SocketApprovalPayload {
  action_id: string;
  event_id?: string;
  status?: string;
  approval_cycle?: number;
}

export type EventDetailSocketEventType =
  | "risk_updated"
  | "final_verdict_updated"
  | "action_executed"
  | "action_verified"
  | "disposition_submitted"
  | "tool_call_started"
  | "tool_call_completed";

export type SocketEvent =
  | { type: "event_created"; event_id: string; payload: SocketEventCreatedPayload }
  | { type: "state_change"; event_id: string; payload: SocketStateChangePayload }
  | { type: "writeback_updated"; event_id: string; payload: SocketWritebackUpdatedPayload }
  | { type: "approval_required"; event_id: string; payload: SocketApprovalPayload }
  | { type: "approval_updated"; event_id: string; payload: SocketApprovalPayload }
  | {
      type: EventDetailSocketEventType;
      event_id: string;
      payload: Record<string, unknown> & Partial<SocketToolCallPayload>;
    };

export interface SocketToolCallPayload {
  call_id: string;
  tool_name: string;
  status?: string;
  tool_category?: string;
  provider_code?: string;
  duration_ms?: number;
  retry_count?: number;
}

export type EventDetailSocketEventType =
  | "risk_updated"
  | "final_verdict_updated"
  | "action_executed"
  | "action_verified"
  | "disposition_submitted"
  | "tool_call_started"
  | "tool_call_completed";

export type SocketEvent =
  | { type: "event_created"; event_id: string; payload: SocketEventCreatedPayload }
  | { type: "state_change"; event_id: string; payload: SocketStateChangePayload }
  | { type: "writeback_updated"; event_id: string; payload: SocketWritebackUpdatedPayload }
  | {
      type: EventDetailSocketEventType;
      event_id: string;
      payload: Record<string, unknown> & Partial<SocketToolCallPayload>;
    };

export function mapSocketWritebackStatus(status: string): WritebackStatus {
  return status.toLowerCase() as WritebackStatus;
}
