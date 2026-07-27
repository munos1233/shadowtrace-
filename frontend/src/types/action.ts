/** Action models — matching backend app/models/action.py + openapi.json */

import type { ActionCategory, ActionLevel, ActionStatus, ExecutionOwner } from "./event";

export interface Action {
  action_id: string;
  event_id: string;
  plan_revision?: number;
  action_fingerprint?: string;
  action_level: ActionLevel;
  action_category: ActionCategory;
  action_name: string;
  tool_name: string;
  execution_phase: "immediate" | "post_verify";
  activation_condition?: string | null;
  target_type?: string | null;
  target?: string | null;
  parameters: Record<string, unknown>;
  status: ActionStatus;
  auto_execute?: boolean;
  reason?: string | null;
  provider_name?: string | null;
  execution_owner?: ExecutionOwner | null;
  execution_job_id?: string | null;
  writeback_required?: boolean;
  writeback_applicable?: boolean;
  writeback_readiness?: string;
  writeback_status?: string | null;
  disposition_source_ref?: Record<string, unknown> | null;
  executed_at?: string | null;
  updated_at: string | null;
}

export interface ActionListResponse {
  total: number;
  page: number;
  page_size: number;
  items: Action[];
}

export type ResolveUnknownResolution =
  | "mark_success"
  | "mark_failed"
  | "manual_confirmed";

export interface ResolveUnknownRequest {
  resolution: ResolveUnknownResolution;
  comment: string;
  evidence_ref?: string | null;
}

export type ResolveWritebackResolution =
  | "manual_confirmed"
  | "mark_failed"
  | "abandon";

export interface ResolveWritebackRequest {
  resolution: ResolveWritebackResolution;
  comment: string;
  evidence_ref?: string | null;
}
