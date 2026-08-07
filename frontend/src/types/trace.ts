/** Typed tool-audit and decision-trace API contracts (ISSUE-072). */

export interface AgentTrace {
  trace_id: string;
  event_id: string;
  agent_name: string;
  status: "completed" | "failed" | "processing";
  input_data: Record<string, unknown> | null;
  output_data: Record<string, unknown> | null;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  error_detail: string | null;
  llm_model: string | null;
  llm_tokens_used: number | null;
}

export interface AuditLog {
  log_id: string;
  event_id: string;
  actor: string;
  action: string;
  detail: string;
  timestamp: string;
}

export interface ToolCallItem {
  call_id: string;
  event_id: string;
  action_id: string | null;
  tool_name: string;
  tool_category: string;
  status: string;
  duration_ms: number | null;
  provider: string | null;
  execution_owner: string | null;
  disposition_id: string | null;
  writeback_status: string | null;
  parameters: Record<string, unknown>;
  result: Record<string, unknown>;
  error_detail: string | null;
  retry_count: number;
  started_at: string | null;
  completed_at: string | null;
  truncated: boolean;
}

export interface ToolCallsResponse {
  total: number;
  page: number;
  page_size: number;
  items: ToolCallItem[];
}

export type DecisionTraceEntryType =
  | "agent_execution"
  | "tool_call"
  | "llm_call"
  | "state_transition"
  | "approval"
  | "action_execution"
  | "disposition"
  | "writeback";

export interface DecisionTraceEntry {
  entry_id: string;
  entry_type: DecisionTraceEntryType;
  timestamp: string;
  actor: string;
  title: string;
  detail: Record<string, unknown>;
  ref_id: string | null;
  decision_record_ref?: string | null;
}

export interface DecisionTraceSummary {
  agent_count: number;
  tool_call_count: number;
  llm_call_count: number;
  total_tokens: number;
  state_transition_count: number;
  approval_count: number;
  action_execution_count: number;
  disposition_count: number;
  writeback_count: number;
  /** Wall-clock span including WAITING_* idle (legacy-compatible). */
  total_duration_ms: number | null;
  /** Effective investigation duration excluding WAITING_* halt gaps. */
  active_duration_ms: number | null;
}

export interface DecisionTraceResponse {
  event_id: string;
  entries: DecisionTraceEntry[];
  summary: DecisionTraceSummary;
  missing_sources: string[];
  page: number;
  page_size: number;
  total: number;
}

export interface TrajectoryReport {
  event_id: string;
  total_steps: number;
  agent_invocations: number;
  tool_calls: number;
  llm_calls: number;
  metrics: Record<string, number>;
  findings: string[];
  insufficient_trace: boolean;
}

export interface AgentQualityScore {
  agent_name: string;
  score: number;
  verdict?: string;
  metrics?: Record<string, number>;
  reasons?: string[];
  evaluated_by?: string;
}
