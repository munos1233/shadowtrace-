/** Core enumerations — must stay in sync with backend app/models/enums.py */

export type EventStatus =
  | "new"
  | "triaging"
  | "collecting_evidence"
  | "analyzing"
  | "scoring"
  | "planning_response"
  | "waiting_approval"
  | "executing_response"
  | "verifying"
  | "replanning"
  | "contained"
  | "failed"
  | "reporting"
  | "closed";

export type Severity = "low" | "medium" | "high" | "critical";

export type FinalVerdict =
  | "none"
  | "possible_false_positive"
  | "false_positive"
  | "confirmed_threat";

export type EventType =
  | "account_anomaly"
  | "host_compromise"
  | "data_exfiltration"
  | "insider_threat"
  | "malicious_process"
  | "suspicious_domain"
  | "lateral_movement"
  | "other";

export type DispositionPolicy = "required" | "not_required";

export type WritebackReadiness =
  | "not_required"
  | "ready"
  | "source_unresolved"
  | "not_configured"
  | "capability_unknown"
  | "capability_unsupported"
  | "permission_denied"
  | "connector_unavailable";

export type WritebackStatus =
  | "pending"
  | "sending"
  | "accepted"
  | "confirmed"
  | "partial"
  | "failed"
  | "conflict"
  | "unknown";

export type ActionStatus =
  | "pending"
  | "waiting_approval"
  | "approved"
  | "rejected"
  | "executing"
  | "partial_success"
  | "success"
  | "failed"
  | "unknown"
  | "superseded"
  | "rolled_back";

export type ActionLevel = "l0" | "l1" | "l2" | "l3" | "l4" | "l5";

export type ExecutionOwner = "xdr_managed" | "direct_tool";

export type ActionCategory =
  | "system"
  | "response"
  | "verification"
  | "rollback";

export type EvidenceSource =
  | "identity"
  | "endpoint"
  | "network_flow"
  | "data_security"
  | "dns"
  | "asset"
  | "threat_intel"
  | "false_positive_match";

export type CollectionStatus =
  | "completed"
  | "partial_done"
  | "degraded"
  | "failed";

export type VerificationOverallStatus =
  | "success"
  | "partial"
  | "failed"
  | "waiting"
  | "manual_resolution";

export type ScoringMode = "llm_and_rule" | "rule_only";

export type ResponsePlanGeneratedBy = "llm" | "template";

export type EffectStatus = "verified" | "failed" | "skipped" | "unverifiable";

/* ------------------------------------------------------------------ */
/*  Entity models (aligned with backend app/models/entities.py)       */
/* ------------------------------------------------------------------ */

export interface EntitySourceReference {
  source_id: string;
  source_type: string;
  object_kind: string;
  object_id: string;
  source_status_raw?: string;
}

export interface BaseEntity {
  entity_id: string;
  source_refs?: EntitySourceReference[];
  attributes?: Record<string, unknown>;
}

export interface AccountEntity extends BaseEntity {
  entity_type: "account";
  username?: string | null;
  domain?: string | null;
  display_name?: string | null;
}

export interface HostEntity extends BaseEntity {
  entity_type: "host";
  hostname?: string | null;
  ip?: string | null;
  os?: string | null;
}

export interface IpEntity extends BaseEntity {
  entity_type: "ip";
  address?: string | null;
  scope?: "external" | "internal" | "unknown";
}

export interface DomainEntity extends BaseEntity {
  entity_type: "domain";
  fqdn?: string | null;
}

export interface ProcessEntity extends BaseEntity {
  entity_type: "process";
  name?: string | null;
  pid?: number | null;
  command_line?: string | null;
  hash?: string | null;
}

export interface FileEntity extends BaseEntity {
  entity_type: "file";
  path?: string | null;
  name?: string | null;
  hash?: string | null;
}

export type EntityItem =
  | AccountEntity
  | HostEntity
  | IpEntity
  | DomainEntity
  | ProcessEntity
  | FileEntity;

export interface EntitySet {
  accounts: AccountEntity[];
  hosts: HostEntity[];
  ips: IpEntity[];
  domains: DomainEntity[];
  processes: ProcessEntity[];
  files: FileEntity[];
}

/* ------------------------------------------------------------------ */
/*  Source / disposition models                                       */
/* ------------------------------------------------------------------ */

export interface SourceReference {
  source_id: string;
  source_type: string;
  object_kind: string;
  object_id: string;
  source_status_raw: string;
}

export interface SourceObjectLocator {
  source_id: string;
  source_type: string;
  object_kind: string;
  object_id: string;
}

export interface DispositionReceipt {
  writeback_id: string;
  sequence: number;
  disposition_id: string;
  action_id: string;
  source_record_id: string;
  status: WritebackStatus;
  confirmation_evidence: string | null;
  provider_record_id?: string | null;
  provider_job_id?: string | null;
  provider_code?: string | null;
  provider_message?: string | null;
  observed_at?: string | null;
  submitted_at: string | null;
  confirmed_at: string | null;
  target_results?: TargetWritebackResult[];
  raw_result?: Record<string, unknown>;
  truncated?: boolean;
  simulated: boolean;
}

export interface TargetWritebackResult {
  canonical_target: string;
  status: string;
  provider_code?: string | null;
  message_code?: string | null;
  artifact_ref?: string | null;
}

export interface DispositionCommand {
  disposition_id: string;
  action_id: string;
  closure_cycle: number;
  intent_kind: string;
  source_locator: SourceObjectLocator;
  operation_code: string;
  operation_params: Record<string, unknown>;
  target_results: Record<string, unknown>[];
  operator_id: string;
  idempotency_key: string;
  source_concurrency_token?: string | null;
  execution_owner: ExecutionOwner;
  parent_disposition_id?: string | null;
  supersedes_disposition_id?: string | null;
}

export interface DispositionResponse {
  disposition: DispositionCommand;
  writeback_status: WritebackStatus | null;
}

export interface DispositionListResponse {
  event_id: string;
  items: DispositionResponse[];
}

export interface WritebackSummary {
  event_id: string;
  closure_cycle: number;
  disposition_policy: DispositionPolicy;
  required_action_count: number;
  applicable_action_count: number;
  blocked_action_ids: string[];
  readiness_counts: Record<string, number>;
  aggregate_readiness: WritebackReadiness;
  writeback_counts: Record<string, number>;
  aggregate_status: WritebackStatus | null;
  terminal_event_action_id: string | null;
  terminal_event_writeback_id: string | null;
  terminal_event_disposition: string | null;
  terminal_event_confirmed: boolean;
  external_unsynced: boolean;
  updated_at: string | null;
}

/* ------------------------------------------------------------------ */
/*  Evidence models                                                   */
/* ------------------------------------------------------------------ */

export interface Evidence {
  evidence_id: string;
  event_id: string;
  source: EvidenceSource;
  evidence_type: string;
  description: string;
  confidence: number;
  timestamp: string | null;
  related_entities?: string[];
  source_ref?: SourceReference | null;
  raw_data: Record<string, unknown>;
  mitre_technique?: string | null;
  is_conflicting: boolean;
}

export interface EvidenceConflict {
  conflict_id: string;
  event_id: string;
  description: string;
  evidence_ids: string[];
  sources: EvidenceSource[];
  detail?: Record<string, unknown>;
}

export interface EvidenceGap {
  event_id: string;
  missing_source: EvidenceSource;
  reason: string;
  detail?: Record<string, unknown>;
}

export interface EvidenceOutput {
  evidence_list: Evidence[];
  conflicts: EvidenceConflict[];
  gaps: EvidenceGap[];
  success_sources: string[];
  failed_sources: string[];
  overall_confidence: number;
  collection_status: CollectionStatus;
}

/* ------------------------------------------------------------------ */
/*  Attack storyline models                                           */
/* ------------------------------------------------------------------ */

export type StorylineGeneratedBy = "llm" | "rule";

export type StorylinePhaseName =
  | "initial_access"
  | "collection"
  | "staging"
  | "exfiltration"
  | "post_action";

export interface TimelineEntry {
  timestamp: string;
  description: string;
  evidence_id: string;
  technique_id?: string | null;
  severity_hint?: Severity | null;
}

export interface StorylinePhase {
  phase_order: number;
  phase_name: StorylinePhaseName;
  tactic?: string | null;
  narrative: string;
  entries: TimelineEntry[];
}

export interface AttackStoryline {
  storyline_id: string;
  event_id: string;
  narrative_summary: string;
  phases: StorylinePhase[];
  generated_by: StorylineGeneratedBy;
}

/* ------------------------------------------------------------------ */
/*  Entity graph models                                               */
/* ------------------------------------------------------------------ */

export type GraphEntityType =
  | "account"
  | "host"
  | "ip"
  | "domain"
  | "process"
  | "file";

export type GraphRelationType =
  | "logged_in_from"
  | "logged_in_to"
  | "executed"
  | "accessed"
  | "connected_to"
  | "resolved"
  | "requested"
  | "uploaded_to";

export interface GraphNode {
  node_id: string;
  event_id: string;
  entity_type: GraphEntityType;
  entity_value: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  edge_id: string;
  event_id: string;
  source_node_id: string;
  target_node_id: string;
  relation_type: GraphRelationType;
  evidence_id: string;
  occurred_at: string | null;
}

export interface GraphOutput {
  nodes: GraphNode[];
  edges: GraphEdge[];
  central_entities: string[];
  attack_path_candidates: string[][];
}

/* ------------------------------------------------------------------ */
/*  Risk models                                                       */
/* ------------------------------------------------------------------ */

export interface RiskFactor {
  factor_name: string;
  weight: number;
  raw_score: number;
  weighted_score: number;
  reasoning: string;
}

export interface RiskAssessment {
  risk_score: number;
  severity: Severity;
  confidence: number;
  risk_factors: RiskFactor[];
  possible_false_positive: boolean;
  scoring_mode: ScoringMode;
}

export interface SourceSyncState {
  disposition?: string;
  source_status_raw?: string;
  source_concurrency_token?: string | null;
  last_observed_at?: string | null;
  [key: string]: unknown;
}

export interface EventContextSnapshot {
  source_snapshot?: Record<string, unknown> | null;
  source_sync_state?: SourceSyncState | null;
  evidence_output?: EvidenceOutput | null;
  storyline?: AttackStoryline | null;
  risk_assessment?: RiskAssessment | null;
  execution_jobs?: ExecutionJobResponse[];
  execution_summary?: {
    jobs?: ExecutionJobResponse[];
    writeback_ids?: string[];
    [key: string]: unknown;
  } | null;
  disposition_commands?: DispositionCommand[];
  disposition_receipts?: DispositionReceipt[];
  writeback_summary?: WritebackSummary | null;
  report?: Record<string, unknown> | null;
  state_history?: Record<string, unknown>[];
  [key: string]: unknown;
}

/* ------------------------------------------------------------------ */
/*  API response models                                               */
/* ------------------------------------------------------------------ */

export interface EventListItem {
  event_id: string;
  event_type: EventType;
  title: string;
  status: EventStatus;
  severity: Severity;
  risk_score: number;
  final_verdict: FinalVerdict;
  writeback_required: boolean;
  writeback_readiness: WritebackReadiness;
  writeback_overall_status: WritebackStatus | null;
  confirmation_evidence?: string | null;
  pending_writeback_count: number;
  created_at: string | null;
  updated_at: string | null;
  occurred_at: string | null;
}

export interface EventListResponse {
  total: number;
  page: number;
  page_size: number;
  items: EventListItem[];
}

export interface EventListParams {
  page?: number;
  page_size?: number;
  status?: EventStatus;
  severity?: Severity;
  event_type?: EventType;
  final_verdict?: FinalVerdict;
  keyword?: string;
  start_time?: string;
  end_time?: string;
  sort_by?: string;
  sort_order?: "asc" | "desc";
}

export interface SecurityEvent {
  event_id: string;
  event_type: EventType;
  title: string;
  description: string;
  status: EventStatus;
  severity: Severity;
  risk_score: number;
  confidence: number;
  final_verdict: FinalVerdict;
  entities: EntitySet;
  creation_source_ref: SourceReference;
  source_reference_snapshots: SourceReference[];
  current_primary_source_record_id: string | null;
  disposition_source_ref: SourceObjectLocator | null;
  disposition_policy: DispositionPolicy;
  raw_alert_ids: string[];
  raw_alert_snapshot: Record<string, unknown> | null;
  source_type: string | null;
  occurred_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  closed_at: string | null;
  replan_count: number;
  degraded_flags: string[];
  escalated: boolean;
  external_unsynced: boolean;
  event_context_snapshot: EventContextSnapshot | null;
  row_version: number;
}

export interface EventDetailResponse {
  event: SecurityEvent;
  writeback_required: boolean;
  writeback_readiness: WritebackReadiness;
  writeback_overall_status: WritebackStatus | null;
  pending_writeback_count: number;
}

export interface InvestigationResult {
  event_id: string;
  final_status: EventStatus;
  final_verdict: FinalVerdict;
  escalated: boolean;
  external_unsynced: boolean;
  report_id: string | null;
  writeback_required: boolean;
  writeback_readiness: WritebackReadiness;
  writeback_overall_status: WritebackStatus | null;
  pending_writeback_ids: string[];
}

export interface ExecutionJob {
  job_id: string;
  event_id: string;
  action_id: string;
  status: string;
  result: Record<string, unknown> | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface WritebackRecord {
  writeback_id: string;
  event_id: string;
  disposition_id: string;
  status: WritebackStatus;
  confirmation_evidence: string | null;
  submitted_at: string | null;
  confirmed_at: string | null;
  retry_count: number;
  error_detail: string | null;
}

export interface SourceRecordResponse {
  source_record_id: string;
  reference: SourceReference;
  normalized?: Record<string, unknown>;
  current_source_disposition?: string;
  source_sync_state?: string | null;
}

export interface ExecutionJobResponse {
  job_id: string;
  event_id: string;
  action_id: string;
  status: string;
  attempt?: number;
  target_results?: Record<string, unknown>[];
}

export interface ConnectorPublic {
  connector_id: string;
  source_product: string;
  display_name: string;
  device_type?: string | null;
  status: string;
  capabilities: Record<string, string>;
  disposition_policy_default?: DispositionPolicy | null;
  last_sync_at?: string | null;
}

export interface ConnectorsResponse {
  items: ConnectorPublic[];
}

export interface WritebackResponse {
  writeback_id: string;
  disposition_id: string;
  action_id: string;
  status: WritebackStatus;
  confirmation_evidence: string | null;
  evidence_tier: "strong" | "medium" | "weak" | null;
  provider_code: string | null;
  message_code: string | null;
  target_results: TargetWritebackResult[];
}
