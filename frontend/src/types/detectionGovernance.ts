/** Detection shadow governance API types. */

export type DetectionGovernanceDecisionKind =
  | "approve"
  | "reject"
  | "expire"
  | "revoke";

export type DetectionPromotionStatus =
  | "pending"
  | "source_persisted"
  | "event_linked"
  | "completed"
  | "retry"
  | "dead"
  | "manual";

export interface DetectionEvaluationArtifactSummary {
  path: string;
  evaluation_id: string;
  tenant_id: string;
  dataset_id: string;
  dataset_version: string;
  status: string;
  artifact_hash?: string;
  gate_verdict?: string | null;
  case_count?: number;
  pass_rate?: number | null;
}

export interface DetectionEvaluationArtifactListResponse {
  items: DetectionEvaluationArtifactSummary[];
}

export interface DetectionEvaluationAggregates {
  case_count: number;
  pass_count: number;
  fail_count: number;
  unevaluable_count?: number;
  error_count?: number;
  pass_rate?: number | null;
}

export interface DetectionEvaluationGate {
  verdict?: string;
  reason_codes?: string[];
}

export interface DetectionCandidateRefs {
  package_id?: string;
  package_version?: number;
  detection_scope_id?: string;
  package_content_hash?: string;
}

export interface DetectionEvaluationArtifact {
  evaluation_id: string;
  tenant_id: string;
  dataset_id: string;
  dataset_version: string;
  status: string;
  artifact_hash?: string;
  aggregates?: DetectionEvaluationAggregates;
  gate?: DetectionEvaluationGate | null;
  config?: {
    candidate_refs?: DetectionCandidateRefs;
  };
  [key: string]: unknown;
}

export interface DetectionEvaluationArtifactResponse {
  path: string;
  artifact: DetectionEvaluationArtifact;
}

export interface DetectionGovernanceEligibility {
  eligible: boolean;
  threshold_manifest_validated?: boolean;
  reason_codes?: string[];
  messages?: string[];
}

export interface DetectionGovernanceDecision {
  decision_id: string;
  schema_version: string;
  tenant_id: string;
  decision: DetectionGovernanceDecisionKind;
  candidate_binding: Record<string, unknown>;
  evaluation_binding: Record<string, unknown>;
  threshold_binding: Record<string, unknown>;
  binding_hash: string;
  decision_hash: string;
  policy_version: string;
  reviewer_subject: string;
  reviewer_roles: string[];
  reason_codes: string[];
  reason_note: string;
  decided_at: string;
  expires_at?: string | null;
  supersedes_decision_id?: string | null;
}

export interface DetectionGovernanceDecisionListResponse {
  total: number;
  page: number;
  page_size: number;
  items: DetectionGovernanceDecision[];
}

export interface DetectionGovernancePromotionGate {
  allowed: boolean;
  decision_id?: string | null;
  reason_codes: string[];
  messages: string[];
}

export interface DetectionCandidate {
  candidate_detection_id: string;
  source_tenant_id: string;
  detection_scope_id: string;
  package_id: string;
  package_version: number;
  rule_id: string;
  rule_version: number;
  operator: string;
  severity: string;
  shadow_only: boolean;
  cutoff_at: string;
  matched_value: number;
  content_hash?: string;
}

export interface DetectionCandidateListResponse {
  total: number;
  page: number;
  page_size: number;
  items: DetectionCandidate[];
}

export interface DetectionPromotionRecord {
  promotion_id: string;
  schema_version?: string;
  tenant_id: string;
  promotion_key: string;
  status: DetectionPromotionStatus;
  decision_id: string;
  candidate_detection_id: string;
  candidate_content_hash: string;
  package_id: string;
  package_version: number;
  package_content_hash: string;
  detection_scope_id: string;
  event_id?: string | null;
  source_record_id?: string | null;
  reason_codes: string[];
  reason_message: string;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface DetectionPromotionResult {
  promotion_id: string;
  status: DetectionPromotionStatus;
  record: DetectionPromotionRecord;
  resumed?: boolean;
}

export interface DetectionPromotionListResponse {
  total: number;
  page: number;
  page_size: number;
  items: DetectionPromotionRecord[];
}

export interface RecordDecisionFromPathRequest {
  artifact_path: string;
  decision: "approve" | "reject";
  reason_note?: string;
  threshold_manifest_path?: string;
}

export interface CreatePromotionRequest {
  tenant_id: string;
  candidate_detection_id: string;
  decision_id?: string;
  artifact_path?: string;
  artifact?: DetectionEvaluationArtifact;
}
