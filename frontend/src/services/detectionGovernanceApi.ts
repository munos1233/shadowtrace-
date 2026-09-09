/** Detection shadow governance API client. */

import apiClient from "./apiClient";
import type {
  CreatePromotionRequest,
  DetectionCandidateListResponse,
  DetectionEvaluationArtifactListResponse,
  DetectionEvaluationArtifactResponse,
  DetectionGovernanceDecision,
  DetectionGovernanceDecisionListResponse,
  DetectionGovernanceEligibility,
  DetectionGovernancePromotionGate,
  DetectionPromotionListResponse,
  DetectionPromotionResult,
  RecordDecisionFromPathRequest,
} from "../types/detectionGovernance";

export function listEvaluationArtifacts(root = "detection_shadow_v1") {
  return apiClient.get<DetectionEvaluationArtifactListResponse>(
    "/detection/evaluation/artifacts",
    { params: { root } },
  );
}

export function getEvaluationArtifactByPath(path: string) {
  return apiClient.get<DetectionEvaluationArtifactResponse>(
    "/detection/evaluation/artifacts/by-path",
    { params: { path } },
  );
}

export function listDetectionCandidates(params: {
  tenant_id: string;
  package_id?: string;
  detection_scope_id?: string;
  page?: number;
  page_size?: number;
}) {
  return apiClient.get<DetectionCandidateListResponse>("/detection/candidates", {
    params,
  });
}

export function assessEligibility(body: {
  artifact: Record<string, unknown>;
  threshold_manifest_path?: string;
}) {
  return apiClient.post<DetectionGovernanceEligibility>(
    "/detection/governance/eligibility",
    body,
    { skipGlobalErrorToast: true },
  );
}

export function recordDecisionFromPath(body: RecordDecisionFromPathRequest) {
  return apiClient.post<DetectionGovernanceDecision>(
    "/detection/governance/decisions/from-path",
    body,
    { skipGlobalErrorToast: true },
  );
}

export function listGovernanceDecisions(params: {
  tenant_id: string;
  binding_hash?: string;
  page?: number;
  page_size?: number;
}) {
  return apiClient.get<DetectionGovernanceDecisionListResponse>(
    "/detection/governance/decisions",
    { params, skipGlobalErrorToast: true },
  );
}

export function revokeGovernanceDecision(
  decisionId: string,
  tenantId: string,
  reasonNote: string,
) {
  return apiClient.post<DetectionGovernanceDecision>(
    `/detection/governance/decisions/${encodeURIComponent(decisionId)}/revoke`,
    { reason_note: reasonNote },
    { params: { tenant_id: tenantId }, skipGlobalErrorToast: true },
  );
}

export function evaluatePromotionGate(body: {
  artifact: Record<string, unknown>;
  binding_hash?: string;
}) {
  return apiClient.post<DetectionGovernancePromotionGate>(
    "/detection/governance/promotion-gate",
    body,
    { skipGlobalErrorToast: true },
  );
}

export function listPromotions(params: {
  tenant_id: string;
  candidate_detection_id?: string;
  status?: string;
  page?: number;
  page_size?: number;
}) {
  return apiClient.get<DetectionPromotionListResponse>("/detection/promotions", {
    params,
  });
}

export function createPromotion(body: CreatePromotionRequest) {
  return apiClient.post<DetectionPromotionResult>("/detection/promotions", body, {
    skipGlobalErrorToast: true,
  });
}
