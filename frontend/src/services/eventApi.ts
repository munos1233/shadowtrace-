/** Event API — all /api/v1/events endpoints (ISSUE-067). */

import apiClient from "./apiClient";
import type {
  AttackStoryline,
  EventCloseRequest,
  EventDetailResponse,
  EventEvidenceResponse,
  EventListParams,
  EventListResponse,
  GraphOutput,
  ConnectorsResponse,
  DispositionListResponse,
  ExecutionJobResponse,
  InvestigationHealthConfig,
  SearchParams,
  SearchResponse,
  SourceRecordResponse,
  WritebackResponse,
} from "../types/event";
import type {
  ActionListResponse,
  ResolveUnknownRequest,
  ResolveWritebackRequest,
} from "../types/action";
import type { InvestigationReport } from "../types/report";
import type { AgentTrace, AuditLog } from "../types/trace";

// ------------------------------------------------------------------ //
// Events
// ------------------------------------------------------------------ //

export function listEvents(params?: EventListParams) {
  return apiClient.get<EventListResponse>("/events", { params });
}

export function getEvent(eventId: string) {
  return apiClient.get<EventDetailResponse>(`/events/${eventId}`);
}

export function getTimeline(eventId: string) {
  return apiClient.get<AttackStoryline>(`/events/${eventId}/timeline`);
}

export function getGraph(eventId: string) {
  return apiClient.get<GraphOutput>(`/events/${eventId}/graph`);
}

export function getEventEvidence(eventId: string) {
  return apiClient.get<EventEvidenceResponse>(`/events/${eventId}/evidence`);
}

export function triggerInvestigation(
  eventId: string,
  options?: { includeResponseExecution?: boolean },
) {
  return apiClient.post<{
    event_id: string;
    status: string;
    include_response_execution?: boolean;
    full_loop_available?: boolean;
  }>(
    `/events/${eventId}/investigate`,
    {
      include_response_execution: options?.includeResponseExecution ?? false,
    },
    { skipGlobalErrorToast: true },
  );
}

export function getHealth() {
  return apiClient.get<{
    investigation?: InvestigationHealthConfig;
  }>("/health");
}

export function closeEvent(eventId: string, body: EventCloseRequest) {
  return apiClient.post<{ event_id: string; status: string }>(
    `/events/${eventId}/close`,
    body,
  );
}

// ------------------------------------------------------------------ //
// Report & traces
// ------------------------------------------------------------------ //

export function getReport(eventId: string) {
  return apiClient.get<{ report: InvestigationReport }>(`/events/${eventId}/report`);
}

export function getTraces(eventId: string) {
  return apiClient.get<{ total: number; page: number; page_size: number; items: AgentTrace[] }>(
    `/events/${eventId}/traces`,
  );
}

export function getAuditLogs(eventId: string) {
  return apiClient.get<{ total: number; page: number; page_size: number; items: AuditLog[] }>(
    `/events/${eventId}/audit-logs`,
  );
}

// ------------------------------------------------------------------ //
// Actions
// ------------------------------------------------------------------ //

export function listActions(
  eventId: string,
  params?: { page?: number; page_size?: number; status?: string },
) {
  return apiClient.get<ActionListResponse>(`/events/${eventId}/actions`, {
    params,
  });
}

export function approveAction(
  actionId: string,
  body?: { comment?: string; decision_id?: string },
) {
  return apiClient.post(`/actions/${actionId}/approve`, body ?? {});
}

export function rejectAction(
  actionId: string,
  body: { comment?: string; decision_id?: string },
) {
  return apiClient.post(`/actions/${actionId}/reject`, body);
}

// ------------------------------------------------------------------ //
// Source records & connectors
// ------------------------------------------------------------------ //

export function getSourceRecord(sourceRecordId: string) {
  return apiClient.get<SourceRecordResponse>(
    `/source-records/${sourceRecordId}`,
  );
}

export function listConnectors() {
  return apiClient.get<ConnectorsResponse>("/connectors");
}

// ------------------------------------------------------------------ //
// Execution jobs
// ------------------------------------------------------------------ //

export function getExecutionJob(jobId: string) {
  return apiClient.get<ExecutionJobResponse>(`/execution-jobs/${jobId}`);
}

// ------------------------------------------------------------------ //
// Dispositions
// ------------------------------------------------------------------ //

export function listDispositions(eventId: string) {
  return apiClient.get<DispositionListResponse>(`/events/${eventId}/dispositions`);
}

export function getDisposition(dispositionId: string) {
  return apiClient.get<unknown>(`/dispositions/${dispositionId}`);
}

export function selectDispositionSource(
  eventId: string,
  sourceLocator: Record<string, unknown>,
) {
  return apiClient.put(`/events/${eventId}/disposition-source`, sourceLocator);
}

// ------------------------------------------------------------------ //
// Writebacks
// ------------------------------------------------------------------ //

export function getWriteback(writebackId: string) {
  return apiClient.get<WritebackResponse>(`/writebacks/${writebackId}`);
}

export function retryWriteback(writebackId: string) {
  return apiClient.post(`/writebacks/${writebackId}/retry`);
}

// ------------------------------------------------------------------ //
// Admin-only resolve actions
// ------------------------------------------------------------------ //

export function resolveUnknownAction(
  actionId: string,
  body: ResolveUnknownRequest,
) {
  return apiClient.post(`/actions/${actionId}/resolve-unknown`, body);
}

export function resolveWriteback(
  writebackId: string,
  body: ResolveWritebackRequest,
) {
  return apiClient.post(`/writebacks/${writebackId}/resolve`, body);
}

// ------------------------------------------------------------------ //
// Search (ISSUE-084)
// ------------------------------------------------------------------ //

export function search(params: SearchParams) {
  return apiClient.get<SearchResponse>("/search", { params });
}
