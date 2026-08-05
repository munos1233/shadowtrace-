import { describe, expect, it } from "vitest";
import type { Action } from "../../src/types/action";
import type { EventDetailResponse } from "../../src/types/event";
import type { EventWriteback } from "../../src/hooks/useEventDetail";
import {
  buildEventTodos,
  canCloseEvent,
  hasInvestigationReport,
  needsWritebackResolve,
} from "../../src/utils/eventTodos";

function baseDetail(overrides: Partial<EventDetailResponse> = {}): EventDetailResponse {
  const event = {
    event_id: "evt-1",
    event_type: "account_anomaly" as const,
    title: "test",
    description: "test",
    status: "reporting" as const,
    severity: "high" as const,
    risk_score: 80,
    confidence: 0.9,
    final_verdict: "confirmed_threat" as const,
    entities: {
      accounts: [],
      hosts: [],
      ips: [],
      domains: [],
      processes: [],
      files: [],
    },
    creation_source_ref: {
      source_id: "mock",
      source_type: "xdr",
      object_kind: "event",
      object_id: "obj-1",
      source_status_raw: "OPEN",
    },
    source_reference_snapshots: [],
    current_primary_source_record_id: null,
    disposition_source_ref: null,
    disposition_policy: "required" as const,
    raw_alert_ids: [],
    raw_alert_snapshot: {},
    source_type: "xdr",
    occurred_at: "2026-08-01T00:00:00Z",
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
    closed_at: null,
    replan_count: 0,
    degraded_flags: [],
    escalated: false,
    external_unsynced: false,
    row_version: 1,
    event_context_snapshot: {},
    ...(overrides.event ?? {}),
  };

  return {
    event,
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: null,
    pending_writeback_count: 0,
    analysis_only_complete: true,
    next_recommended_action: "none",
    phase_message: "分析已完成",
    ...overrides,
  };
}

describe("eventTodos", () => {
  it("detects report pending after analysis complete without report snapshot", () => {
    const detail = baseDetail();
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });
    expect(todos.some((item) => item.kind === "report_pending")).toBe(true);
    expect(todos.some((item) => item.kind === "decision_basis")).toBe(true);
  });

  it("shows close ready when guidance allows close and report exists", () => {
    const detail = baseDetail({
      next_recommended_action: "close",
      event: {
        ...baseDetail().event,
        event_context_snapshot: {
          report: { report_id: "evt-1", summary: "done" },
        },
      },
    });
    expect(hasInvestigationReport(detail)).toBe(true);
    expect(canCloseEvent(detail)).toBe(true);
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });
    expect(todos.some((item) => item.kind === "close_ready")).toBe(true);
    expect(todos.some((item) => item.kind === "close_blocked")).toBe(false);
  });

  it("blocks close when report missing despite close guidance", () => {
    const detail = baseDetail({ next_recommended_action: "close" });
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });
    expect(todos.some((item) => item.kind === "close_blocked")).toBe(true);
  });

  it("flags approval and writeback resolve todos", () => {
    const actions: Action[] = [
      {
        action_id: "act-1",
        event_id: "evt-1",
        action_level: "l1",
        action_name: "block_ip",
        action_category: "response",
        tool_name: "mock_tool",
        status: "waiting_approval",
        target: "1.2.3.4",
        execution_owner: "direct_tool",
        execution_phase: "immediate",
        parameters: {},
        updated_at: "2026-08-01T00:00:00Z",
      },
      {
        action_id: "act-2",
        event_id: "evt-1",
        action_level: "l1",
        action_name: "isolate_host",
        action_category: "response",
        tool_name: "mock_tool",
        status: "unknown",
        target: "host-1",
        execution_owner: "direct_tool",
        execution_phase: "immediate",
        parameters: {},
        updated_at: "2026-08-01T00:00:00Z",
      },
    ];
    const writebacks: EventWriteback[] = [
      {
        writeback_id: "wbk-1",
        disposition_id: "disp-1",
        action_id: "act-3",
        status: "unknown",
        confirmation_evidence: null,
        evidence_tier: null,
        provider_code: null,
        message_code: null,
        target_results: [],
      },
    ];
    const detail = baseDetail({ execution_substate: "manual_resolution" });
    expect(needsWritebackResolve(detail, actions, writebacks)).toBe(true);
    const todos = buildEventTodos({
      detail,
      actions,
      writebacks,
      evidenceDetail: null,
    });
    expect(todos.some((item) => item.kind === "approval_pending")).toBe(true);
    expect(todos.some((item) => item.kind === "writeback_resolve")).toBe(true);
  });

  it("includes memory review, evidence gap, and conflict todos", () => {
    const detail = baseDetail({
      event: {
        ...baseDetail().event,
        event_context_snapshot: {
          evidence_output: {
            evidence_list: [],
            conflicts: [
              {
                conflict_id: "conf-1",
                event_id: "evt-1",
                description: "severity mismatch",
                evidence_ids: ["ev-1", "ev-2"],
                sources: ["edr"],
              },
            ],
            gaps: [],
            success_sources: [],
            failed_sources: [],
            overall_confidence: 0.5,
            collection_status: "partial_done",
          },
        },
      },
    });
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: null,
      pendingMemoryReviewCount: 2,
    });
    expect(todos.some((item) => item.kind === "memory_review")).toBe(true);
    expect(todos.some((item) => item.kind === "evidence_gaps")).toBe(false);
    expect(todos.some((item) => item.kind === "evidence_conflicts")).toBe(true);
  });

  it("includes evidence gap todo from evidenceDetail", () => {
    const detail = baseDetail();
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: {
        event_id: "evt-1",
        evidence_list: [],
        conflicts: [],
        gaps: [
          {
            event_id: "evt-1",
            missing_source: "endpoint",
            reason: "missing logs",
          },
        ],
        success_sources: [],
        failed_sources: [],
        overall_confidence: 0.5,
        collection_status: "partial_done",
        query_summary: [],
      },
      pendingMemoryReviewCount: 0,
    });
    expect(todos.some((item) => item.kind === "evidence_gaps")).toBe(true);
  });
});
