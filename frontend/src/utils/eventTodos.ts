/** Event detail todo computation (ISSUE-210). */

import type { Action } from "../types/action";
import type { EventDetailResponse, EventEvidenceResponse } from "../types/event";
import type { EventWriteback } from "../hooks/useEventDetail";

export type EventTodoKind =
  | "approval_pending"
  | "report_pending"
  | "memory_review"
  | "writeback_resolve"
  | "close_blocked"
  | "close_ready"
  | "decision_basis"
  | "evidence_conflicts"
  | "evidence_gaps";

export interface EventTodoItem {
  id: string;
  kind: EventTodoKind;
  label: string;
  description?: string;
  tabKey?: string;
  externalHref?: string;
  priority: number;
}

const POST_ANALYSIS_STATUSES = new Set([
  "scoring",
  "planning_response",
  "waiting_approval",
  "executing_response",
  "verifying",
  "reporting",
  "closed",
  "failed",
]);

export function hasInvestigationReport(detail: EventDetailResponse): boolean {
  const report = detail.event.event_context_snapshot?.report;
  return Boolean(report && typeof report === "object" && Object.keys(report).length > 0);
}

export function isAnalysisComplete(detail: EventDetailResponse): boolean {
  if (detail.analysis_only_complete) {
    return true;
  }
  const phase = detail.response_phase_state;
  if (phase && phase !== "not_started" && phase !== "analysis_in_progress") {
    return true;
  }
  return POST_ANALYSIS_STATUSES.has(detail.event.status);
}

export function hasWaitingApproval(actions: Action[]): boolean {
  return actions.some((action) => action.status === "waiting_approval");
}

export function unknownActions(actions: Action[]): Action[] {
  return actions.filter((action) => action.status === "unknown");
}

export function unknownWritebacks(writebacks: EventWriteback[]): EventWriteback[] {
  return writebacks.filter((item) => item.status === "unknown");
}

export function needsWritebackResolve(
  detail: EventDetailResponse,
  actions: Action[],
  writebacks: EventWriteback[],
): boolean {
  if (detail.execution_substate === "waiting_writeback") {
    return true;
  }
  if (detail.execution_substate === "manual_resolution") {
    return true;
  }
  if ((detail.pending_writeback_count ?? 0) > 0 && detail.writeback_overall_status === "unknown") {
    return true;
  }
  return unknownActions(actions).length > 0 || unknownWritebacks(writebacks).length > 0;
}

export function canCloseEvent(detail: EventDetailResponse): boolean {
  if (detail.event.status === "closed") {
    return false;
  }
  return detail.next_recommended_action === "close";
}

export interface BuildEventTodosInput {
  detail: EventDetailResponse;
  actions: Action[];
  writebacks: EventWriteback[];
  evidenceDetail: EventEvidenceResponse | null;
  pendingMemoryReviewCount?: number;
}

export function buildEventTodos(input: BuildEventTodosInput): EventTodoItem[] {
  const { detail, actions, writebacks, evidenceDetail, pendingMemoryReviewCount = 0 } = input;
  const todos: EventTodoItem[] = [];
  const hasReport = hasInvestigationReport(detail);
  const analysisComplete = isAnalysisComplete(detail);
  const closeAllowed = canCloseEvent(detail);

  if (hasWaitingApproval(actions)) {
    todos.push({
      id: "approval-pending",
      kind: "approval_pending",
      label: "待审批处置",
      description: "存在 waiting_approval 动作，请前往审批中心或动作表处理。",
      tabKey: "actions",
      externalHref: "/approvals",
      priority: 10,
    });
  }

  if (analysisComplete && !hasReport && detail.event.status !== "closed") {
    todos.push({
      id: "report-pending",
      kind: "report_pending",
      label: "待生成报告",
      description: "分析已完成但尚无报告快照，请打开报告 Tab 确认或触发生成。",
      tabKey: "report",
      priority: 20,
    });
  }

  if (pendingMemoryReviewCount > 0) {
    todos.push({
      id: "memory-review",
      kind: "memory_review",
      label: "待知识审核",
      description: `${pendingMemoryReviewCount} 条与本事件相关的 pending 候选待审核。`,
      externalHref: `/knowledge/reviews?event_id=${encodeURIComponent(detail.event.event_id)}`,
      priority: 30,
    });
  }

  if (needsWritebackResolve(detail, actions, writebacks)) {
    todos.push({
      id: "writeback-resolve",
      kind: "writeback_resolve",
      label: "写回待处理",
      description: "存在 UNKNOWN 写回或需人工裁决的处置状态。",
      tabKey: "writeback",
      priority: 40,
    });
  }

  if (closeAllowed && !hasReport) {
    todos.push({
      id: "close-blocked",
      kind: "close_blocked",
      label: "结案受阻：先生成报告",
      description: "当前 guidance 允许结案，但缺少报告快照。",
      tabKey: "report",
      priority: 50,
    });
  } else if (closeAllowed && hasReport) {
    todos.push({
      id: "close-ready",
      kind: "close_ready",
      label: "可结案",
      description: detail.phase_message ?? "报告已就绪，可执行结案。",
      priority: 60,
    });
  }

  const gapCount =
    evidenceDetail?.gaps?.length ??
    detail.event.event_context_snapshot?.evidence_output?.gaps?.length ??
    0;
  const conflictCount =
    evidenceDetail?.conflicts?.length ??
    detail.event.event_context_snapshot?.evidence_output?.conflicts?.length ??
    0;

  if (conflictCount > 0) {
    todos.push({
      id: "evidence-conflicts",
      kind: "evidence_conflicts",
      label: `证据冲突（${conflictCount}）`,
      description: "存在相互矛盾的证据条目，请查看证据 Tab 核对来源。",
      tabKey: "evidence",
      priority: 69,
    });
  }

  if (gapCount > 0) {
    todos.push({
      id: "evidence-gaps",
      kind: "evidence_gaps",
      label: `证据缺口（${gapCount}）`,
      description: "存在未补齐的证据来源，请查看证据 Tab。",
      tabKey: "evidence",
      priority: 70,
    });
  }

  todos.push({
    id: "decision-basis",
    kind: "decision_basis",
    label: "查看决策依据",
    description: "跳转到审计 Tab 查看 DecisionTraceTimeline（结构化结论，非思维链）。",
    tabKey: "audit",
    priority: 80,
  });

  return todos.sort((left, right) => left.priority - right.priority);
}
