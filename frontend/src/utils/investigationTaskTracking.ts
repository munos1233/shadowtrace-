/** Celery investigation task helpers (ISSUE-306 / OpenAPI TaskResponse contract). */

export const TERMINAL_TASK_STATES = new Set(["SUCCESS", "FAILURE", "UNKNOWN"]);

export function normalizeTaskState(state: string): string {
  return (state || "PENDING").trim().toUpperCase();
}

export function isTerminalTaskState(state: string): boolean {
  return TERMINAL_TASK_STATES.has(normalizeTaskState(state));
}

export function isCeleryTaskMode(taskMode?: string | null): boolean {
  return (taskMode ?? "").trim().toLowerCase() === "celery";
}

export function labelTaskState(state: string): string {
  switch (normalizeTaskState(state)) {
    case "PENDING":
      return "排队中";
    case "STARTED":
      return "执行中";
    case "SUCCESS":
      return "已完成";
    case "FAILURE":
      return "失败";
    case "UNKNOWN":
      return "状态未知";
    default:
      return normalizeTaskState(state);
  }
}
