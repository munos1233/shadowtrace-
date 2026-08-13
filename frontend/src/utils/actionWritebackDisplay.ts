/** Action-level writeback display semantics (ISSUE-331).

  ``writeback_required`` is an event-level business obligation snapshot.
  ``writeback_applicable`` marks whether *this* action owns a terminal
  disposition writeback. UI must not treat required=true as "writeback done"
  when applicable=false (entity side effects).
*/

import type { WritebackStatus } from "../types/event";

export type ActionWritebackDisplayTone =
  | "neutral"
  | "success"
  | "warning"
  | "error"
  | "info";

export interface ActionWritebackDisplay {
  label: string;
  tone: ActionWritebackDisplayTone;
  tooltip: string;
  /** True only when applicable writeback reached CONFIRMED. */
  isConfirmedApplicableWriteback: boolean;
}

export interface ActionWritebackInput {
  writeback_required?: boolean;
  writeback_applicable?: boolean;
  writeback_status?: string | WritebackStatus | null;
}

const STATUS_LABELS: Record<WritebackStatus, string> = {
  pending: "待发送",
  sending: "发送中",
  accepted: "已接收",
  confirmed: "已确认",
  partial: "部分成功",
  failed: "失败",
  conflict: "冲突",
  unknown: "未知",
};

export function resolveActionWritebackDisplay(
  action: ActionWritebackInput,
): ActionWritebackDisplay {
  const required = Boolean(action.writeback_required);
  const applicable = Boolean(action.writeback_applicable);
  const statusRaw = action.writeback_status;
  const status =
    typeof statusRaw === "string" && statusRaw.length > 0
      ? (statusRaw.toLowerCase() as WritebackStatus)
      : null;

  if (!required) {
    return {
      label: "无需写回",
      tone: "neutral",
      tooltip: "本动作不承担事件级写回义务（writeback_required=false）。",
      isConfirmedApplicableWriteback: false,
    };
  }

  if (!applicable) {
    return {
      label: "事件级义务 · 本动作不承担终态写回",
      tone: "neutral",
      tooltip:
        "writeback_required=true 表示事件需要终态写回；本动作 writeback_applicable=false（entity_side_effect），不得以 SUCCESS/ACCEPTED 冒充终态写回完成。闭环以 EVENT_STATUS_UPDATE 的 CONFIRMED 为准。",
      isConfirmedApplicableWriteback: false,
    };
  }

  if (status === "confirmed") {
    return {
      label: "终态写回已确认",
      tone: "success",
      tooltip: "本动作承担可写回义务且 writeback_status=confirmed。",
      isConfirmedApplicableWriteback: true,
    };
  }

  if (status === "failed" || status === "conflict") {
    const label = status ? (STATUS_LABELS[status] ?? status) : "写回失败";
    return {
      label,
      tone: "error",
      tooltip: `本动作 writeback_applicable=true，写回状态为 ${status}。`,
      isConfirmedApplicableWriteback: false,
    };
  }

  if (status === "unknown") {
    return {
      label: "写回未知",
      tone: "warning",
      tooltip: "本动作承担写回义务，但外部确认状态未知，需人工裁决。",
      isConfirmedApplicableWriteback: false,
    };
  }

  if (status) {
    const label = STATUS_LABELS[status] ?? status;
    return {
      label,
      tone: "info",
      tooltip: `本动作 writeback_applicable=true，写回进行中（${status}）。`,
      isConfirmedApplicableWriteback: false,
    };
  }

  return {
    label: "待写回",
    tone: "info",
    tooltip: "本动作 writeback_applicable=true，尚未产生写回状态。",
    isConfirmedApplicableWriteback: false,
  };
}

/** Receipt row display: entity submit ACCEPTED is not terminal writeback done. */
export function resolveWritebackReceiptDisplay(input: {
  status: WritebackStatus | null;
  intentKind?: string | null;
  matchingAction?: ActionWritebackInput | null;
  terminal?: boolean;
}): ActionWritebackDisplay {
  const { status, intentKind, matchingAction, terminal } = input;
  const actionDisplay = matchingAction
    ? resolveActionWritebackDisplay(matchingAction)
    : null;

  if (terminal) {
    if (status === "confirmed") {
      return {
        label: "终态写回已确认",
        tone: "success",
        tooltip: "EVENT_STATUS_UPDATE 回执已 CONFIRMED。",
        isConfirmedApplicableWriteback: true,
      };
    }
    if (status === "failed" || status === "conflict") {
      return {
        label: STATUS_LABELS[status] ?? status,
        tone: "error",
        tooltip: `终态 EVENT_STATUS_UPDATE 写回状态：${status}。`,
        isConfirmedApplicableWriteback: false,
      };
    }
    if (status) {
      return {
        label: STATUS_LABELS[status] ?? status,
        tone: "info",
        tooltip: `终态 EVENT_STATUS_UPDATE 写回状态：${status}。`,
        isConfirmedApplicableWriteback: false,
      };
    }
    return {
      label: "终态写回待确认",
      tone: "info",
      tooltip: "终态 EVENT_STATUS_UPDATE 尚无确认回执。",
      isConfirmedApplicableWriteback: false,
    };
  }

  if (
    actionDisplay &&
    !actionDisplay.isConfirmedApplicableWriteback &&
    matchingAction?.writeback_required &&
    !matchingAction?.writeback_applicable
  ) {
    if (status === "accepted") {
      return {
        label: "实体侧效应已提交",
        tone: "info",
        tooltip:
          "entity_action_submit 可能停在 ACCEPTED；这不代表事件终态写回已完成。",
        isConfirmedApplicableWriteback: false,
      };
    }
    if (status === "confirmed") {
      return {
        label: "实体侧效应已确认",
        tone: "info",
        tooltip:
          "实体动作回执已确认，但不承担终态 disposition；不得以本行代替 EVENT_STATUS_UPDATE。",
        isConfirmedApplicableWriteback: false,
      };
    }
    return actionDisplay;
  }

  if (intentKind === "entity_action_submit" && status === "accepted") {
    return {
      label: "实体侧效应已提交",
      tone: "info",
      tooltip: "entity_action_submit 已提交；终态写回以 EVENT_STATUS_UPDATE 为准。",
      isConfirmedApplicableWriteback: false,
    };
  }

  if (status === "confirmed") {
    return {
      label: STATUS_LABELS.confirmed,
      tone: "success",
      tooltip: "写回回执已确认。",
      isConfirmedApplicableWriteback: Boolean(matchingAction?.writeback_applicable),
    };
  }

  if (status) {
    return {
      label: STATUS_LABELS[status] ?? status,
      tone: status === "failed" || status === "conflict" ? "error" : "info",
      tooltip: `写回状态：${status}。`,
      isConfirmedApplicableWriteback: false,
    };
  }

  return {
    label: "暂无数据",
    tone: "neutral",
    tooltip: "尚无写回回执。",
    isConfirmedApplicableWriteback: false,
  };
}
