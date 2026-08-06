/** Event detail todo bar + close/resolve actions (ISSUE-210). */

import {
  Alert,
  Button,
  Card,
  Input,
  Modal,
  Select,
  Space,
  Typography,
  message,
} from "antd";
import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import {
  closeEvent,
  resolveUnknownAction,
  resolveWriteback,
} from "../../services/eventApi";
import { ApiError } from "../../services/apiClient";
import { currentAuthRoles } from "../../config/auth";
import type { Action } from "../../types/action";
import type { EventDetailResponse, EventEvidenceResponse } from "../../types/event";
import type { EventWriteback } from "../../hooks/useEventDetail";
import {
  buildEventTodos,
  unknownActions,
  unknownWritebacks,
  type EventTodoItem,
} from "../../utils/eventTodos";

interface Props {
  detail: EventDetailResponse;
  actions: Action[];
  writebacks: EventWriteback[];
  evidenceDetail?: EventEvidenceResponse | null;
  pendingMemoryReviewCount?: number;
  onNavigateTab: (tabKey: string) => void;
  onRefresh: () => Promise<void>;
}

function todoColor(kind: EventTodoItem["kind"]): "success" | "warning" | "info" {
  switch (kind) {
    case "approval_pending":
    case "writeback_resolve":
    case "close_blocked":
      return "warning";
    case "close_ready":
      return "success";
    default:
      return "info";
  }
}

export default function EventTodoBar({
  detail,
  actions,
  writebacks,
  evidenceDetail = null,
  pendingMemoryReviewCount = 0,
  onNavigateTab,
  onRefresh,
}: Props) {
  const [closing, setClosing] = useState(false);
  const [closeOpen, setCloseOpen] = useState(false);
  const [closeReason, setCloseReason] = useState("operator closed from event detail");
  const [resolveOpen, setResolveOpen] = useState(false);
  const [resolveComment, setResolveComment] = useState("");
  const [resolveTarget, setResolveTarget] = useState<
    { kind: "action"; id: string } | { kind: "writeback"; id: string } | null
  >(null);
  const [resolving, setResolving] = useState(false);

  const roles = currentAuthRoles();
  // Backend close_event: require_roles(ROLE_ANALYST); admin bypasses via has_any_role.
  const canCloseRole = roles.includes("analyst") || roles.includes("admin");
  const canResolveRole = roles.includes("admin");

  const unknownAction = unknownActions(actions)[0];
  const unknownWriteback = unknownWritebacks(writebacks)[0];
  const hasResolveTarget = Boolean(unknownAction || unknownWriteback);

  const todos = useMemo(
    () =>
      buildEventTodos({
        detail,
        actions,
        writebacks,
        evidenceDetail,
        pendingMemoryReviewCount,
      }),
    [detail, actions, writebacks, evidenceDetail, pendingMemoryReviewCount],
  );

  const closeReady = todos.some((item) => item.kind === "close_ready");

  const handleClose = async () => {
    const reason = closeReason.trim();
    if (!reason) {
      message.warning("请填写结案原因");
      return;
    }
    setClosing(true);
    try {
      await closeEvent(detail.event.event_id, { reason });
      message.success("事件已结案");
      setCloseOpen(false);
      await onRefresh();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "结案失败");
      } else {
        message.error("结案失败");
      }
    } finally {
      setClosing(false);
    }
  };

  const openResolve = () => {
    if (unknownAction) {
      setResolveTarget({ kind: "action", id: unknownAction.action_id });
    } else if (unknownWriteback?.writeback_id) {
      setResolveTarget({ kind: "writeback", id: unknownWriteback.writeback_id });
    } else {
      message.info("当前没有 UNKNOWN 动作或写回可裁决");
      return;
    }
    setResolveComment("");
    setResolveOpen(true);
  };

  const submitResolve = async () => {
    if (!resolveTarget) return;
    const comment = resolveComment.trim();
    if (!comment) {
      message.warning("请填写裁决说明");
      return;
    }
    setResolving(true);
    try {
      if (resolveTarget.kind === "action") {
        await resolveUnknownAction(resolveTarget.id, {
          resolution: "manual_confirmed",
          comment,
        });
      } else {
        await resolveWriteback(resolveTarget.id, {
          resolution: "manual_confirmed",
          comment,
        });
      }
      message.success("已提交 UNKNOWN 裁决");
      setResolveOpen(false);
      await onRefresh();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "裁决失败");
      } else {
        message.error("裁决失败");
      }
    } finally {
      setResolving(false);
    }
  };

  return (
    <>
      <Card size="small" title="待办与下一步" data-testid="event-todo-bar">
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          {todos.map((item) => (
            <Alert
              key={item.id}
              type={todoColor(item.kind)}
              showIcon
              message={<Typography.Text strong>{item.label}</Typography.Text>}
              description={
                <Space direction="vertical" size={4}>
                  {item.description ? (
                    <Typography.Text type="secondary">{item.description}</Typography.Text>
                  ) : null}
                  <Space wrap>
                    {item.tabKey ? (
                      <Button
                        size="small"
                        type="link"
                        data-testid={`todo-nav-${item.id}`}
                        onClick={() => onNavigateTab(item.tabKey!)}
                      >
                        打开 Tab
                      </Button>
                    ) : null}
                    {item.externalHref ? (
                      <Link to={item.externalHref}>外部跳转</Link>
                    ) : null}
                  </Space>
                </Space>
              }
            />
          ))}

          <Space wrap>
            <Button
              type="primary"
              disabled={!closeReady || !canCloseRole}
              loading={closing}
              data-testid="event-close-button"
              onClick={() => setCloseOpen(true)}
            >
              结案
            </Button>
            {!canCloseRole && (
              <Typography.Text type="secondary">
                结案需 analyst 或 admin 角色
              </Typography.Text>
            )}
            <Button
              disabled={!hasResolveTarget || !canResolveRole}
              data-testid="event-resolve-unknown-button"
              onClick={openResolve}
            >
              裁决 UNKNOWN
            </Button>
            {hasResolveTarget && !canResolveRole && (
              <Typography.Text type="secondary">裁决 UNKNOWN 需 admin 角色</Typography.Text>
            )}
          </Space>
        </Space>
      </Card>

      <Modal
        title="结案事件"
        open={closeOpen}
        okText="确认结案"
        cancelText="取消"
        confirmLoading={closing}
        onOk={() => void handleClose()}
        onCancel={() => setCloseOpen(false)}
        destroyOnHidden
      >
        <Input.TextArea
          aria-label="结案原因"
          rows={3}
          value={closeReason}
          onChange={(event) => setCloseReason(event.target.value)}
        />
      </Modal>

      <Modal
        title="裁决 UNKNOWN"
        open={resolveOpen}
        okText="提交裁决"
        cancelText="取消"
        confirmLoading={resolving}
        onOk={() => void submitResolve()}
        onCancel={() => setResolveOpen(false)}
        destroyOnHidden
      >
        <Space direction="vertical" style={{ width: "100%" }}>
          <Typography.Text type="secondary">
            目标：{resolveTarget?.kind} / {resolveTarget?.id}
          </Typography.Text>
          <Select
            aria-label="裁决结果"
            value="manual_confirmed"
            options={[{ value: "manual_confirmed", label: "manual_confirmed" }]}
            disabled
          />
          <Input.TextArea
            aria-label="裁决说明"
            rows={3}
            value={resolveComment}
            onChange={(event) => setResolveComment(event.target.value)}
            placeholder="请说明人工确认依据"
          />
        </Space>
      </Modal>
    </>
  );
}
