/** ApprovalCenterPage — approval queue with cards and real-time updates (ISSUE-073). */

import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Typography, Space, Empty, Spin, Alert, message } from "antd";
import { CheckCircleOutlined } from "@ant-design/icons";
import {
  useApprovalStore,
  loadRevisionProgress,
  revisionProgressKey,
  isActionTimedOut,
  type ApprovalDecisionBody,
  type RevisionProgress,
} from "../stores/approvalStore";
import ApprovalCard from "../components/approval/ApprovalCard";
import ApprovalActionModal from "../components/approval/ApprovalActionModal";
import { ApiError } from "../services/apiClient";
import type { Action } from "../types/action";

const { Title, Text } = Typography;

interface ModalState {
  open: boolean;
  actionId: string | null;
  mode: "approve" | "reject";
}

export default function ApprovalPage() {
  const {
    pendingApprovals,
    eventPendingApprovals,
    loading,
    error,
    eventLoading,
    eventError,
    approvalDeadlines,
    loadPendingApprovals,
    loadPendingApprovalsForEvent,
    clearEventScope,
    refreshEventIds,
    approve,
    reject,
  } = useApprovalStore();

  const [modal, setModal] = useState<ModalState>({ open: false, actionId: null, mode: "approve" });
  const [submitting, setSubmitting] = useState(false);
  const [revisionProgress, setRevisionProgress] = useState<Map<string, RevisionProgress>>(
    new Map(),
  );
  const [searchParams] = useSearchParams();
  const eventFilter = searchParams.get("event_id");

  useEffect(() => {
    // Deep link: query the target event directly (it may be beyond the first
    // 200 events of the global board) into the isolated scoped state. The
    // global queue / polling keeps its own _eventIds and is never narrowed.
    if (eventFilter) {
      void loadPendingApprovalsForEvent(eventFilter);
    } else {
      void refreshEventIds().then((ids) => loadPendingApprovals(ids));
    }
    return () => clearEventScope();
  }, [
    clearEventScope,
    eventFilter,
    loadPendingApprovals,
    loadPendingApprovalsForEvent,
    refreshEventIds,
  ]);

  // ?event_id= deep link from the event-detail todo bar CTA (ISSUE-207):
  // scoped state for the deep link, global queue otherwise.
  const visibleApprovals = useMemo(() => {
    if (!eventFilter) return pendingApprovals;
    return eventPendingApprovals;
  }, [eventFilter, eventPendingApprovals, pendingApprovals]);

  // Scoped loading/error are isolated from the global poll's (ISSUE-207 review).
  const activeLoading = eventFilter ? eventLoading : loading;
  const activeError = eventFilter ? eventError : error;

  useEffect(() => {
    if (visibleApprovals.length === 0) {
      setRevisionProgress(new Map());
      return;
    }
    let cancelled = false;
    void loadRevisionProgress(visibleApprovals).then((map) => {
      if (!cancelled) setRevisionProgress(map);
    });
    return () => {
      cancelled = true;
    };
  }, [visibleApprovals]);

  const groupedByEvent = useMemo(() => {
    const groups = new Map<string, Action[]>();
    for (const action of visibleApprovals) {
      const list = groups.get(action.event_id) ?? [];
      list.push(action);
      groups.set(action.event_id, list);
    }
    return [...groups.entries()].map(([eventId, actions]) => ({ eventId, actions }));
  }, [visibleApprovals]);

  const handleApprove = (actionId: string) => {
    setModal({ open: true, actionId, mode: "approve" });
  };

  const handleReject = (actionId: string) => {
    setModal({ open: true, actionId, mode: "reject" });
  };

  const handleConfirm = async (actionId: string, body: ApprovalDecisionBody) => {
    const action = visibleApprovals.find((a) => a.action_id === actionId);
    const eventId = action?.event_id;
    const remainingBefore = eventId
      ? visibleApprovals.filter((a) => a.event_id === eventId).length
      : 0;
    setSubmitting(true);
    try {
      if (modal.mode === "approve") {
        await approve(actionId, body);
      } else {
        if (!body.comment?.trim()) {
          message.error("拒绝必须填写原因");
          return;
        }
        await reject(actionId, body);
      }
      setModal({ open: false, actionId: null, mode: "approve" });
      if (eventId && remainingBefore > 1) {
        message.info("本事件仍有待审批动作，计划尚未全部决出。");
      }
    } catch (err: unknown) {
      // approve/reject skip the apiClient interceptor toast; surface errors here.
      if (err instanceof ApiError && err.error_code === "approval_decision_conflict") {
        // Another approver decided first — reload the queue instead of leaving
        // the stale card for the operator to retry into 409s. In deep-link mode
        // refresh the scoped event directly; otherwise the global queue.
        setModal({ open: false, actionId: null, mode: "approve" });
        const refreshed = eventFilter
          ? await loadPendingApprovalsForEvent(eventFilter)
          : await refreshEventIds().then((ids) => loadPendingApprovals(ids));
        const messageText =
          refreshed === "ok"
            ? "该审批已由其他审批者处理，已刷新最新状态。"
            : refreshed === "partial"
              ? "该审批已由其他审批者处理，部分事件刷新失败，请手动刷新查看最新状态。"
              : "该审批已由其他审批者处理，但刷新失败，请手动刷新查看最新状态。";
        message.warning(messageText);
      } else if (err instanceof ApiError && err.error_code === "forbidden") {
        message.error("无审批权限（403）：需要 approver 角色，请联系管理员授权。");
      } else if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "审批操作失败");
      } else {
        message.error("审批操作失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    setModal({ open: false, actionId: null, mode: "approve" });
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={3}>
        <CheckCircleOutlined style={{ marginRight: 8 }} />
        审批中心
      </Title>

      <Text type="secondary">
        需审批的处置动作。同一事件的审批计划需全部决出后方可进入执行。
        {visibleApprovals.length > 0 && (
          <span style={{ marginLeft: 16 }}>共 {visibleApprovals.length} 个待审批动作</span>
        )}
      </Text>

      {eventFilter && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={`仅显示事件 ${eventFilter} 的待审批动作`}
          action={<Link to="/approvals">查看全部</Link>}
          data-testid="approval-event-filter-hint"
        />
      )}

      {activeError && (
        <Alert message={activeError} type="error" showIcon style={{ marginBottom: 16 }} closable />
      )}

      <Spin spinning={activeLoading}>
        {visibleApprovals.length === 0 && !activeLoading ? (
          <Empty
            description={eventFilter ? "该事件暂无待审批动作" : "暂无待审批动作"}
            style={{ marginTop: 48 }}
          >
            <div style={{ maxWidth: 460, textAlign: "left", marginTop: 8 }}>
              <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
                待审批动作的产生条件：对事件发起「分析并生成处置方案」调查，且计划中包含
                L2+（或策略要求审批）的处置动作。仅「分析」调查不会产生待审批动作。
              </Typography.Paragraph>
              <Link to="/events" data-testid="approval-empty-goto-events">
                前往事件看板发起调查
              </Link>
            </div>
          </Empty>
        ) : (
          <Space direction="vertical" size="large" style={{ width: "100%", marginTop: 16 }}>
            {groupedByEvent.map(({ eventId, actions }) => {
              const sample = actions[0];
              const rev = sample.plan_revision ?? 0;
              const progress = revisionProgress.get(revisionProgressKey(eventId, rev));
              return (
                <Space key={eventId} direction="vertical" size="middle" style={{ width: "100%" }}>
                  <Alert
                    type="info"
                    showIcon
                    message={
                      progress
                        ? `事件 ${eventId} · revision ${rev} · 本 revision 已决出 ${progress.decided}/${progress.total}`
                        : `事件 ${eventId} · revision ${rev}`
                    }
                    description="同一计划须全部审批完（含 deferred）后才进入执行。"
                  />
                  {actions.map((action) => (
                    <ApprovalCard
                      key={action.action_id}
                      action={action}
                      deadline={approvalDeadlines[action.action_id]}
                      timedOut={isActionTimedOut(
                        action,
                        approvalDeadlines[action.action_id],
                      )}
                      onApprove={handleApprove}
                      onReject={handleReject}
                    />
                  ))}
                </Space>
              );
            })}
          </Space>
        )}
      </Spin>

      <ApprovalActionModal
        open={modal.open}
        actionId={modal.actionId}
        mode={modal.mode}
        loading={submitting}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
      />
    </div>
  );
}
