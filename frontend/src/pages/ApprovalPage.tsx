/** ApprovalCenterPage — approval queue with cards and real-time updates (ISSUE-073). */

import { useEffect, useState, useCallback } from "react";
import { Typography, Space, Empty, Spin, Alert } from "antd";
import { CheckCircleOutlined } from "@ant-design/icons";
import { useApprovalStore } from "../stores/approvalStore";
import { listEvents } from "../services/eventApi";
import ApprovalCard from "../components/approval/ApprovalCard";
import ApprovalActionModal from "../components/approval/ApprovalActionModal";

const { Title, Text } = Typography;

interface ModalState {
  open: boolean;
  actionId: string | null;
  mode: "approve" | "reject";
}

export default function ApprovalPage() {
  const {
    pendingApprovals,
    loading,
    error,
    loadPendingApprovals,
    approve,
    reject,
    startPolling,
    stopPolling,
  } = useApprovalStore();

  const [modal, setModal] = useState<ModalState>({ open: false, actionId: null, mode: "approve" });
  const [submitting, setSubmitting] = useState(false);

  // Fetch event IDs on mount — load from API, not eventStore
  useEffect(() => {
    listEvents({ page_size: 200 })
      .then((res) => {
        const ids = res.data.items.map((e: { event_id: string }) => e.event_id);
        loadPendingApprovals(ids);
        startPolling(ids);
      })
      .catch(() => { /* swallow */ });
    return () => stopPolling();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Check if an action has timed out (backend timeout is authoritative;
  // this is a front-end visual hint based on updated_at age > 30 min).
  const isTimedOut = useCallback(
    (action: { updated_at: string | null }) => {
      if (!action.updated_at) return false;
      const age = Date.now() - new Date(action.updated_at).getTime();
      return age > 30 * 60 * 1000;
    },
    [],
  );

  const handleApprove = (actionId: string) => {
    setModal({ open: true, actionId, mode: "approve" });
  };

  const handleReject = (actionId: string) => {
    setModal({ open: true, actionId, mode: "reject" });
  };

  const handleConfirm = async (actionId: string, comment?: string) => {
    setSubmitting(true);
    try {
      if (modal.mode === "approve") {
        await approve(actionId, comment);
      } else {
        await reject(actionId, comment ?? "");
      }
      setModal({ open: false, actionId: null, mode: "approve" });
    } catch {
      // API error toast already shown by apiClient interceptor
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
        {pendingApprovals.length > 0 && (
          <span style={{ marginLeft: 16 }}>共 {pendingApprovals.length} 个待审批动作</span>
        )}
      </Text>

      {error && (
        <Alert message={error} type="error" showIcon style={{ marginBottom: 16 }} closable />
      )}

      <Spin spinning={loading}>
        {pendingApprovals.length === 0 && !loading ? (
          <Empty description="暂无待审批动作" style={{ marginTop: 48 }} />
        ) : (
          <Space direction="vertical" size="middle" style={{ width: "100%", marginTop: 16 }}>
            {pendingApprovals.map((action) => (
              <ApprovalCard
                key={action.action_id}
                action={action}
                timedOut={isTimedOut(action)}
                onApprove={handleApprove}
                onReject={handleReject}
              />
            ))}
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
