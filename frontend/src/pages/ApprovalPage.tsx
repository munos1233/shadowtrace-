/** ApprovalCenterPage — approval queue with cards and real-time updates (ISSUE-073). */

import { useEffect, useState, useMemo, useCallback, useRef } from "react";
import { Typography, Space, Empty, Spin, Alert, Badge, Statistic, Row, Col } from "antd";
import { CheckCircleOutlined } from "@ant-design/icons";
import { useApprovalStore } from "../stores/approvalStore";
import { useEventStore } from "../stores/eventStore";
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

  const { items } = useEventStore();

  const [modal, setModal] = useState<ModalState>({
    open: false,
    actionId: null,
    mode: "approve",
  });
  const [submitting, setSubmitting] = useState(false);
  const polledRef = useRef(false);

  // Collect all event IDs that are currently active
  const eventIds = useMemo(() => items.map((e) => e.event_id), [items]);

  // One-time initialisation: load events + start polling
  useEffect(() => {
    if (polledRef.current) return;
    polledRef.current = true;

    loadPendingApprovals(eventIds);
    startPolling(eventIds);

    return () => {
      stopPolling();
    };
  }, [eventIds.length > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  // Count unique event_ids among pending approvals
  const eventPlanInfo = useMemo(() => {
    const map = new Map<string, { total: number; eventId: string }>();
    for (const a of pendingApprovals) {
      const existing = map.get(a.event_id);
      if (existing) {
        existing.total += 1;
      } else {
        map.set(a.event_id, { total: 1, eventId: a.event_id });
      }
    }
    return Array.from(map.values());
  }, [pendingApprovals]);

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
      </Text>

      {/* Per-event progress */}
      {eventPlanInfo.length > 0 && (
        <Row gutter={16} style={{ marginTop: 16, marginBottom: 16 }}>
          {eventPlanInfo.map((info) => (
            <Col key={info.eventId}>
              <Badge count={info.total} overflowCount={99}>
                <Statistic
                  title="待批动作"
                  value={info.total}
                  suffix={`/ ${info.eventId}`}
                  valueStyle={{ fontSize: 18 }}
                />
              </Badge>
            </Col>
          ))}
        </Row>
      )}

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
