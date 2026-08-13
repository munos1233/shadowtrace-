import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Modal,
  Result,
  Row,
  Skeleton,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { ArrowLeftOutlined, ReloadOutlined } from "@ant-design/icons";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import type { ColumnsType } from "antd/es/table";
import { resolveWritebackReceiptDisplay } from "../utils/actionWritebackDisplay";
import ReportViewer from "../components/report/ReportViewer";
import { coerceInvestigationReport } from "../types/report";
import { ApiError } from "../services/apiClient";
import { generateReport } from "../services/eventApi";
import EventOverviewCard from "../components/event/EventOverviewCard";
import EventOperationalInsights from "../components/event/EventOperationalInsights";
import ActionWritebackStatus from "../components/event/ActionWritebackStatus";
import EventTodoBar from "../components/event/EventTodoBar";
import InvestigationPhaseBanner from "../components/event/InvestigationPhaseBanner";
import EntityList from "../components/event/EntityList";
import EvidenceList from "../components/event/EvidenceList";
import RiskScorePanel from "../components/event/RiskScorePanel";
import AgentStatusPanel from "../components/agent/AgentStatusPanel";
import EntityGraph from "../components/graph/EntityGraph";
import StorylineTimeline from "../components/storyline/StorylineTimeline";
import EventAuditPanel from "../components/audit/EventAuditPanel";
import EventChatPanel from "../components/chat/EventChatPanel";
import { isEventChatEnabled } from "../config/features";
import { listMemoryReviews } from "../services/knowledgeApi";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useEventDetail, type EventWriteback } from "../hooks/useEventDetail";
import type { Action } from "../types/action";
import type {
  ConnectorPublic,
  DispositionResponse,
  ExecutionJobResponse,
  TargetWritebackResult,
  WritebackStatus,
} from "../types/event";
import ApprovalActionModal from "../components/approval/ApprovalActionModal";
import {
  useApprovalStore,
  type ApprovalDecisionBody,
} from "../stores/approvalStore";
import { isApprovalUiDisabled } from "../config/auth";
import { showResumeFeedback } from "../utils/approvalFeedback";

const BASE_TAB_KEYS = [
  "source",
  "timeline",
  "graph",
  "evidence",
  "actions",
  "writeback",
  "audit",
] as const;

type BaseTabKey = (typeof BASE_TAB_KEYS)[number];
type TabKey = BaseTabKey | "chat" | "report";

function eventDetailTabKeys(): TabKey[] {
  const keys: TabKey[] = [...BASE_TAB_KEYS];
  if (isEventChatEnabled()) keys.push("chat");
  keys.push("report");
  return keys;
}

function activeTab(hash: string): TabKey {
  const keys = eventDetailTabKeys();
  const value = hash.replace(/^#/, "") as TabKey;
  return keys.includes(value) ? value : "source";
}

function JsonPreview({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <Typography.Text type="secondary">暂无数据</Typography.Text>;
  }
  return (
    <pre
      style={{
        margin: 0,
        maxHeight: 280,
        overflow: "auto",
        padding: 12,
        background: "#fafafa",
        borderRadius: 6,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function CapabilityTags({
  connector,
  keys,
}: {
  connector: ConnectorPublic;
  keys: string[];
}) {
  return (
    <Space wrap>
      {keys.map((key) => {
        const status = connector.capabilities[key] ?? "UNKNOWN";
        return (
          <Tag key={key} color={status === "SUPPORTED" ? "green" : "default"}>
            {key}: {status}
          </Tag>
        );
      })}
    </Space>
  );
}

const POST_VERIFY_ACTIVATED_STATUSES = new Set([
  "executing",
  "partial_success",
  "success",
  "failed",
  "unknown",
  "rolled_back",
]);

function isDeferredPostVerifyAction(action: Action): boolean {
  if (action.execution_phase !== "post_verify") return false;
  if (POST_VERIFY_ACTIVATED_STATUSES.has(action.status)) return false;
  return (
    action.status === "approved" ||
    action.status === "pending" ||
    action.status === "waiting_approval"
  );
}

const ACTION_NAME_LABELS: Record<string, string> = {
  generate_report: "自动生成分析报告",
};

function actionDisplayName(action: Action): string {
  return ACTION_NAME_LABELS[action.action_name] ?? action.action_name;
}

interface ActionsPanelProps {
  actions: Action[];
  onApprove: (actionId: string) => void;
  onReject: (actionId: string) => void;
  /** Disable inline approval buttons when the operator lacks approver/admin role (ISSUE-207). */
  approvalDisabled: boolean;
  /** action_id -> decided locally (approve/reject succeeded, awaiting re-sync).
   *  Prevents a second submit while the table is still stale (ISSUE-207 review). */
  decidedActionIds?: Record<string, boolean>;
}

function ActionsPanel({
  actions,
  onApprove,
  onReject,
  approvalDisabled,
  decidedActionIds = {},
}: ActionsPanelProps) {
  const columns: ColumnsType<Action> = [
    { title: "action_id", dataIndex: "action_id", width: 170 },
    {
      title: "动作",
      dataIndex: "action_name",
      width: 190,
      render: (_name: string, action) => actionDisplayName(action),
    },
    { title: "工具", dataIndex: "tool_name", width: 210 },
    {
      title: "执行阶段",
      dataIndex: "execution_phase",
      width: 190,
      render: (phase: Action["execution_phase"], action) =>
        isDeferredPostVerifyAction(action) ? (
          <Tag color="gold">待效果验证后激活</Tag>
        ) : (
          <Tag color={phase === "post_verify" ? "purple" : "blue"}>
            {phase === "post_verify" ? "POST_VERIFY" : "IMMEDIATE"}
          </Tag>
        ),
    },
    { title: "执行主体", dataIndex: "execution_owner", render: (value) => value || "暂无数据" },
    { title: "状态", dataIndex: "status", render: (value) => <Tag>{value}</Tag> },
    {
      title: "写回义务",
      key: "writeback_obligation",
      width: 120,
      render: (_value, action) =>
        action.writeback_required ? (
          <Tag color="blue">事件级</Tag>
        ) : (
          <Tag>无</Tag>
        ),
    },
    {
      title: "写回状态",
      key: "writeback_display",
      width: 240,
      render: (_value, action) => (
        <ActionWritebackStatus
          writeback_required={action.writeback_required}
          writeback_applicable={action.writeback_applicable}
          writeback_status={action.writeback_status}
          data-testid={`action-writeback-${action.action_id}`}
        />
      ),
    },
    { title: "目标", dataIndex: "target", render: (value) => value || "暂无数据" },
    {
      title: "审批",
      key: "approval",
      width: 130,
      fixed: "right",
      render: (_value: unknown, action) => {
        if (action.status !== "waiting_approval") return "—";
        if (decidedActionIds[action.action_id]) {
          return (
            <Typography.Text
              type="secondary"
              data-testid={`approval-decided-${action.action_id}`}
            >
              已处理，同步中…
            </Typography.Text>
          );
        }
        return (
          <Space size={4}>
            <Button
              size="small"
              type="link"
              disabled={approvalDisabled}
              data-testid={`approve-action-${action.action_id}`}
              onClick={() => onApprove(action.action_id)}
            >
              批准
            </Button>
            <Button
              size="small"
              type="link"
              danger
              disabled={approvalDisabled}
              data-testid={`reject-action-${action.action_id}`}
              onClick={() => onReject(action.action_id)}
            >
              拒绝
            </Button>
          </Space>
        );
      },
    },
  ];

  const systemActions = actions.filter((a) => a.action_category === "system");
  const securityActions = actions.filter((a) => a.action_category !== "system");

  const renderTable = (rows: Action[]) => (
    <Table
      rowKey="action_id"
      dataSource={rows}
      columns={columns}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      locale={{ emptyText: "暂无数据" }}
      scroll={{ x: 1300 }}
    />
  );

  return (
    <Tabs
      items={[
        {
          key: "system",
          label: `系统动作（${systemActions.length}）`,
          children: renderTable(systemActions),
        },
        {
          key: "security",
          label: `安全处置（${securityActions.length}）`,
          children: renderTable(securityActions),
        },
      ]}
    />
  );
}

interface WritebackRow {
  rowKey: string;
  disposition_id: string;
  writeback_id: string | null;
  action_id: string;
  status: WritebackStatus | null;
  confirmation_evidence: string | null;
  evidence_tier: EventWriteback["evidence_tier"];
  provider_job_id?: string | null;
  target_results: TargetWritebackResult[];
  simulated?: boolean;
  sequence?: number;
  closure_cycle?: number;
  intent_kind?: string;
  execution_owner?: string;
  execution_phase?: string;
  attempt?: number;
  terminal?: boolean;
}

function WritebackPanel({
  dispositions,
  writebacks,
  actions,
  executionJobs,
  terminalActionId,
  terminalWritebackId,
  closureCycle,
}: {
  dispositions: DispositionResponse[];
  writebacks: EventWriteback[];
  actions: Action[];
  executionJobs: ExecutionJobResponse[];
  terminalActionId?: string | null;
  terminalWritebackId?: string | null;
  closureCycle?: number;
}) {
  const rows = useMemo<WritebackRow[]>(() => {
    const writebackByDisposition = new Map(
      writebacks.map((item) => [item.disposition_id, item]),
    );
    const dispositionRows = dispositions.map((item) => {
      const disposition = item.disposition;
      const writeback = writebackByDisposition.get(disposition.disposition_id);
      const actionId = writeback?.action_id ?? disposition.action_id;
      const matchingAction = actions.find((candidate) => candidate.action_id === actionId);
      const job = executionJobs.find((candidate) => candidate.action_id === actionId);
      return {
        rowKey: writeback?.writeback_id ?? disposition.disposition_id,
        disposition_id: disposition.disposition_id,
        writeback_id: writeback?.writeback_id ?? null,
        action_id: actionId,
        status: writeback?.status ?? item.writeback_status,
        confirmation_evidence: writeback?.confirmation_evidence ?? null,
        evidence_tier: writeback?.evidence_tier ?? null,
        provider_job_id: writeback?.provider_job_id,
        target_results: writeback?.target_results ?? [],
        simulated: writeback?.simulated,
        sequence: writeback?.sequence,
        closure_cycle: disposition.closure_cycle,
        intent_kind: disposition.intent_kind,
        execution_owner:
          disposition.execution_owner ?? matchingAction?.execution_owner ?? undefined,
        execution_phase: matchingAction?.execution_phase,
        attempt: job?.attempt,
        terminal:
          (closureCycle === undefined || disposition.closure_cycle === closureCycle) &&
          (writeback?.writeback_id === terminalWritebackId || actionId === terminalActionId),
      };
    });
    const knownDispositionIds = new Set(
      dispositions.map((item) => item.disposition.disposition_id),
    );
    const orphanReceipts = writebacks
      .filter((item) => !knownDispositionIds.has(item.disposition_id))
      .map((writeback) => {
        const action = actions.find((item) => item.action_id === writeback.action_id);
        const job = executionJobs.find((item) => item.action_id === writeback.action_id);
        return {
          rowKey: writeback.writeback_id,
          disposition_id: writeback.disposition_id,
          writeback_id: writeback.writeback_id,
          action_id: writeback.action_id,
          status: writeback.status,
          confirmation_evidence: writeback.confirmation_evidence,
          evidence_tier: writeback.evidence_tier,
          provider_job_id: writeback.provider_job_id,
          target_results: writeback.target_results,
          simulated: writeback.simulated,
          sequence: writeback.sequence,
          execution_owner: action?.execution_owner ?? undefined,
          execution_phase: action?.execution_phase,
          attempt: job?.attempt,
          terminal:
            writeback.writeback_id === terminalWritebackId ||
            writeback.action_id === terminalActionId,
        };
      });
    return [...dispositionRows, ...orphanReceipts];
  }, [
    actions,
    closureCycle,
    dispositions,
    executionJobs,
    terminalActionId,
    terminalWritebackId,
    writebacks,
  ]);

  const columns: ColumnsType<WritebackRow> = [
    { title: "disposition_id", dataIndex: "disposition_id", width: 180 },
    {
      title: "writeback_id",
      dataIndex: "writeback_id",
      width: 180,
      render: (value) => value || "暂无数据",
    },
    { title: "action_id", dataIndex: "action_id", width: 170 },
    {
      title: "execution_owner",
      dataIndex: "execution_owner",
      width: 150,
      render: (value) => value || "暂无数据",
    },
    {
      title: "execution_phase",
      dataIndex: "execution_phase",
      width: 150,
      render: (value) => value || "暂无数据",
    },
    {
      title: "writeback_status",
      dataIndex: "status",
      width: 200,
      render: (value: WritebackStatus | null, row) => {
        const matchingAction = actions.find((item) => item.action_id === row.action_id);
        const display = resolveWritebackReceiptDisplay({
          status: value,
          intentKind: row.intent_kind,
          matchingAction,
          terminal: row.terminal,
        });
        const color =
          display.tone === "success"
            ? "green"
            : display.tone === "error"
              ? "red"
              : display.tone === "warning"
                ? "gold"
                : "blue";
        return (
          <Space direction="vertical" size={2}>
            <Tooltip title={display.tooltip}>
              <Tag color={display.tone === "neutral" ? "default" : color}>
                {display.label}
              </Tag>
            </Tooltip>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              证据：{row.confirmation_evidence || "暂无数据"}
              {row.evidence_tier ? `（${row.evidence_tier}）` : ""}
            </Typography.Text>
          </Space>
        );
      },
    },
    {
      title: "provider_job_id",
      dataIndex: "provider_job_id",
      width: 170,
      render: (value) => value || "暂无数据",
    },
    {
      title: "目标结果",
      dataIndex: "target_results",
      width: 220,
      render: (targets: EventWriteback["target_results"]) =>
        targets.length === 0 ? (
          "暂无数据"
        ) : (
          <Space direction="vertical" size={2}>
            {targets.map((target) => (
              <Typography.Text key={`${target.canonical_target}-${target.status}`}>
                {target.canonical_target}: {target.status}
              </Typography.Text>
            ))}
          </Space>
        ),
    },
    {
      title: "重试/冲突",
      width: 130,
      render: (_, row) => (
        <Space direction="vertical" size={2}>
          <span>
            重试{" "}
            {row.attempt === undefined && row.sequence === undefined
              ? "暂无数据"
              : `${Math.max(0, (row.attempt ?? row.sequence ?? 1) - 1)} 次`}
          </span>
          {row.status === "conflict" && <Tag color="red">存在冲突</Tag>}
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size={12} style={{ width: "100%" }}>
      <Alert
        type="info"
        showIcon
        message="外部同步状态只依据适配器 DispositionReceipt 展示；本地动作成功或单次 HTTP ACK 不代表外部系统已完成写入。"
      />
      {rows.some((row) => row.simulated) && (
        <Alert
          type="warning"
          showIcon
          message="包含模拟回执（SIMULATED），仅用于演示，不代表真实外部系统状态。"
          data-testid="simulated-receipt-warning"
        />
      )}
      {terminalWritebackId && (
        <Typography.Text>
          当前 closure_cycle：{closureCycle ?? "暂无数据"}；终态 EVENT_STATUS_UPDATE：{" "}
          <Typography.Text code>{terminalWritebackId}</Typography.Text>
        </Typography.Text>
      )}
      <Table
        rowKey="rowKey"
        dataSource={rows}
        columns={columns}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: "暂无数据" }}
        scroll={{ x: 1600 }}
        onRow={(row) => ({
          "data-testid": `writeback-row-${row.writeback_id ?? row.disposition_id}`,
          style: row.terminal
            ? { background: "rgba(82, 196, 26, 0.10)", borderLeft: "3px solid #52c41a" }
            : undefined,
        })}
      />
    </Space>
  );
}

export default function EventDetailPage() {
  const { eventId } = useParams<{ eventId: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const {
    event,
    traces,
    actions,
    executionJobs,
    dispositions,
    writebacks,
    sourceRecord,
    connectors,
    evidenceDetail,
    loading,
    refresh,
  } = useEventDetail(eventId);
  const selectedTab = activeTab(location.hash);
  const [pendingMemoryReviewCount, setPendingMemoryReviewCount] = useState(0);
  const { approve, reject } = useApprovalStore();
  const [approvalModal, setApprovalModal] = useState<{
    open: boolean;
    actionId: string | null;
    mode: "approve" | "reject";
  }>({ open: false, actionId: null, mode: "approve" });
  const [approvalSubmitting, setApprovalSubmitting] = useState(false);
  // Locally decided actions (approve/reject succeeded, awaiting re-sync) —
  // blocks a duplicate submit if the follow-up refresh fails (ISSUE-207 review).
  const [decidedActionIds, setDecidedActionIds] = useState<Record<string, boolean>>({});

  const approvalDisabled = isApprovalUiDisabled();

  const openApprovalModal = (actionId: string, mode: "approve" | "reject") => {
    setApprovalModal({ open: true, actionId, mode });
  };

  const handleApprovalCancel = () => {
    setApprovalModal({ open: false, actionId: null, mode: "approve" });
  };

  const handleApprovalConfirm = async (actionId: string, body: ApprovalDecisionBody) => {
    setApprovalSubmitting(true);
    try {
      const result =
        approvalModal.mode === "approve"
          ? await approve(actionId, body)
          : await reject(actionId, body);
      setApprovalModal({ open: false, actionId: null, mode: "approve" });
      setDecidedActionIds((prev) => ({ ...prev, [actionId]: true }));
      showResumeFeedback(actionId, approvalModal.mode, result);
      // Locked refresh (ISSUE-207): re-pull the actions table (ActionsPanel data
      // source) and the event so the todo bar recomputes — not just a toast.
      const [actionsRefresh, eventRefresh] = await Promise.all([
        refresh("actions"),
        refresh("event"),
      ]);
      if (!actionsRefresh.actionsOk || !eventRefresh.eventOk) {
        // Approval itself succeeded; only the re-sync failed — surface it as a
        // refresh problem, never as an approval failure (ISSUE-207 review).
        message.warning("审批已成功，但页面刷新失败，请手动刷新查看最新状态。");
      }
    } catch (err: unknown) {
      if (err instanceof ApiError && err.error_code === "approval_decision_conflict") {
        // Another approver already decided this action: mark it locally decided
        // BEFORE re-syncing so a failed refresh cannot leave a stale approve
        // button behind for more 409s (ISSUE-207 review).
        setApprovalModal({ open: false, actionId: null, mode: "approve" });
        setDecidedActionIds((prev) => ({ ...prev, [actionId]: true }));
        const [actionsRefresh, eventRefresh] = await Promise.all([
          refresh("actions"),
          refresh("event"),
        ]);
        const refreshed = actionsRefresh.actionsOk && eventRefresh.eventOk;
        message.warning(
          refreshed
            ? "该审批已由其他审批者处理，已刷新最新状态。"
            : "该审批已由其他审批者处理，但页面刷新未完成，请手动刷新查看最新状态。",
        );
        return;
      }
      if (err instanceof ApiError && err.error_code === "forbidden") {
        message.error("无审批权限（403）：需要 approver 角色，请联系管理员授权。");
      } else if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "审批操作失败");
      } else {
        message.error("审批操作失败");
      }
      // Re-throw so ApprovalActionModal keeps the reject reason / comment (ISSUE-207).
      throw err;
    } finally {
      setApprovalSubmitting(false);
    }
  };

  // ISSUE-206: on-demand report generation with ISSUE-212 quality-gate handling.
  const [reportGenerating, setReportGenerating] = useState(false);
  const [regenerateOpen, setRegenerateOpen] = useState(false);
  const [qualityConfirm, setQualityConfirm] = useState<{
    open: boolean;
    errorCode: "report_quality_incomplete" | "report_quality_conflict";
    retryParams: { force?: boolean; confirm_downgrade?: boolean };
  }>({ open: false, errorCode: "report_quality_incomplete", retryParams: {} });

  const handleGenerateReport = async (
    params?: { force?: boolean; confirm_downgrade?: boolean },
  ) => {
    if (!eventId) return;
    setReportGenerating(true);
    try {
      await generateReport(eventId, params);
      message.success("报告已生成");
      setQualityConfirm((q) => ({ ...q, open: false }));
      setRegenerateOpen(false);
      // Refresh the event snapshot — socket report_generated also re-pulls the
      // event. If the re-sync fails, say so instead of pretending it succeeded.
      const { eventOk } = await refresh("event");
      if (!eventOk) {
        message.warning("报告已生成，但页面同步失败，请刷新查看最新状态。");
      }
    } catch (err: unknown) {
      if (err instanceof ApiError && err.error_code === "report_quality_incomplete") {
        message.error("报告质量不完整：存在占位章节。可强制生成以存档降级件。");
        setRegenerateOpen(false);
        setQualityConfirm({
          open: true,
          errorCode: "report_quality_incomplete",
          retryParams: { force: true },
        });
      } else if (err instanceof ApiError && err.error_code === "report_quality_conflict") {
        message.warning("已有完整报告：覆盖为降级报告需确认降级。");
        setRegenerateOpen(false);
        setQualityConfirm({
          open: true,
          errorCode: "report_quality_conflict",
          retryParams: { confirm_downgrade: true },
        });
      } else if (err instanceof ApiError && err.error_code === "invalid_state_transition") {
        message.error("分析尚未完成，请待事件进入「报告生成」状态后再生成报告。");
      } else if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "报告生成失败");
      } else {
        message.error("报告生成失败");
      }
    } finally {
      setReportGenerating(false);
    }
  };

  const navigateTab = useCallback(
    (tabKey: string) => {
      navigate(
        { pathname: location.pathname, search: location.search, hash: tabKey },
        { replace: true },
      );
    },
    [location.pathname, location.search, navigate],
  );

  // Pending memory reviews: API has no event_id filter yet; client-side match only.
  useEffect(() => {
    if (!eventId) return;
    let cancelled = false;
    void listMemoryReviews()
      .then((response) => {
        if (cancelled) return;
        const count = response.data.items.filter((item) => {
          if (item.status !== "pending") return false;
          const payload = item.payload;
          const sourceEventId =
            (typeof payload.event_id === "string" && payload.event_id) ||
            (typeof payload.source_event_id === "string" && payload.source_event_id) ||
            "";
          return sourceEventId === eventId;
        }).length;
        setPendingMemoryReviewCount(count);
      })
      .catch(() => {
        if (!cancelled) setPendingMemoryReviewCount(0);
      });
    return () => {
      cancelled = true;
    };
  }, [eventId, event?.event.updated_at]);

  useEffect(() => {
    const raw = location.hash.replace(/^#/, "");
    if (!eventDetailTabKeys().includes(raw as TabKey)) {
      navigate(
        { pathname: location.pathname, search: location.search, hash: "source" },
        { replace: true },
      );
    }
  }, [location.hash, location.pathname, location.search, navigate]);

  if (loading && !event) {
    return <Skeleton active paragraph={{ rows: 12 }} />;
  }
  if (!event || !eventId) {
    return (
      <Result
        status="warning"
        title="事件详情暂不可用"
        subTitle="暂无数据，请稍后刷新。"
        extra={<Button onClick={() => void refresh()}>重新加载</Button>}
      />
    );
  }

  const context = event.event.event_context_snapshot;
  const evidenceOutput = evidenceDetail ?? context?.evidence_output;
  const triageContext =
    evidenceDetail?.triage_context ?? triageContextFromSnapshot(context) ?? null;
  const writebackSummary = context?.writeback_summary;

  const sourceContent = (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <Card title="冻结研判快照" size="small">
          <JsonPreview value={context?.source_snapshot ?? event.event.raw_alert_snapshot} />
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="当前源对象状态" size="small">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="source_record_id">
              {sourceRecord?.source_record_id ?? event.event.current_primary_source_record_id ?? "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="source disposition">
              {sourceRecord?.current_source_disposition ??
                context?.source_sync_state?.disposition ??
                "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="source sync state">
              {sourceRecord?.source_sync_state ?? "暂无数据"}
            </Descriptions.Item>
          </Descriptions>
          <JsonPreview value={context?.source_sync_state} />
        </Card>
      </Col>
      <Col span={24}>
        <Card title="Connector 读写能力" size="small">
          {connectors.length === 0 ? (
            <Typography.Text type="secondary">暂无数据</Typography.Text>
          ) : (
            <Space direction="vertical" size={14}>
              {connectors.map((connector) => (
                <div key={connector.connector_id}>
                  <Typography.Text strong>
                    {connector.display_name}（{connector.status}）
                  </Typography.Text>
                  <div style={{ marginTop: 6 }}>
                    <Typography.Text type="secondary">读取：</Typography.Text>{" "}
                    <CapabilityTags connector={connector} keys={["LOG_INGESTION", "QUERY"]} />
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <Typography.Text type="secondary">写入：</Typography.Text>{" "}
                    <CapabilityTags
                      connector={connector}
                      keys={["EVENT_DISPOSITION", "ENTITY_RESPONSE"]}
                    />
                  </div>
                </div>
              ))}
            </Space>
          )}
        </Card>
      </Col>
      <Col span={24}>
        <Card title="Detection Context 溯源" size="small">
          {event.detection_context_snapshot ? (
            <Descriptions column={1} size="small">
              <Descriptions.Item label="snapshot_id">
                {event.detection_context_snapshot.snapshot_id}
              </Descriptions.Item>
              <Descriptions.Item label="revision">
                {event.detection_context_snapshot.revision}
              </Descriptions.Item>
              <Descriptions.Item label="content_hash">
                {event.detection_context_snapshot.content_hash}
              </Descriptions.Item>
              <Descriptions.Item label="promotion_id">
                {event.detection_context_snapshot.promotion_id}
              </Descriptions.Item>
              <Descriptions.Item label="promotion_link_revision">
                {event.detection_context_snapshot.promotion_link_revision}
              </Descriptions.Item>
              <Descriptions.Item label="event_revision">
                {event.detection_context_snapshot.event_revision}
              </Descriptions.Item>
              <Descriptions.Item label="created_at">
                {event.detection_context_snapshot.created_at ?? "暂无数据"}
              </Descriptions.Item>
            </Descriptions>
          ) : event.detection_context_projection_error ? (
            <Descriptions column={1} size="small">
              <Descriptions.Item label="promotion_id">
                {event.detection_context_projection_error.promotion_id}
              </Descriptions.Item>
              <Descriptions.Item label="reason">
                {event.detection_context_projection_error.reason}
              </Descriptions.Item>
              <Descriptions.Item label="message">
                {event.detection_context_projection_error.message}
              </Descriptions.Item>
              <Descriptions.Item label="recorded_at">
                {event.detection_context_projection_error.recorded_at ?? "暂无数据"}
              </Descriptions.Item>
            </Descriptions>
          ) : (
            <Typography.Text type="secondary">暂无 detection context snapshot</Typography.Text>
          )}
        </Card>
      </Col>
    </Row>
  );

  const items = [
    { key: "source", label: "来源对象", children: sourceContent },
    {
      key: "timeline",
      label: "攻击故事线",
      children: (
        <StorylineTimeline
          eventId={eventId}
          evidence={evidenceOutput?.evidence_list ?? []}
          refreshToken={event.event.updated_at}
        />
      ),
    },
    {
      key: "graph",
      label: "攻击图谱",
      children: (
        <EntityGraph
          eventId={eventId}
          refreshToken={event.event.updated_at}
        />
      ),
    },
    {
      key: "evidence",
      label: `证据（${evidenceOutput?.evidence_list?.length ?? 0}）`,
      children: (
        <EvidenceList
          evidence={evidenceOutput?.evidence_list ?? []}
          conflicts={evidenceOutput?.conflicts ?? []}
          gaps={evidenceOutput?.gaps ?? []}
          collectionStatus={evidenceOutput?.collection_status}
          successSources={evidenceOutput?.success_sources ?? []}
          failedSources={evidenceOutput?.failed_sources ?? []}
          querySummary={evidenceDetail?.query_summary ?? []}
          triageContext={triageContext}
        />
      ),
    },
    {
      key: "actions",
      label: `处置动作（${actions.length}）`,
      children: (
        <>
          {actions.some((a) => a.status === "waiting_approval") && approvalDisabled && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              message="当前角色无审批权限"
              description="内联批准/拒绝需要 approver 或 admin 角色，按钮已禁用；请使用具备审批角色的账号操作。"
              data-testid="approval-role-hint"
            />
          )}
          <ActionsPanel
            actions={actions}
            onApprove={(actionId) => openApprovalModal(actionId, "approve")}
            onReject={(actionId) => openApprovalModal(actionId, "reject")}
            approvalDisabled={approvalDisabled}
            decidedActionIds={decidedActionIds}
          />
        </>
      ),
    },
    {
      key: "writeback",
      label: `外部写回（${writebacks.length}）`,
      children: (
        <WritebackPanel
          dispositions={dispositions}
          writebacks={writebacks}
          actions={actions}
          executionJobs={executionJobs}
          terminalActionId={writebackSummary?.terminal_event_action_id}
          terminalWritebackId={writebackSummary?.terminal_event_writeback_id}
          closureCycle={writebackSummary?.closure_cycle}
        />
      ),
    },
    {
      key: "audit",
      label: "审计",
      children: (
        <EventAuditPanel eventId={eventId} qualityScores={context?.quality_scores} />
      ),
    },
    ...(isEventChatEnabled()
      ? [
          {
            key: "chat" as const,
            label: "问答",
            children: <EventChatPanel eventId={eventId} />,
          },
        ]
      : []),
    {
      key: "report",
      label: "报告",
      children: (
        <ReportViewer
          report={coerceInvestigationReport(context?.report)}
          loading={loading}
          eventStatus={event.event.status}
          onGenerate={() => void handleGenerateReport()}
          onRegenerate={() => setRegenerateOpen(true)}
          generating={reportGenerating}
        />
      ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Space className="shadowtrace-event-toolbar">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/events")}>
          返回事件列表
        </Button>
        <Button
          icon={<ReloadOutlined />}
          loading={loading}
          onClick={() => void refresh()}
          data-testid="refresh-event-detail"
        >
          刷新
        </Button>
      </Space>
      <EventOverviewCard
        detail={event}
        onRefresh={async () => {
          await refresh("all");
        }}
      />
      <InvestigationPhaseBanner detail={event} />
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <EventTodoBar
            detail={event}
            actions={actions}
            writebacks={writebacks}
            evidenceDetail={evidenceDetail}
            pendingMemoryReviewCount={pendingMemoryReviewCount}
            onNavigateTab={navigateTab}
            onRefresh={async () => {
              await refresh("all");
            }}
          />
        </Col>
        <Col xs={24} xl={10}>
          <EventOperationalInsights
            detail={event}
            writebacks={writebacks}
            onNavigateTab={navigateTab}
          />
        </Col>
      </Row>
      <AgentStatusPanel
        eventId={eventId}
        eventStatus={event.event.status}
        traces={traces}
      />
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <EntityList entities={event.event.entities} />
        </Col>
        <Col xs={24} xl={14}>
          <RiskScorePanel
            assessment={context?.risk_assessment}
            fallbackScore={event.event.risk_score}
            finalVerdict={event.event.final_verdict}
          />
        </Col>
      </Row>
      <Card className="shadowtrace-event-tabs">
        <Tabs
          activeKey={selectedTab}
          destroyOnHidden
          items={items}
          onChange={(key) =>
            navigate(
              { pathname: location.pathname, search: location.search, hash: key },
              { replace: true },
            )
          }
        />
      </Card>
      <ApprovalActionModal
        open={approvalModal.open}
        actionId={approvalModal.actionId}
        mode={approvalModal.mode}
        loading={approvalSubmitting}
        onConfirm={handleApprovalConfirm}
        onCancel={handleApprovalCancel}
      />

      <Modal
        title="重新生成报告"
        open={regenerateOpen}
        okText="重新生成"
        cancelText="取消"
        confirmLoading={reportGenerating}
        onOk={() => void handleGenerateReport()}
        onCancel={() => setRegenerateOpen(false)}
        data-testid="report-regenerate-modal"
      >
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          重新生成将基于当前调查上下文重建正式报告，并再次经过质量门校验。
        </Typography.Paragraph>
      </Modal>

      <Modal
        title={qualityConfirm.errorCode === "report_quality_conflict" ? "确认覆盖完整报告" : "强制生成降级报告"}
        open={qualityConfirm.open}
        okText={qualityConfirm.errorCode === "report_quality_conflict" ? "确认覆盖" : "强制生成"}
        cancelText="取消"
        confirmLoading={reportGenerating}
        onOk={() => void handleGenerateReport(qualityConfirm.retryParams)}
        onCancel={() => setQualityConfirm((q) => ({ ...q, open: false }))}
        data-testid="report-quality-confirm-modal"
      >
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          {qualityConfirm.errorCode === "report_quality_conflict"
            ? "目标报告将用降级质量覆盖现有完整报告，覆盖后原完整报告不可恢复。"
            : "报告存在占位章节，强制生成将把当前版本存档为降级件（incomplete_placeholder），不视为完整合格报告。"}
        </Typography.Paragraph>
      </Modal>
    </Space>
  );
}
