import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Result,
  Row,
  Skeleton,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
} from "antd";
import { ArrowLeftOutlined, ReloadOutlined } from "@ant-design/icons";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import type { ColumnsType } from "antd/es/table";
import { triageContextFromSnapshot } from "../utils/evidenceContext";
import ReportViewer from "../components/report/ReportViewer";
import { coerceInvestigationReport } from "../types/report";
import EventOverviewCard from "../components/event/EventOverviewCard";
import EventOperationalInsights from "../components/event/EventOperationalInsights";
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

function ActionsPanel({ actions }: { actions: Action[] }) {
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
    { title: "目标", dataIndex: "target", render: (value) => value || "暂无数据" },
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
      scroll={{ x: 1100 }}
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
      width: 160,
      render: (value: WritebackStatus | null, row) => (
        <Space direction="vertical" size={2}>
          {value ? (
            <Tag color={value === "confirmed" ? "green" : value === "failed" || value === "conflict" ? "red" : "blue"}>
              {value}
            </Tag>
          ) : (
            <Typography.Text type="secondary">暂无数据</Typography.Text>
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            证据：{row.confirmation_evidence || "暂无数据"}
            {row.evidence_tier ? `（${row.evidence_tier}）` : ""}
          </Typography.Text>
        </Space>
      ),
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
    { key: "actions", label: `处置动作（${actions.length}）`, children: <ActionsPanel actions={actions} /> },
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
      <EventOverviewCard detail={event} />
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
            onRefresh={() => refresh("all")}
          />
        </Col>
        <Col xs={24} xl={10}>
          <EventOperationalInsights detail={event} writebacks={writebacks} />
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
    </Space>
  );
}
