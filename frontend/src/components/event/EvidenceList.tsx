import { Alert, Descriptions, Select, Space, Table, Tag, Tooltip, Typography } from "antd";
import { WarningOutlined } from "@ant-design/icons";
import { useMemo, useState } from "react";
import type { ColumnsType } from "antd/es/table";
import type {
  CollectionStatus,
  Evidence,
  EvidenceConflict,
  EvidenceGap,
  EvidenceQuerySummaryItem,
  EvidenceTriageContext,
} from "../../types/event";

const COLLECTION_STATUS_LABEL: Record<CollectionStatus, string> = {
  completed: "已完成（≥5 路有效源）",
  partial_done: "部分完成（3-4 路有效源）",
  degraded: "降级（1-2 路有效源）",
  failed: "失败（0 路有效源）",
};

const GAP_REASON_LABEL: Record<string, string> = {
  invalid_entity: "实体校验失败",
  source_skipped: "缺少所需实体，已跳过",
  no_records: "工具成功但无可用记录",
  triage_degraded: "分诊降级且无 Source 实体",
  tool_failed: "工具调用失败",
  missing_scope: "缺少证据查询范围",
  global_timeout: "全局采集超时",
};

const TOOL_OUTCOME_LABEL: Record<string, string> = {
  tool_ok: "工具成功且有记录",
  tool_ok_empty: "工具成功但无可用记录",
  tool_failed: "工具调用失败",
  source_skipped: "缺少所需实体，已跳过",
};

function conflictReason(evidenceId: string, conflicts: EvidenceConflict[]): string | null {
  const reasons = conflicts
    .filter((conflict) => conflict.evidence_ids.includes(evidenceId))
    .map((conflict) => conflict.description);
  return reasons.length > 0 ? reasons.join("；") : null;
}

function gapReasonLabel(reason: string): string {
  return GAP_REASON_LABEL[reason] ?? reason;
}

function toolOutcomeLabel(outcome: string): string {
  return TOOL_OUTCOME_LABEL[outcome] ?? outcome;
}

function isEmptyToolOutcome(item: EvidenceQuerySummaryItem): boolean {
  return (
    item.tool_outcome === "tool_ok_empty" ||
    item.status === "tool_ok_empty" ||
    item.gap_reason === "no_records"
  );
}

function buildEmptyExplanation(
  gaps: EvidenceGap[],
  collectionStatus: CollectionStatus | undefined,
  triageContext?: EvidenceTriageContext | null,
): string {
  const triageHints: string[] = [];
  if (triageContext?.degraded) {
    triageHints.push("分诊已降级");
  }
  if (triageContext?.degradation_reasons?.length) {
    triageHints.push(`分诊原因：${triageContext.degradation_reasons.join("；")}`);
  }
  if (gaps.length === 0) {
    if (triageHints.length > 0) {
      return `证据为空：${triageHints.join("；")}。`;
    }
    return collectionStatus === "failed"
      ? "证据采集未产出可展示记录，但未记录具体缺口原因。"
      : "暂无证据记录。";
  }
  const reasons = [...new Set(gaps.map((gap) => gapReasonLabel(gap.reason)))];
  const chain = [...triageHints, ...reasons].filter(Boolean);
  return `证据为空：${chain.join("；")}。请查看下方分诊上下文、缺口明细与采集摘要。`;
}

function collectionStatusDescription(
  collectionStatus: CollectionStatus,
  emptyResultSources: string[],
  querySummary: EvidenceQuerySummaryItem[],
): string | null {
  if (collectionStatus !== "failed") {
    return null;
  }
  const emptyTools = querySummary.filter(isEmptyToolOutcome).map((item) => item.tool_name);
  if (emptyResultSources.length > 0 || emptyTools.length > 0) {
    const parts = [
      "采集层判定为失败（0 路有效源，ISSUE-101 阈值未改）",
      "工具层存在成功但无可用记录（tool_ok_empty），并非工具调用故障",
    ];
    if (emptyTools.length > 0) {
      parts.push(`空结果工具：${emptyTools.join(", ")}`);
    }
    return parts.join("。") + "。";
  }
  return "采集层判定为失败（0 路有效源）。请结合缺口原因区分工具失败与实体跳过。";
}

function formatRejectionSummary(summary: Record<string, unknown>): string | null {
  const counts = summary.rejection_counts;
  if (typeof counts !== "object" || counts === null) {
    return null;
  }
  const parts = Object.entries(counts as Record<string, number>)
    .filter(([, count]) => count > 0)
    .map(([reason, count]) => `${reason}×${count}`);
  return parts.length > 0 ? parts.join("，") : null;
}

export default function EvidenceList({
  evidence,
  conflicts,
  gaps = [],
  collectionStatus,
  successSources = [],
  failedSources = [],
  querySummary = [],
  triageContext = null,
}: {
  evidence: Evidence[];
  conflicts: EvidenceConflict[];
  gaps?: EvidenceGap[];
  collectionStatus?: CollectionStatus;
  successSources?: string[];
  failedSources?: string[];
  querySummary?: EvidenceQuerySummaryItem[];
  triageContext?: EvidenceTriageContext | null;
}) {
  const [source, setSource] = useState<string>();
  const sources = useMemo(
    () => [...new Set(evidence.map((item) => item.source))].sort(),
    [evidence],
  );
  const rows = source ? evidence.filter((item) => item.source === source) : evidence;
  const emptyResultSources = useMemo(
    () => [...new Set(gaps.filter((gap) => gap.reason === "no_records").map((gap) => gap.missing_source))],
    [gaps],
  );
  const rejectionSummary = triageContext?.entity_rejection_summary
    ? formatRejectionSummary(triageContext.entity_rejection_summary)
    : null;
  const emptyExplanation = buildEmptyExplanation(gaps, collectionStatus, triageContext);
  const failedCollectionHint = collectionStatus
    ? collectionStatusDescription(collectionStatus, emptyResultSources, querySummary)
    : null;

  const gapColumns: ColumnsType<EvidenceGap> = [
    { title: "缺失源", dataIndex: "missing_source", width: 140 },
    {
      title: "原因",
      dataIndex: "reason",
      width: 180,
      render: (value: string) => (
        <Tag color={value === "no_records" ? "orange" : value === "tool_failed" ? "red" : "default"}>
          {gapReasonLabel(value)}
        </Tag>
      ),
    },
    {
      title: "说明",
      dataIndex: "detail",
      render: (detail: EvidenceGap["detail"]) => {
        const description =
          typeof detail?.description === "string" ? detail.description : null;
        const toolName = typeof detail?.tool_name === "string" ? detail.tool_name : null;
        return (
          <Typography.Text type="secondary">
            {[toolName, description].filter(Boolean).join(" — ") || "暂无数据"}
          </Typography.Text>
        );
      },
    },
  ];

  const summaryColumns: ColumnsType<EvidenceQuerySummaryItem> = [
    { title: "tool", dataIndex: "tool_name", width: 170 },
    { title: "source", dataIndex: "source", width: 130 },
    {
      title: "tool_outcome",
      dataIndex: "tool_outcome",
      width: 170,
      render: (value: string | null | undefined, record) => {
        const outcome = value || (record.status === "tool_ok_empty" ? "tool_ok_empty" : null);
        if (!outcome) {
          return <Tag>{record.status || "—"}</Tag>;
        }
        const color =
          outcome === "tool_ok_empty"
            ? "orange"
            : outcome === "tool_failed"
              ? "red"
              : outcome === "tool_ok"
                ? "green"
                : "default";
        return <Tag color={color}>{toolOutcomeLabel(outcome)}</Tag>;
      },
    },
    { title: "status", dataIndex: "status", width: 140 },
    { title: "records", dataIndex: "records_count", width: 90 },
    {
      title: "gap",
      dataIndex: "gap_reason",
      width: 160,
      render: (value: string | null | undefined) =>
        value ? <Tag>{gapReasonLabel(value)}</Tag> : <Tag>—</Tag>,
    },
    {
      title: "耗时(ms)",
      dataIndex: "execution_time_ms",
      width: 100,
    },
  ];

  const columns: ColumnsType<Evidence> = [
    { title: "evidence_id", dataIndex: "evidence_id", width: 170 },
    { title: "source", dataIndex: "source", width: 130 },
    { title: "evidence_type", dataIndex: "evidence_type", width: 150 },
    {
      title: "timestamp",
      dataIndex: "timestamp",
      width: 180,
      render: (value: string | null) => value || "暂无数据",
    },
    {
      title: "description",
      dataIndex: "description",
      render: (value: string, record) => {
        const reason = conflictReason(record.evidence_id, conflicts);
        const isConflicting = record.is_conflicting || Boolean(reason);
        return (
          <Space>
            <Typography.Text>{value || "暂无数据"}</Typography.Text>
            {isConflicting && (
              <Tooltip title={reason || "存在冲突，但暂无冲突原因"}>
                <Tag color="error" icon={<WarningOutlined />} data-testid={`evidence-conflict-${record.evidence_id}`}>
                  冲突证据
                </Tag>
              </Tooltip>
            )}
          </Space>
        );
      },
    },
    {
      title: "confidence",
      dataIndex: "confidence",
      width: 110,
      render: (value: number) => `${Math.round((value ?? 0) * 100)}%`,
    },
    {
      title: "is_conflicting",
      dataIndex: "is_conflicting",
      width: 120,
      render: (value: boolean, record) =>
        value || conflictReason(record.evidence_id, conflicts) ? (
          <Tag color="red">是</Tag>
        ) : (
          <Tag>否</Tag>
        ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      {triageContext && (
        <Alert
          type={triageContext.degraded ? "warning" : "info"}
          showIcon
          message="分诊上下文（上游）"
          description={
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="分诊降级">
                {triageContext.degraded ? "是" : "否"}
              </Descriptions.Item>
              <Descriptions.Item label="降级原因">
                {triageContext.degradation_reasons.length > 0
                  ? triageContext.degradation_reasons.join("；")
                  : "无"}
              </Descriptions.Item>
              <Descriptions.Item label="实体拒收摘要">
                {rejectionSummary ?? "无"}
              </Descriptions.Item>
            </Descriptions>
          }
          data-testid="evidence-triage-context"
        />
      )}

      {collectionStatus && (
        <Alert
          type={collectionStatus === "failed" ? "warning" : "info"}
          showIcon
          message={`采集状态：${COLLECTION_STATUS_LABEL[collectionStatus] ?? collectionStatus}`}
          description={
            <Space direction="vertical" size={8} style={{ width: "100%" }}>
              {failedCollectionHint ? (
                <Typography.Text data-testid="evidence-collection-failed-hint">
                  {failedCollectionHint}
                </Typography.Text>
              ) : null}
              <Descriptions size="small" column={3}>
                <Descriptions.Item label="有效源">
                  {successSources.length > 0 ? successSources.join(", ") : "无"}
                </Descriptions.Item>
                <Descriptions.Item label="失败/跳过源">
                  {failedSources.length > 0 ? failedSources.join(", ") : "无"}
                </Descriptions.Item>
                <Descriptions.Item label="空结果源">
                  {emptyResultSources.length > 0 ? emptyResultSources.join(", ") : "无"}
                </Descriptions.Item>
                <Descriptions.Item label="缺口数">{gaps.length}</Descriptions.Item>
              </Descriptions>
            </Space>
          }
          data-testid="evidence-collection-status"
        />
      )}

      {gaps.length > 0 && (
        <Table
          rowKey={(row) => `${row.missing_source}-${row.reason}-${row.event_id}`}
          columns={gapColumns}
          dataSource={gaps}
          pagination={false}
          size="small"
          title={() => "证据缺口"}
          data-testid="evidence-gaps-table"
        />
      )}

      {querySummary.length > 0 && (
        <Table
          rowKey="tool_name"
          columns={summaryColumns}
          dataSource={querySummary}
          pagination={false}
          size="small"
          title={() => "采集摘要（按工具）"}
          data-testid="evidence-query-summary"
        />
      )}

      <Select
        allowClear
        placeholder="按证据来源筛选"
        value={source}
        onChange={setSource}
        options={sources.map((item) => ({ label: item, value: item }))}
        style={{ width: 220 }}
        data-testid="evidence-source-filter"
      />
      <Table
        rowKey="evidence_id"
        columns={columns}
        dataSource={rows}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: emptyExplanation }}
        scroll={{ x: 1050 }}
        onRow={(record) => ({
          "data-testid": `evidence-row-${record.evidence_id}`,
          style: record.is_conflicting || conflictReason(record.evidence_id, conflicts)
            ? { background: "rgba(255, 77, 79, 0.08)", borderLeft: "3px solid #ff4d4f" }
            : undefined,
        })}
      />
    </Space>
  );
}
