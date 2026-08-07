/** EventTable — fixed-column event list table (ISSUE-068).

  Columns (fixed order):
    event_id | title | event_type | severity | status (本地状态) |
    final_verdict | risk_score | writeback_overall_status | created_at | 操作

  The "操作" column contains the "触发研判" button which calls triggerInvestigation.
  On 409 (investigation in progress) a warning toast is shown.
*/

import { useMemo } from "react";
import { Table, Button, Tag, Tooltip, Typography, Space } from "antd";
import type { ColumnsType } from "antd/es/table";
import { ExperimentOutlined } from "@ant-design/icons";
import type { EventListItem } from "../../types/event";
import StatusBadge from "./StatusBadge";
import SeverityTag from "./SeverityTag";
import VerdictTag from "./VerdictTag";
import WritebackBadge from "./WritebackBadge";
import {
  EVENT_TYPE_OPTIONS,
  NON_TRIGGERABLE_STATUSES,
  isListExternalUnsynced,
} from "./constants";
import {
  isHighRiskNoneMismatch,
  labelVerdictReasonCode,
  resolveVerdictDemotionCodes,
} from "../../utils/verdictObservability";

export interface EventTableProps {
  items: EventListItem[];
  loading: boolean;
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number, pageSize: number) => void;
  onTriggerInvestigation: (eventId: string) => void;
  /** Optional set of event_ids currently triggering (for button loading). */
  triggeringIds?: Set<string>;
  /** Navigate to event detail. */
  onRowClick?: (eventId: string) => void;
}

export default function EventTable({
  items,
  loading,
  total,
  page,
  pageSize,
  onPageChange,
  onTriggerInvestigation,
  triggeringIds,
  onRowClick,
}: EventTableProps) {
  const columns: ColumnsType<EventListItem> = useMemo(
    () => [
      {
        title: "Event ID",
        dataIndex: "event_id",
        key: "event_id",
        width: 160,
        ellipsis: true,
        render: (id: string) => (
          <Typography.Text code copyable={false} style={{ fontSize: 12 }}>
            {id}
          </Typography.Text>
        ),
      },
      {
        title: "标题",
        dataIndex: "title",
        key: "title",
        ellipsis: true,
        render: (title: string, record) =>
          onRowClick ? (
            <Tooltip title="点击查看详情">
              <a onClick={() => onRowClick(record.event_id)}>{title}</a>
            </Tooltip>
          ) : (
            <span>{title}</span>
          ),
      },
      {
        title: "事件类型",
        dataIndex: "event_type",
        key: "event_type",
        width: 120,
        render: (type: string) => {
          const opt = EVENT_TYPE_OPTIONS.find((o) => o.value === type);
          return <span>{opt?.label ?? type}</span>;
        },
      },
      {
        title: "严重度",
        dataIndex: "severity",
        key: "severity",
        width: 90,
        render: (severity: EventListItem["severity"]) => (
          <SeverityTag severity={severity} />
        ),
        sorter: (a, b) => {
          const order = { low: 0, medium: 1, high: 2, critical: 3 };
          return (
            (order[a.severity] ?? 0) - (order[b.severity] ?? 0)
          );
        },
      },
      {
        title: "状态（本地）",
        dataIndex: "status",
        key: "status",
        width: 150,
        render: (status: EventListItem["status"], record) => {
          const unsynced = isListExternalUnsynced(record);
          return (
            <StatusBadge
              status={status}
              suffix={
                status === "closed" && unsynced
                  ? "本地已关/外部未确认"
                  : undefined
              }
            />
          );
        },
      },
      {
        title: "研判结论",
        dataIndex: "final_verdict",
        key: "final_verdict",
        width: 150,
        render: (verdict: EventListItem["final_verdict"], record) => {
          const demotionCodes = resolveVerdictDemotionCodes({
            riskScore: record.risk_score,
            finalVerdict: verdict,
            evidenceLimited: record.evidence_limited,
            verdictReasonCodes: record.verdict_reason_codes,
          });
          const showDemotion =
            demotionCodes.length > 0 &&
            isHighRiskNoneMismatch({
              riskScore: record.risk_score,
              finalVerdict: verdict,
            });
          return (
            <Space direction="vertical" size={2}>
              <VerdictTag verdict={verdict} />
              {showDemotion ? (
                <Tooltip title={demotionCodes.map(labelVerdictReasonCode).join("；")}>
                  <Tag
                    color="gold"
                    style={{ marginInlineEnd: 0 }}
                    data-testid="list-verdict-demotion-tag"
                  >
                    证据不足降级
                  </Tag>
                </Tooltip>
              ) : null}
            </Space>
          );
        },
      },
      {
        title: "风险分",
        dataIndex: "risk_score",
        key: "risk_score",
        width: 90,
        align: "right" as const,
        sorter: (a, b) => a.risk_score - b.risk_score,
        render: (score: number) => {
          const color =
            score >= 80 ? "#ff4d4f" : score >= 50 ? "#fa8c16" : "#52c41a";
          return (
            <span style={{ fontWeight: 600, color }}>{score.toFixed(1)}</span>
          );
        },
      },
      {
        title: "写回状态",
        key: "writeback_overall_status",
        width: 170,
        render: (_, record) => {
          // First-screen degradation (ISSUE-038 / ISSUE-068):
          // listEvents always returns writeback_overall_status=null and does
          // not project confirmation_evidence / external_unsynced. Until a
          // writeback_updated socket event (or a future list-API extension)
          // supplies status, the badge shows "未写回" / heuristic CLOSED
          // unsynced. When status is later CONFIRMED without evidence, we
          // intentionally pass null evidence so WritebackBadge renders
          // "已同步（弱证据）" instead of plain green success.
          const externalUnsynced = isListExternalUnsynced(record);
          return (
            <WritebackBadge
              status={record.writeback_overall_status}
              required={record.writeback_required}
              confirmationEvidence={record.confirmation_evidence ?? null}
              eventStatus={record.status}
              externalUnsynced={externalUnsynced || undefined}
            />
          );
        },
      },
      {
        title: "创建时间",
        dataIndex: "created_at",
        key: "created_at",
        width: 170,
        render: (ts: string | null) =>
          ts ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {new Date(ts).toLocaleString("zh-CN", { hour12: false })}
            </Typography.Text>
          ) : (
            <Typography.Text type="secondary">—</Typography.Text>
          ),
        sorter: (a, b) => {
          const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
          const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
          return ta - tb;
        },
      },
      {
        title: "操作",
        key: "action",
        width: 110,
        fixed: "right" as const,
        render: (_, record) => {
          const isTriggering = triggeringIds?.has(record.event_id) ?? false;
          const nonTriggerable = NON_TRIGGERABLE_STATUSES.includes(record.status);
          const disabled = nonTriggerable || isTriggering;
          const tip = nonTriggerable
            ? "事件已在研判流程中或已结束"
            : isTriggering
              ? "正在触发..."
              : "触发研判流程";
          return (
            <Space>
              <Tooltip title={tip}>
                <Button
                  size="small"
                  type="primary"
                  ghost
                  icon={<ExperimentOutlined />}
                  loading={isTriggering}
                  disabled={disabled}
                  onClick={(e) => {
                    e.stopPropagation();
                    onTriggerInvestigation(record.event_id);
                  }}
                  aria-label={`触发研判 ${record.event_id}`}
                  data-testid={`trigger-investigation-${record.event_id}`}
                >
                  触发研判
                </Button>
              </Tooltip>
            </Space>
          );
        },
      },
    ],
    [onRowClick, onTriggerInvestigation, triggeringIds],
  );

  return (
    <Table<EventListItem>
      rowKey="event_id"
      columns={columns}
      dataSource={items}
      loading={loading}
      size="middle"
      scroll={{ x: 1280 }}
      data-testid="event-table"
      pagination={{
        current: page,
        pageSize,
        total,
        showSizeChanger: true,
        showQuickJumper: true,
        showTotal: (t) => `共 ${t} 条`,
        pageSizeOptions: ["10", "20", "50"],
        onChange: (p, ps) => onPageChange(p, ps),
      }}
      onRow={(record) => ({
        onClick: () => onRowClick?.(record.event_id),
        style: { cursor: onRowClick ? "pointer" : "default" },
        "data-testid": `event-row-${record.event_id}`,
      })}
    />
  );
}
