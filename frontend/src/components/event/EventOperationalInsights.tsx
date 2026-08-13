/** Operational summary: guidance, degraded flags, writeback rollup (ISSUE-210). */

import { Alert, Card, Descriptions, Space, Tag, Typography } from "antd";
import type { EventDetailResponse } from "../../types/event";
import type { EventWriteback } from "../../hooks/useEventDetail";
import OutstandingSideEffectsPanel from "./OutstandingSideEffectsPanel";

const NEXT_ACTION_LABELS: Record<string, string> = {
  none: "无",
  approve_actions: "审批待处理",
  close: "可结案",
};

const PHASE_LABELS: Record<string, string> = {
  not_started: "未开始",
  analysis_in_progress: "分析进行中",
  analysis_complete_deferred: "分析完成（处置延后）",
  response_planning: "处置规划中",
  awaiting_approval: "等待审批",
  executing: "执行中",
  complete: "已完成",
};

interface Props {
  detail: EventDetailResponse;
  writebacks: EventWriteback[];
  onNavigateTab?: (tabKey: string) => void;
}

export default function EventOperationalInsights({
  detail,
  writebacks,
  onNavigateTab,
}: Props) {
  const flags = detail.event.degraded_flags ?? [];
  const summary = detail.event.event_context_snapshot?.writeback_summary;
  const unknownCount = writebacks.filter((item) => item.status === "unknown").length;

  return (
    <Card size="small" title="运营要素" data-testid="event-operational-insights">
      <Space direction="vertical" size={12} style={{ width: "100%" }}>
        <Descriptions size="small" column={{ xs: 1, md: 2 }}>
          <Descriptions.Item label="调查指引">
            {detail.phase_message ?? "暂无 phase_message"}
          </Descriptions.Item>
          <Descriptions.Item label="推荐下一步">
            {NEXT_ACTION_LABELS[detail.next_recommended_action ?? "none"] ??
              detail.next_recommended_action ??
              "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="响应阶段">
            {PHASE_LABELS[detail.response_phase_state ?? "not_started"] ??
              detail.response_phase_state ??
              "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="执行子状态">
            {detail.execution_substate ?? "none"}
          </Descriptions.Item>
        </Descriptions>

        <div>
          <Typography.Text type="secondary">degraded_flags</Typography.Text>
          <div style={{ marginTop: 6 }} data-testid="event-degraded-flags">
            {flags.length === 0 ? (
              <Typography.Text type="secondary">无</Typography.Text>
            ) : (
              <Space wrap>
                {flags.map((flag) => (
                  <Tag key={flag} color="orange">
                    {flag}
                  </Tag>
                ))}
              </Space>
            )}
          </div>
        </div>

        <Descriptions size="small" column={{ xs: 1, md: 2 }} title="写回汇总">
          <Descriptions.Item label="required_actions">
            {summary?.required_action_count ?? "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="applicable_actions">
            {summary?.applicable_action_count ?? "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="aggregate_status">
            {summary?.aggregate_status ?? detail.writeback_overall_status ?? "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="pending_writebacks">
            {detail.pending_writeback_count ?? 0}
          </Descriptions.Item>
          <Descriptions.Item label="terminal_confirmed">
            {summary?.terminal_event_confirmed === true ? "是" : summary?.terminal_event_confirmed === false ? "否" : "暂无数据"}
          </Descriptions.Item>
          <Descriptions.Item label="external_unsynced">
            {summary?.external_unsynced ?? detail.event.external_unsynced ? "是" : "否"}
          </Descriptions.Item>
          <Descriptions.Item label="UNKNOWN 写回数">{unknownCount}</Descriptions.Item>
        </Descriptions>

        {detail.event.external_unsynced && (
          <Alert
            type="warning"
            showIcon
            message="外部处置尚未同步"
            description="结案或报告可能已完成，但源系统写回仍未确认。"
          />
        )}

        <OutstandingSideEffectsPanel
          projection={detail}
          onNavigateActionsTab={
            onNavigateTab ? () => onNavigateTab("actions") : undefined
          }
        />
      </Space>
    </Card>
  );
}
