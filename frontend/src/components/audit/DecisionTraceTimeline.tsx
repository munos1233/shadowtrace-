import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Empty,
  Space,
  Tag,
  Timeline,
  Typography,
} from "antd";
import { LinkOutlined } from "@ant-design/icons";
import { useMemo, useState } from "react";
import type {
  DecisionTraceEntry,
  DecisionTraceEntryType,
} from "../../types/trace";
import {
  ALL_TRACE_TYPES,
  TRACE_TYPE_COLORS,
  TRACE_TYPE_LABELS,
} from "./constants";
import JsonTree from "./JsonTree";

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

const COT_COMPAT_KEYS = [
  "thought",
  "reflection",
  "rationale",
  "reasoning",
  "chain_of_thought",
  "chain-of-thought",
] as const;

const NOT_RETAINED = "[NOT_RETAINED]";

function textList(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join("、");
  return value === undefined || value === null || value === "" ? "暂无数据" : String(value);
}

function primaryBrief(detail: Record<string, unknown>): string {
  const brief = detail.brief ?? detail.structured_conclusion;
  if (typeof brief === "string" && brief.trim()) {
    return brief;
  }
  const unavailable = detail.summary_unavailable;
  if (typeof unavailable === "string" && unavailable.trim()) {
    return `summary_unavailable=${unavailable}`;
  }
  return "暂无数据";
}

function AgentDecisionBasis({ entry }: { entry: DecisionTraceEntry }) {
  const detail = entry.detail;
  const confidence =
    typeof detail.confidence === "number"
      ? `${Math.round(detail.confidence * 100)}%`
      : textList(detail.confidence);
  const model = [detail.model_name ?? detail.model, detail.model_version]
    .filter(Boolean)
    .join(" / ");
  const rules = [textList(detail.rules_applied), detail.rule_version]
    .filter((value) => value && value !== "暂无数据")
    .join(" / ");
  const cotNotRetained = COT_COMPAT_KEYS.some(
    (key) => detail[key] === NOT_RETAINED,
  );

  return (
    <div style={{ marginTop: 8 }}>
      <Descriptions size="small" column={1}>
        <Descriptions.Item label="决策依据">
          {primaryBrief(detail)}
        </Descriptions.Item>
        <Descriptions.Item label="证据引用">
          {textList(detail.evidence_refs)}
        </Descriptions.Item>
        <Descriptions.Item label="规则 / 版本">{rules || "暂无数据"}</Descriptions.Item>
        <Descriptions.Item label="模型 / 版本">{model || "暂无数据"}</Descriptions.Item>
        <Descriptions.Item label="置信度">{confidence}</Descriptions.Item>
        <Descriptions.Item label="警告">{textList(detail.warnings)}</Descriptions.Item>
      </Descriptions>
      {cotNotRetained ? (
        <Typography.Text type="secondary" style={{ display: "block", marginTop: 4 }}>
          原始思维链未保留（ISSUE-131）
        </Typography.Text>
      ) : null}
    </div>
  );
}

function NonAgentTraceDetail({ entry }: { entry: DecisionTraceEntry }) {
  const detail = entry.detail;
  const rows: Array<{ label: string; value: unknown }> = [];

  const push = (label: string, ...keys: string[]) => {
    for (const key of keys) {
      if (detail[key] !== undefined && detail[key] !== null && detail[key] !== "") {
        rows.push({ label, value: detail[key] });
        return;
      }
    }
  };

  switch (entry.entry_type) {
    case "tool_call":
      push("工具", "tool_name");
      push("状态", "status");
      push("工具结果语义", "tool_outcome");
      push("提供者状态", "provider_status");
      push("记录数", "records_count");
      push("缺口原因", "gap_reason");
      push("耗时 (ms)", "duration_ms");
      push("结果摘要", "result_summary", "summary", "message");
      break;
    case "llm_call":
      push("模型", "model_name", "model");
      push("状态", "status");
      push("Tokens", "tokens_used", "total_tokens");
      push("输出摘要", "output_summary", "summary");
      break;
    case "state_transition":
      push("原状态", "from_status");
      push("新状态", "to_status");
      push("原因", "reason", "message");
      break;
    case "approval":
      push("动作 ID", "action_id");
      push("状态", "status", "decision");
      push("说明", "comment", "summary");
      break;
    case "action_execution":
      push("动作 ID", "action_id");
      push("动作名", "action_name");
      push("状态", "status");
      push("目标", "target");
      break;
    case "disposition":
      push("disposition_id", "disposition_id");
      push("intent", "intent_kind");
      push("状态", "status");
      break;
    case "writeback":
      push("状态", "status");
      push("confirmation_evidence", "confirmation_evidence");
      push("disposition_id", "disposition_id");
      break;
    default:
      break;
  }

  if (rows.length === 0) {
    const hasDetail = Object.keys(detail).length > 0;
    if (!hasDetail) {
      return (
        <Typography.Text type="secondary" style={{ marginTop: 8, display: "block" }}>
          无结构化详情
        </Typography.Text>
      );
    }
    return (
      <div style={{ marginTop: 8 }}>
        <JsonTree value={detail} />
      </div>
    );
  }

  return (
    <Descriptions size="small" column={1} style={{ marginTop: 8 }}>
      {rows.map((row) => (
        <Descriptions.Item key={row.label} label={row.label}>
          {textList(row.value)}
        </Descriptions.Item>
      ))}
    </Descriptions>
  );
}

function TraceDetail({ entry }: { entry: DecisionTraceEntry }) {
  if (entry.entry_type === "agent_execution") {
    return <AgentDecisionBasis entry={entry} />;
  }
  return <NonAgentTraceDetail entry={entry} />;
}

export default function DecisionTraceTimeline({
  entries,
  missingSources = [],
  onToolCallSelect,
}: {
  entries: DecisionTraceEntry[];
  missingSources?: string[];
  onToolCallSelect?: (callId: string) => void;
}) {
  const [selectedTypes, setSelectedTypes] =
    useState<DecisionTraceEntryType[]>(ALL_TRACE_TYPES);
  const orderedEntries = useMemo(
    () =>
      [...entries]
        .filter((entry) => selectedTypes.includes(entry.entry_type))
        .sort(
          (left, right) =>
            new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime(),
        ),
    [entries, selectedTypes],
  );

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      {missingSources.length > 0 && (
        <Alert
          type="warning"
          showIcon
          message="部分决策轨迹来源不可用"
          description={missingSources.join("；")}
        />
      )}
      <Checkbox.Group
        aria-label="轨迹类型筛选"
        value={selectedTypes}
        options={ALL_TRACE_TYPES.map((value) => ({
          value,
          label: TRACE_TYPE_LABELS[value],
        }))}
        onChange={(values) =>
          setSelectedTypes(values as DecisionTraceEntryType[])
        }
      />
      {orderedEntries.length === 0 ? (
        <Empty description="暂无符合条件的决策轨迹" />
      ) : (
        <Timeline
          items={orderedEntries.map((entry) => ({
            color: TRACE_TYPE_COLORS[entry.entry_type],
            children: (
              <div data-testid={`trace-entry-${entry.entry_type}`}>
                <Space wrap>
                  <Tag color={TRACE_TYPE_COLORS[entry.entry_type]}>
                    {TRACE_TYPE_LABELS[entry.entry_type]}
                  </Tag>
                  {entry.entry_type === "tool_call" && entry.ref_id ? (
                    <Button
                      type="link"
                      style={{ padding: 0, height: "auto" }}
                      icon={<LinkOutlined />}
                      onClick={() => onToolCallSelect?.(entry.ref_id!)}
                    >
                      {entry.title}
                    </Button>
                  ) : (
                    <Typography.Text strong>{entry.title}</Typography.Text>
                  )}
                  <Typography.Text type="secondary">{entry.actor}</Typography.Text>
                </Space>
                <div>
                  <Typography.Text type="secondary">
                    {formatTimestamp(entry.timestamp)}
                  </Typography.Text>
                </div>
                <TraceDetail entry={entry} />
              </div>
            ),
          }))}
        />
      )}
    </Space>
  );
}
