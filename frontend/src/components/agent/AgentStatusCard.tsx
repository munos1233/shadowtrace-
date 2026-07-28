/** Agent status card — individual Agent state display with color + pulse animation (ISSUE-075). */

import { Card, Progress, Tag, Typography } from "antd";
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import type { AgentName } from "../../stores/agentStatusStore";
import {
  AGENT_LABELS,
  AGENT_STATUS_COLORS,
  type AgentStateEntry,
} from "../../stores/agentStatusStore";
import "./AgentStatusCard.css";

const { Text } = Typography;

function StatusIcon({ status }: { status: AgentStateEntry["status"] }) {
  const style = { fontSize: 18, color: AGENT_STATUS_COLORS[status] };
  switch (status) {
    case "IDLE":
      return <ClockCircleOutlined style={style} />;
    case "PROCESSING":
      return <LoadingOutlined spin style={style} />;
    case "COMPLETED":
      return <CheckCircleOutlined style={style} />;
    case "FAILED":
      return <CloseCircleOutlined style={style} />;
    case "DEGRADED":
      return <ExclamationCircleOutlined style={style} />;
    default:
      return <ClockCircleOutlined style={style} />;
  }
}

export interface AgentStatusCardProps {
  agentName: AgentName;
  state: AgentStateEntry;
}

export default function AgentStatusCard({ agentName, state }: AgentStatusCardProps) {
  const color = AGENT_STATUS_COLORS[state.status];
  const isProcessing = state.status === "PROCESSING";

  return (
    <Card
      size="small"
      className={`agent-status-card ${isProcessing ? "agent-status-card--processing" : ""}`}
      data-testid={`agent-card-${agentName}`}
      title={
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <StatusIcon status={state.status} />
          <Text
            strong
            style={{
              maxWidth: 90,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {AGENT_LABELS[agentName]}
          </Text>
        </span>
      }
      extra={
        <Tag color={color} data-testid={`agent-status-tag-${agentName}`}>
          {state.status}
        </Tag>
      }
    >
      {isProcessing && state.progress_percent != null && (
        <Progress
          percent={Math.round(state.progress_percent)}
          size="small"
          strokeColor={color}
          style={{ marginBottom: 4 }}
        />
      )}
      {state.message && (
        <Text
          type="secondary"
          style={{
            fontSize: 12,
            display: "block",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={state.message}
        >
          {state.message}
        </Text>
      )}
      {state.duration_ms != null && (
        <Text type="secondary" style={{ fontSize: 11 }}>
          {(state.duration_ms / 1000).toFixed(1)}s
        </Text>
      )}
    </Card>
  );
}
