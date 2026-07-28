/** Agent status panel — 12-Agent grid + activity feed, embedded in event detail (ISSUE-075). */

import { useEffect, useMemo } from "react";
import { Alert, Card, Col, Collapse, Row, Tag, Typography } from "antd";
import { CaretRightOutlined } from "@ant-design/icons";
import AgentStatusCard from "./AgentStatusCard";
import AgentActivityFeed from "./AgentActivityFeed";
import {
  AGENT_NAMES,
  useAgentStatusStore,
  type AgentName,
} from "../../stores/agentStatusStore";
import type { AgentTrace } from "../../types/trace";
import type { EventStatus } from "../../types/event";

const { Text } = Typography;

export interface AgentStatusPanelProps {
  eventId: string;
  eventStatus: EventStatus;
  traces: AgentTrace[];
}

/** Statuses where investigation is actively running — panel stays expanded. */
const ACTIVE_INVESTIGATION_STATUSES: Set<EventStatus> = new Set([
  "triaging",
  "collecting_evidence",
  "analyzing",
  "scoring",
  "planning_response",
  "executing_response",
  "verifying",
  "replanning",
  "reporting",
]);

export default function AgentStatusPanel({
  eventId,
  eventStatus,
  traces,
}: AgentStatusPanelProps) {
  const {
    agents,
    feed,
    expanded,
    connectSocket,
    disconnectSocket,
    startPolling,
    stopPolling,
    setExpanded,
    replayFromTraces,
  } = useAgentStatusStore();

  const isActive = ACTIVE_INVESTIGATION_STATUSES.has(eventStatus);
  const isClosed = eventStatus === "closed";

  // Startup: connect socket + replay traces
  useEffect(() => {
    if (!eventId) return;

    // Replay from traces on mount (covers completed events too)
    if (traces && traces.length > 0) {
      replayFromTraces(traces);
    }

    // Connect socket for real-time updates
    connectSocket(eventId);

    return () => {
      disconnectSocket();
    };
  }, [eventId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Re-run trace replay when traces update
  useEffect(() => {
    if (traces && traces.length > 0 && feed.length === 0) {
      replayFromTraces(traces);
    }
  }, [traces]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-expand when investigation is active, collapse when closed
  useEffect(() => {
    if (isActive) {
      setExpanded(true);
    } else if (isClosed) {
      setExpanded(false);
    }
  }, [isActive, isClosed, setExpanded]);

  // Count agents by status for summary
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const name of AGENT_NAMES) {
      const s = agents[name].status;
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [agents]);

  const panelHeader = (
    <div
      style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}
      data-testid="agent-status-panel-header"
    >
      <Text strong>Agent 实时状态</Text>
      {statusCounts["PROCESSING"] > 0 && (
        <Tag color="processing">{statusCounts["PROCESSING"]} 运行中</Tag>
      )}
      {statusCounts["COMPLETED"] > 0 && (
        <Tag color="success">{statusCounts["COMPLETED"]} 已结束</Tag>
      )}
      {statusCounts["FAILED"] > 0 && (
        <Tag color="error">{statusCounts["FAILED"]} 失败</Tag>
      )}
      {statusCounts["DEGRADED"] > 0 && (
        <Tag color="warning">{statusCounts["DEGRADED"]} 降级</Tag>
      )}
    </div>
  );

  return (
    <Card
      size="small"
      data-testid="agent-status-panel"
      style={{ marginTop: 16 }}
    >
      <Collapse
        activeKey={expanded ? ["agent-panel"] : []}
        onChange={(keys) => setExpanded(keys.includes("agent-panel"))}
        expandIcon={({ isActive }) => (
          <CaretRightOutlined rotate={isActive ? 90 : 0} />
        )}
        ghost
        items={[
          {
            key: "agent-panel",
            label: panelHeader,
            children: (
              <div>
                {/* Socket fallback notice */}
                {!useAgentStatusStore.getState().socketConnected && isActive && (
                  <Alert
                    type="warning"
                    showIcon
                    message="Socket 未连接，每 10 秒轮询 traces 数据，无实时动画。"
                    style={{ marginBottom: 12 }}
                    data-testid="socket-fallback-notice"
                  />
                )}

                {/* 12 Agent status card grid */}
                <Row gutter={[8, 8]}>
                  {AGENT_NAMES.map((agentName: AgentName) => (
                    <Col key={agentName} xs={12} sm={8} md={6} lg={4} xl={4}>
                      <AgentStatusCard
                        agentName={agentName}
                        state={agents[agentName]}
                      />
                    </Col>
                  ))}
                </Row>

                {/* Activity feed */}
                <Card
                  size="small"
                  title={`活动日志（${feed.length} 条）`}
                  style={{ marginTop: 12 }}
                  data-testid="agent-activity-feed-card"
                >
                  <AgentActivityFeed entries={feed} />
                </Card>
              </div>
            ),
          },
        ]}
      />
    </Card>
  );
}
