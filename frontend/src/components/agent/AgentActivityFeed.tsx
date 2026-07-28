/** Agent activity feed — real-time scrolling event log (ISSUE-075). */

import { useEffect, useRef } from "react";
import { Empty, List, Tag, Typography } from "antd";
import type { ActivityFeedEntry, AgentName } from "../../stores/agentStatusStore";
import { AGENT_LABELS } from "../../stores/agentStatusStore";

const { Text } = Typography;

export interface AgentActivityFeedProps {
  entries: ActivityFeedEntry[];
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("zh-CN", { hour12: false });
  } catch {
    return iso;
  }
}

/** Agent name colors for feed tags (distinct from status colors). */
const AGENT_TAG_COLORS: Record<AgentName, string> = {
  super_agent: "magenta",
  planner_agent: "purple",
  triage_agent: "cyan",
  evidence_agent: "blue",
  graph_agent: "geekblue",
  rag_agent: "lime",
  risk_agent: "orange",
  response_agent: "gold",
  verify_agent: "green",
  report_agent: "red",
  memory_agent: "volcano",
  tool_agent: "default",
};

export default function AgentActivityFeed({ entries }: AgentActivityFeedProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to latest entry
  useEffect(() => {
    if (bottomRef.current && typeof bottomRef.current.scrollIntoView === "function") {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [entries.length]);

  if (entries.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="暂无活动记录"
      />
    );
  }

  return (
    <div
      data-testid="agent-activity-feed"
      style={{ maxHeight: 320, overflow: "auto", paddingRight: 4 }}
    >
      <List
        size="small"
        dataSource={entries}
        renderItem={(entry) => (
          <List.Item
            style={{ padding: "4px 0", borderBottom: "1px solid #f0f0f0" }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 8,
                width: "100%",
              }}
            >
              <Text
                type="secondary"
                style={{ fontSize: 11, whiteSpace: "nowrap", minWidth: 56 }}
              >
                {formatTime(entry.timestamp)}
              </Text>
              <Tag
                color={AGENT_TAG_COLORS[entry.agent_name] ?? "default"}
                style={{ fontSize: 11, margin: 0, whiteSpace: "nowrap" }}
              >
                {AGENT_LABELS[entry.agent_name]}
              </Tag>
              <Text style={{ fontSize: 12, wordBreak: "break-word", flex: 1 }}>
                {entry.message}
              </Text>
            </div>
          </List.Item>
        )}
      />
      <div ref={bottomRef} />
    </div>
  );
}
