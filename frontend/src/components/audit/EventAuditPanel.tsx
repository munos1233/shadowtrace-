import { Alert, Button, Skeleton, Space } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getDecisionTrace,
  getEventToolCalls,
  getTrajectory,
} from "../../services/auditApi";
import { socketClient } from "../../services/socketClient";
import type {
  AgentQualityScore,
  DecisionTraceEntry,
  DecisionTraceResponse,
  ToolCallItem,
  TrajectoryReport,
} from "../../types/trace";
import DecisionTraceTimeline from "./DecisionTraceTimeline";
import ToolCallDetailDrawer from "./ToolCallDetailDrawer";
import ToolCallTable from "./ToolCallTable";
import TrajectorySummary from "./TrajectorySummary";

function normalizeQualityScores(value: unknown): AgentQualityScore[] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is AgentQualityScore =>
        Boolean(
          item &&
            typeof item === "object" &&
            typeof (item as AgentQualityScore).agent_name === "string" &&
            typeof (item as AgentQualityScore).score === "number",
        ),
    );
  }
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([agentName, score]) =>
      score && typeof score === "object" && typeof Reflect.get(score, "score") === "number"
        ? [{ ...(score as Omit<AgentQualityScore, "agent_name">), agent_name: agentName }]
        : [],
    );
  }
  return [];
}

function optimisticToolCall(
  eventId: string,
  payload: Record<string, unknown>,
  status: string,
): ToolCallItem {
  return {
    call_id: String(payload.call_id ?? ""),
    event_id: eventId,
    action_id: null,
    tool_name: String(payload.tool_name ?? "unknown_tool"),
    tool_category: String(payload.tool_category ?? "unknown"),
    status,
    duration_ms:
      typeof payload.duration_ms === "number" ? payload.duration_ms : null,
    provider:
      typeof payload.provider_code === "string" ? payload.provider_code : null,
    execution_owner: null,
    disposition_id: null,
    writeback_status: null,
    parameters: {},
    result: {},
    error_detail: null,
    retry_count:
      typeof payload.retry_count === "number" ? payload.retry_count : 0,
    started_at: new Date().toISOString(),
    completed_at: status === "running" ? null : new Date().toISOString(),
    truncated: false,
  };
}

function liveTraceEntry(
  eventId: string,
  call: ToolCallItem,
): DecisionTraceEntry {
  return {
    entry_id: `live-${call.call_id}-${call.status}`,
    entry_type: "tool_call",
    timestamp: call.completed_at ?? call.started_at ?? new Date().toISOString(),
    actor: call.tool_name,
    title: `${call.tool_name} 工具调用：status=${call.status}`,
    detail: {
      tool_name: call.tool_name,
      tool_category: call.tool_category,
      status: call.status,
      duration_ms: call.duration_ms,
      retry_count: call.retry_count,
      event_id: eventId,
    },
    ref_id: call.call_id,
  };
}

function sortTraceEntries(entries: DecisionTraceEntry[]): DecisionTraceEntry[] {
  return [...entries].sort(
    (left, right) =>
      new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime(),
  );
}

export default function EventAuditPanel({
  eventId,
  qualityScores: rawQualityScores,
}: {
  eventId: string;
  qualityScores?: unknown;
}) {
  const [trace, setTrace] = useState<DecisionTraceResponse | null>(null);
  const [toolCalls, setToolCalls] = useState<ToolCallItem[]>([]);
  const [trajectory, setTrajectory] = useState<TrajectoryReport | null>(null);
  const [traceFailed, setTraceFailed] = useState(false);
  const [toolCallsFailed, setToolCallsFailed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedCall, setSelectedCall] = useState<ToolCallItem | null>(null);
  const qualityScores = useMemo(
    () => normalizeQualityScores(rawQualityScores),
    [rawQualityScores],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    const [traceResult, callsResult, trajectoryResult] = await Promise.allSettled([
      getDecisionTrace(eventId, { page: 1, page_size: 200 }),
      getEventToolCalls(eventId, { page: 1, page_size: 200 }),
      getTrajectory(eventId),
    ]);

    if (traceResult.status === "fulfilled") {
      setTrace(traceResult.value.data);
      setTraceFailed(false);
    } else {
      setTrace(null);
      setTraceFailed(true);
    }
    if (callsResult.status === "fulfilled") {
      setToolCalls(callsResult.value.data.items);
      setToolCallsFailed(false);
    } else {
      setToolCallsFailed(true);
    }
    if (trajectoryResult.status === "fulfilled") {
      setTrajectory(trajectoryResult.value.data);
    }
    setLoading(false);
  }, [eventId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    socketClient.connect();
    socketClient.subscribe(eventId);
    return socketClient.onEvent((event) => {
      if (
        event.event_id !== eventId ||
        (event.type !== "tool_call_started" &&
          event.type !== "tool_call_completed")
      ) {
        return;
      }
      const status =
        event.type === "tool_call_started"
          ? "running"
          : String(event.payload.status ?? "success");
      const optimistic = optimisticToolCall(eventId, event.payload, status);
      setToolCalls((current) => {
        const existing = current.find((item) => item.call_id === optimistic.call_id);
        return existing
          ? current.map((item) =>
              item.call_id === optimistic.call_id
                ? {
                    ...item,
                    status,
                    duration_ms: optimistic.duration_ms ?? item.duration_ms,
                    retry_count: optimistic.retry_count,
                    completed_at:
                      event.type === "tool_call_completed"
                        ? optimistic.completed_at
                        : item.completed_at,
                  }
                : item,
            )
          : [optimistic, ...current];
      });
      setTrace((current) => {
        if (!current) return current;
        const entry = liveTraceEntry(eventId, optimistic);
        const withoutStaleLive = current.entries.filter(
          (candidate) =>
            !(
              candidate.ref_id === entry.ref_id &&
              candidate.entry_id.startsWith("live-")
            ),
        );
        const alreadyRecorded = current.entries.some(
          (candidate) =>
            candidate.ref_id === entry.ref_id &&
            candidate.detail.status === entry.detail.status,
        );
        const entries = sortTraceEntries([...withoutStaleLive, entry]);
        return {
          ...current,
          total: alreadyRecorded ? current.total : current.total + 1,
          entries,
        };
      });
      if (event.type === "tool_call_completed") {
        void getEventToolCalls(eventId, { page: 1, page_size: 200 }).then(
          (response) => setToolCalls(response.data.items),
          () => undefined,
        );
      }
    });
  }, [eventId]);

  const selectCallById = (callId: string) => {
    const call = toolCalls.find((item) => item.call_id === callId);
    if (call) setSelectedCall(call);
  };

  if (loading && !trace && toolCalls.length === 0) {
    return <Skeleton active paragraph={{ rows: 8 }} />;
  }

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void refresh()}>
          刷新审计
        </Button>
      </div>
      <TrajectorySummary report={trajectory} qualityScores={qualityScores} />
      {traceFailed ? (
        <Alert
          type="warning"
          showIcon
          message="决策轨迹暂不可用，已降级为工具调用列表"
          description="工具调用审计仍可独立查询；稍后可重试加载完整决策轨迹。"
        />
      ) : (
        trace && (
          <DecisionTraceTimeline
            entries={trace.entries}
            missingSources={trace.missing_sources}
            summary={trace.summary}
            onToolCallSelect={selectCallById}
          />
        )
      )}
      {toolCallsFailed && traceFailed && (
        <Alert type="error" showIcon message="工具调用列表加载失败，请稍后重试" />
      )}
      {traceFailed && (
        <ToolCallTable
          items={toolCalls}
          total={toolCalls.length}
          page={1}
          pageSize={200}
          showEvent={false}
          onSelect={setSelectedCall}
        />
      )}
      <ToolCallDetailDrawer
        toolCall={selectedCall}
        open={selectedCall !== null}
        onClose={() => setSelectedCall(null)}
      />
    </Space>
  );
}
