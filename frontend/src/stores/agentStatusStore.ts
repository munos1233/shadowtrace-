/** Agent status store — socket-driven real-time Agent state + activity feed (ISSUE-075). */

import { create } from "zustand";
import type { AgentStatus, AgentSocketPayload } from "../types/socket";
import type { AgentTrace } from "../types/trace";
import { socketClient } from "../services/socketClient";

/* ------------------------------------------------------------------ */
/*  Canonical 12 Agent names from backend AgentName Literal            */
/* ------------------------------------------------------------------ */

export const AGENT_NAMES = [
  "super_agent",
  "planner_agent",
  "triage_agent",
  "evidence_agent",
  "graph_agent",
  "rag_agent",
  "risk_agent",
  "response_agent",
  "verify_agent",
  "report_agent",
  "memory_agent",
  "tool_agent",
] as const;

export type AgentName = (typeof AGENT_NAMES)[number];

/** Chinese display labels for each Agent (ISSUE-075 unified naming). */
export const AGENT_LABELS: Record<AgentName, string> = {
  super_agent: "超级智能体",
  planner_agent: "规划智能体",
  triage_agent: "分诊智能体",
  evidence_agent: "证据采集智能体",
  graph_agent: "图谱智能体",
  rag_agent: "RAG查询智能体",
  risk_agent: "风险评分智能体",
  response_agent: "响应规划智能体",
  verify_agent: "验证智能体",
  report_agent: "报告生成智能体",
  memory_agent: "记忆智能体",
  tool_agent: "工具智能体",
};

/* ------------------------------------------------------------------ */
/*  Status color mapping (ISSUE-075 unified naming)                    */
/* ------------------------------------------------------------------ */

export const AGENT_STATUS_COLORS: Record<AgentStatus, string> = {
  IDLE: "#8c8c8c",
  PROCESSING: "#1677ff",
  COMPLETED: "#52c41a",
  FAILED: "#ff4d4f",
  DEGRADED: "#fa8c16",
};

/* ------------------------------------------------------------------ */
/*  Per-agent state                                                    */
/* ------------------------------------------------------------------ */

export interface AgentStateEntry {
  agent_name: AgentName;
  status: AgentStatus;
  message: string;
  progress_percent: number | null;
  /** ISO timestamp of last status change */
  last_updated: string | null;
  /** duration_ms from completed trace, if available */
  duration_ms: number | null;
}

export interface ActivityFeedEntry {
  timestamp: string;
  agent_name: AgentName;
  message: string;
}

/* ------------------------------------------------------------------ */
/*  Store                                                              */
/* ------------------------------------------------------------------ */

const MAX_FEED_ENTRIES = 200;

interface AgentStatusState {
  /** Map of agent_name → AgentStateEntry */
  agents: Record<AgentName, AgentStateEntry>;

  /** Activity feed (most recent last). */
  feed: ActivityFeedEntry[];

  /** Whether the panel should be expanded. */
  expanded: boolean;

  /** Whether socket is connected (for fallback indication). */
  socketConnected: boolean;

  /** Polling fallback timer reference. */
  _pollTimer: ReturnType<typeof setInterval> | null;
  _socketUnsub: (() => void) | null;

  // Actions
  setAgentState: (agentName: AgentName, patch: Partial<AgentStateEntry>) => void;
  appendFeed: (entry: ActivityFeedEntry) => void;
  applySocketEvent: (payload: AgentSocketPayload) => void;
  replayFromTraces: (traces: AgentTrace[]) => void;
  setExpanded: (expanded: boolean) => void;

  /** Start listening to socket events for a given event_id. */
  connectSocket: (eventId: string) => void;
  disconnectSocket: () => void;

  /** Start polling fallback (10s interval using traces API). */
  startPolling: (eventId: string, fetchTraces: (eventId: string) => Promise<AgentTrace[]>) => void;
  stopPolling: () => void;
}

function initialAgentState(agentName: AgentName): AgentStateEntry {
  return {
    agent_name: agentName,
    status: "IDLE",
    message: "",
    progress_percent: null,
    last_updated: null,
    duration_ms: null,
  };
}

function buildInitialAgents(): Record<AgentName, AgentStateEntry> {
  const map = {} as Record<AgentName, AgentStateEntry>;
  for (const name of AGENT_NAMES) {
    map[name] = initialAgentState(name);
  }
  return map;
}

/** Map trace status string → AgentStatus. */
function traceStatusToAgentStatus(status: string): AgentStatus {
  switch (status) {
    case "completed":
      return "COMPLETED";
    case "failed":
      return "FAILED";
    case "processing":
      return "PROCESSING";
    default:
      return "IDLE";
  }
}

export const useAgentStatusStore = create<AgentStatusState>((set, get) => ({
  agents: buildInitialAgents(),
  feed: [],
  expanded: true,
  socketConnected: false,
  _pollTimer: null,
  _socketUnsub: null,

  setAgentState(agentName, patch) {
    set((s) => ({
      agents: {
        ...s.agents,
        [agentName]: { ...s.agents[agentName], ...patch },
      },
    }));
  },

  appendFeed(entry) {
    set((s) => {
      const next = [...s.feed, entry];
      // Keep only last MAX_FEED_ENTRIES
      if (next.length > MAX_FEED_ENTRIES) {
        return { feed: next.slice(next.length - MAX_FEED_ENTRIES) };
      }
      return { feed: next };
    });
  },

  applySocketEvent(payload) {
    const { agent_name, status, message, progress_percent } = payload;
    // Validate agent_name is one of the 12
    if (!AGENT_NAMES.includes(agent_name as AgentName)) {
      return;
    }
    const name = agent_name as AgentName;
    const now = new Date().toISOString();

    set((s) => ({
      agents: {
        ...s.agents,
        [name]: {
          ...s.agents[name],
          status,
          message,
          progress_percent: progress_percent ?? s.agents[name].progress_percent,
          last_updated: now,
        },
      },
    }));

    // Append to feed
    get().appendFeed({
      timestamp: now,
      agent_name: name,
      message,
    });
  },

  replayFromTraces(traces) {
    if (!traces || traces.length === 0) return;

    // Sort traces by started_at for chronological replay
    const sorted = [...traces].sort(
      (a, b) =>
        new Date(a.started_at).getTime() - new Date(b.started_at).getTime(),
    );

    const feedEntries: ActivityFeedEntry[] = [];
    const agentStates = buildInitialAgents();

    for (const trace of sorted) {
      const name = trace.agent_name as AgentName;
      if (!AGENT_NAMES.includes(name)) continue;

      const status = traceStatusToAgentStatus(trace.status);
      const timestamp = trace.completed_at ?? trace.started_at;

      agentStates[name] = {
        agent_name: name,
        status,
        message:
          status === "COMPLETED"
            ? `${AGENT_LABELS[name]} 已完成`
            : status === "FAILED"
              ? `失败: ${trace.error_detail ?? "未知错误"}`
              : "处理中",
        progress_percent: status === "COMPLETED" ? 100 : null,
        last_updated: timestamp,
        duration_ms: trace.duration_ms,
      };

      feedEntries.push({
        timestamp,
        agent_name: name,
        message: agentStates[name].message,
      });
    }

    // Keep only last MAX_FEED_ENTRIES
    const trimmedFeed =
      feedEntries.length > MAX_FEED_ENTRIES
        ? feedEntries.slice(feedEntries.length - MAX_FEED_ENTRIES)
        : feedEntries;

    set({ agents: agentStates, feed: trimmedFeed });
  },

  setExpanded(expanded) {
    set({ expanded });
  },

  connectSocket(eventId) {
    const { _socketUnsub } = get();
    // Already connected
    if (_socketUnsub) return;

    socketClient.connect();
    socketClient.subscribe(eventId);

    const unsub = socketClient.onEvent((evt) => {
      if (evt.event_id !== eventId) return;
      if (
        evt.type === "agent_progress" ||
        evt.type === "agent_completed" ||
        evt.type === "agent_failed"
      ) {
        get().applySocketEvent(evt.payload as AgentSocketPayload);
      }
    });

    set({ _socketUnsub: unsub, socketConnected: socketClient.isConnected });
  },

  disconnectSocket() {
    const { _socketUnsub, _pollTimer } = get();
    _socketUnsub?.();
    if (_pollTimer) clearInterval(_pollTimer);
    set({ _socketUnsub: null, _pollTimer: null, socketConnected: false });
  },

  startPolling(eventId, fetchTraces) {
    const { _pollTimer } = get();
    if (_pollTimer) return; // already polling

    // Connect socket first (best-effort)
    socketClient.connect();
    socketClient.subscribe(eventId);

    const timer = setInterval(async () => {
      try {
        const traces = await fetchTraces(eventId);
        if (traces && traces.length > 0) {
          get().replayFromTraces(traces);
        }
      } catch {
        // Polling is fallback — silently ignore errors
      }
    }, 10_000);

    set({ _pollTimer: timer });
  },

  stopPolling() {
    const { _pollTimer } = get();
    if (_pollTimer) {
      clearInterval(_pollTimer);
      set({ _pollTimer: null });
    }
  },
}));
