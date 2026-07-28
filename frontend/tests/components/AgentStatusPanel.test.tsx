/** AgentStatusPanel tests — ISSUE-075 acceptance criteria. */

import { render, screen, act } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AgentStatusPanel from "../../src/components/agent/AgentStatusPanel";
import AgentStatusCard from "../../src/components/agent/AgentStatusCard";
import AgentActivityFeed from "../../src/components/agent/AgentActivityFeed";
import {
  AGENT_NAMES,
  AGENT_LABELS,
  useAgentStatusStore,
  type AgentName,
  type AgentStateEntry,
} from "../../src/stores/agentStatusStore";
import type { AgentTrace } from "../../src/types/trace";
import type { EventStatus } from "../../src/types/event";

// Hoist mocks to compile-time (vi.hoisted runs before any import)
const { mockSubscribe, mockOnEvent, mockConnect } = vi.hoisted(() => ({
  mockSubscribe: vi.fn(),
  mockOnEvent: vi.fn<() => () => void>().mockReturnValue(() => undefined),
  mockConnect: vi.fn(),
}));

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: (...args: unknown[]) => mockConnect(...args),
    subscribe: (...args: unknown[]) => mockSubscribe(...args),
    onEvent: mockOnEvent,
    get isConnected() {
      return true;
    },
  },
}));

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function makeTrace(
  agentName: string,
  status: "completed" | "failed" | "processing",
  overrides?: Partial<AgentTrace>,
): AgentTrace {
  return {
    trace_id: `trace-${agentName}-1`,
    event_id: "evt-test",
    agent_name: agentName,
    status,
    input_data: null,
    output_data: null,
    started_at: "2026-07-28T10:00:00Z",
    completed_at: "2026-07-28T10:00:05Z",
    duration_ms: 5000,
    error_detail: status === "failed" ? "连接超时" : null,
    llm_model: null,
    llm_tokens_used: null,
    ...overrides,
  };
}

function renderPanel(
  overrides?: Partial<{
    eventId: string;
    eventStatus: EventStatus;
    traces: AgentTrace[];
  }>,
) {
  return render(
    <AgentStatusPanel
      eventId={overrides?.eventId ?? "evt-test-001"}
      eventStatus={overrides?.eventStatus ?? "triaging"}
      traces={overrides?.traces ?? []}
    />,
  );
}

/* ------------------------------------------------------------------ */
/*  Tests                                                             */
/* ------------------------------------------------------------------ */

describe("AgentStatusCard", () => {
  it("renders all 5 status colors with correct label", () => {
    const states: Array<{ name: AgentName; state: AgentStateEntry }> = [
      {
        name: "triage_agent",
        state: {
          agent_name: "triage_agent",
          status: "IDLE",
          message: "",
          progress_percent: null,
          last_updated: null,
          duration_ms: null,
        },
      },
      {
        name: "evidence_agent",
        state: {
          agent_name: "evidence_agent",
          status: "PROCESSING",
          message: "正在采集证据...",
          progress_percent: 45,
          last_updated: "2026-07-28T10:00:00Z",
          duration_ms: null,
        },
      },
      {
        name: "risk_agent",
        state: {
          agent_name: "risk_agent",
          status: "COMPLETED",
          message: "评分完成",
          progress_percent: 100,
          last_updated: "2026-07-28T10:00:05Z",
          duration_ms: 3000,
        },
      },
      {
        name: "verify_agent",
        state: {
          agent_name: "verify_agent",
          status: "FAILED",
          message: "验证失败：目标不可达",
          progress_percent: null,
          last_updated: "2026-07-28T10:00:10Z",
          duration_ms: null,
        },
      },
      {
        name: "rag_agent",
        state: {
          agent_name: "rag_agent",
          status: "DEGRADED",
          message: "向量检索降级为关键词匹配",
          progress_percent: null,
          last_updated: "2026-07-28T10:00:03Z",
          duration_ms: null,
        },
      },
    ];

    for (const { name, state } of states) {
      const { unmount } = render(
        <AgentStatusCard agentName={name} state={state} />,
      );
      expect(screen.getByText(AGENT_LABELS[name])).toBeInTheDocument();
      expect(screen.getByTestId(`agent-status-tag-${name}`)).toHaveTextContent(
        state.status,
      );
      if (state.message) {
        expect(screen.getByText(state.message)).toBeInTheDocument();
      }
      unmount();
    }
  });

  it("shows progress bar when PROCESSING with progress_percent", () => {
    render(
      <AgentStatusCard
        agentName="triage_agent"
        state={{
          agent_name: "triage_agent",
          status: "PROCESSING",
          message: "分诊中...",
          progress_percent: 60,
          last_updated: null,
          duration_ms: null,
        }}
      />,
    );
    // Antd Progress renders the percent text
    expect(screen.getByText("60%")).toBeInTheDocument();
  });

  it("does not show progress bar when progress_percent is null", () => {
    render(
      <AgentStatusCard
        agentName="triage_agent"
        state={{
          agent_name: "triage_agent",
          status: "PROCESSING",
          message: "处理中",
          progress_percent: null,
          last_updated: null,
          duration_ms: null,
        }}
      />,
    );
    expect(screen.queryByText("%")).not.toBeInTheDocument();
  });
});

describe("AgentActivityFeed", () => {
  it("renders empty state when no entries", () => {
    render(<AgentActivityFeed entries={[]} />);
    expect(screen.getByText("暂无活动记录")).toBeInTheDocument();
  });

  it("renders feed entries with timestamps and agent labels", () => {
    const entries = [
      {
        timestamp: "2026-07-28T10:00:01Z",
        agent_name: "triage_agent" as AgentName,
        message: "分诊开始",
      },
      {
        timestamp: "2026-07-28T10:00:05Z",
        agent_name: "evidence_agent" as AgentName,
        message: "证据采集完成",
      },
    ];
    render(<AgentActivityFeed entries={entries} />);
    expect(screen.getByText("分诊开始")).toBeInTheDocument();
    expect(screen.getByText("证据采集完成")).toBeInTheDocument();
    expect(screen.getByText(AGENT_LABELS.triage_agent)).toBeInTheDocument();
    expect(screen.getByText(AGENT_LABELS.evidence_agent)).toBeInTheDocument();
  });

  it("renders all 250 entries as-is (cap is enforced by store, not component)", () => {
    const entries = Array.from({ length: 250 }, (_, i) => ({
      timestamp: `2026-07-28T10:${String(i % 60).padStart(2, "0")}:00Z`,
      agent_name: "triage_agent" as AgentName,
      message: `消息 ${i + 1}`,
    }));
    render(<AgentActivityFeed entries={entries} />);
    // Component renders whatever it receives; capping is done by appendFeed in the store
    expect(screen.getByText("消息 1")).toBeInTheDocument();
    expect(screen.getByText("消息 250")).toBeInTheDocument();
  });
});

describe("AgentStatusPanel", () => {
  beforeEach(() => {
    // Reset the store before each test
    useAgentStatusStore.setState({
      agents: Object.fromEntries(
        AGENT_NAMES.map((name) => [
          name,
          {
            agent_name: name,
            status: "IDLE",
            message: "",
            progress_percent: null,
            last_updated: null,
            duration_ms: null,
          },
        ]),
      ) as Record<AgentName, AgentStateEntry>,
      feed: [],
      expanded: true,
      socketConnected: true,
      _pollTimer: null,
      _socketUnsub: null,
    });
    mockSubscribe.mockReset();
    mockOnEvent.mockReset();
    mockOnEvent.mockReturnValue(() => undefined);
    mockConnect.mockReset();
  });

  it("renders all 12 agent cards in the grid", () => {
    renderPanel();
    for (const name of AGENT_NAMES) {
      expect(screen.getByTestId(`agent-card-${name}`)).toBeInTheDocument();
    }
  });

  it("shows panel header with status counts", () => {
    renderPanel();
    expect(screen.getByTestId("agent-status-panel-header")).toBeInTheDocument();
    expect(screen.getByText("Agent 实时状态")).toBeInTheDocument();
  });

  it("replays trace history into agent states on mount", () => {
    const traces: AgentTrace[] = [
      makeTrace("triage_agent", "completed"),
      makeTrace("evidence_agent", "completed", {
        duration_ms: 8000,
        started_at: "2026-07-28T10:00:05Z",
        completed_at: "2026-07-28T10:00:13Z",
      }),
      makeTrace("verify_agent", "failed", {
        started_at: "2026-07-28T10:01:00Z",
        completed_at: "2026-07-28T10:01:02Z",
      }),
    ];

    render(
      <AgentStatusPanel
        eventId="evt-test"
        eventStatus="closed"
        traces={traces}
      />,
    );

    // Triage agent should show COMPLETED
    expect(
      screen.getByTestId("agent-status-tag-triage_agent"),
    ).toHaveTextContent("COMPLETED");

    // Evidence agent should show COMPLETED
    expect(
      screen.getByTestId("agent-status-tag-evidence_agent"),
    ).toHaveTextContent("COMPLETED");

    // Verify agent should show FAILED
    expect(
      screen.getByTestId("agent-status-tag-verify_agent"),
    ).toHaveTextContent("FAILED");
  });

  it("auto-expands during active investigation, collapses when closed", () => {
    const { unmount } = render(
      <AgentStatusPanel
        eventId="evt-test"
        eventStatus="triaging"
        traces={[]}
      />,
    );

    // During active investigation, panel should be expanded
    expect(useAgentStatusStore.getState().expanded).toBe(true);

    // Switch to closed
    unmount();
    const { unmount: unmount2 } = render(
      <AgentStatusPanel
        eventId="evt-test"
        eventStatus="closed"
        traces={[]}
      />,
    );
    expect(useAgentStatusStore.getState().expanded).toBe(false);
    unmount2();
  });

  it("calls connectSocket on mount and disconnectSocket on unmount", () => {
    const { unmount } = renderPanel();
    expect(mockConnect).toHaveBeenCalled();
    expect(mockSubscribe).toHaveBeenCalledWith("evt-test-001");
    expect(mockOnEvent).toHaveBeenCalled();

    unmount();
    // After unmount, store should be disconnected
    expect(useAgentStatusStore.getState()._socketUnsub).toBeNull();
  });

  it("feed is updated after processing socket agent_progress event", () => {
    renderPanel();

    act(() => {
      useAgentStatusStore.getState().applySocketEvent({
        agent_name: "triage_agent",
        status: "PROCESSING",
        message: "正在分析告警上下文...",
        progress_percent: 30,
      });
    });

    const state = useAgentStatusStore.getState();
    expect(state.agents.triage_agent.status).toBe("PROCESSING");
    expect(state.agents.triage_agent.message).toBe("正在分析告警上下文...");
    expect(state.feed.length).toBe(1);
    expect(state.feed[0].message).toBe("正在分析告警上下文...");
  });

  it("feed is updated after processing socket agent_completed event", () => {
    renderPanel();

    act(() => {
      useAgentStatusStore.getState().applySocketEvent({
        agent_name: "evidence_agent",
        status: "COMPLETED",
        message: "证据采集完成，共 5 条证据",
        progress_percent: 100,
      });
    });

    const state = useAgentStatusStore.getState();
    expect(state.agents.evidence_agent.status).toBe("COMPLETED");
    expect(state.agents.evidence_agent.progress_percent).toBe(100);
    expect(state.feed.length).toBe(1);
  });

  it("feed is updated after processing socket agent_failed event", () => {
    renderPanel();

    act(() => {
      useAgentStatusStore.getState().applySocketEvent({
        agent_name: "verify_agent",
        status: "FAILED",
        message: "验证失败：目标不可达",
      });
    });

    const state = useAgentStatusStore.getState();
    expect(state.agents.verify_agent.status).toBe("FAILED");
    expect(state.agents.verify_agent.message).toBe("验证失败：目标不可达");
    expect(state.feed.length).toBe(1);
  });

  it("ignores socket events for unknown agent names", () => {
    renderPanel();

    act(() => {
      useAgentStatusStore.getState().applySocketEvent({
        agent_name: "unknown_agent",
        status: "PROCESSING",
        message: "test",
      });
    });

    // Feed should not have changed
    const state = useAgentStatusStore.getState();
    expect(state.feed.length).toBe(0);
  });

  it("caps feed at 200 entries from socket events", () => {
    renderPanel();

    act(() => {
      for (let i = 0; i < 250; i++) {
        useAgentStatusStore.getState().applySocketEvent({
          agent_name: "triage_agent",
          status: i % 3 === 0 ? "PROCESSING" : "COMPLETED",
          message: `消息 ${i + 1}`,
        });
      }
    });

    const state = useAgentStatusStore.getState();
    expect(state.feed.length).toBe(200);
    expect(state.feed[0].message).toBe("消息 51");
    expect(state.feed[199].message).toBe("消息 250");
  });
});

describe("agentStatusStore", () => {
  beforeEach(() => {
    useAgentStatusStore.setState({
      agents: Object.fromEntries(
        AGENT_NAMES.map((name) => [
          name,
          {
            agent_name: name,
            status: "IDLE",
            message: "",
            progress_percent: null,
            last_updated: null,
            duration_ms: null,
          },
        ]),
      ) as Record<AgentName, AgentStateEntry>,
      feed: [],
      expanded: true,
      socketConnected: false,
      _pollTimer: null,
      _socketUnsub: null,
    });
  });

  it("has all 12 agents initialized as IDLE", () => {
    const { agents } = useAgentStatusStore.getState();
    expect(Object.keys(agents)).toHaveLength(12);
    for (const name of AGENT_NAMES) {
      expect(agents[name].status).toBe("IDLE");
    }
  });

  it("replayFromTraces handles empty array gracefully", () => {
    const stateBefore = useAgentStatusStore.getState();
    act(() => {
      useAgentStatusStore.getState().replayFromTraces([]);
    });
    const stateAfter = useAgentStatusStore.getState();
    expect(stateAfter.feed).toEqual(stateBefore.feed);
  });

  it("replayFromTraces sorts traces chronologically", () => {
    const traces: AgentTrace[] = [
      makeTrace("report_agent", "completed", {
        started_at: "2026-07-28T10:00:20Z",
        completed_at: "2026-07-28T10:00:25Z",
      }),
      makeTrace("triage_agent", "completed", {
        started_at: "2026-07-28T10:00:00Z",
        completed_at: "2026-07-28T10:00:03Z",
      }),
    ];

    act(() => {
      useAgentStatusStore.getState().replayFromTraces(traces);
    });

    const { feed } = useAgentStatusStore.getState();
    // First entry should be triage (earlier timestamp)
    expect(feed[0].agent_name).toBe("triage_agent");
    // Second entry should be report (later timestamp)
    expect(feed[1].agent_name).toBe("report_agent");
  });

  it("replayFromTraces maps trace status → AgentStatus correctly", () => {
    const traces: AgentTrace[] = [
      makeTrace("triage_agent", "completed"),
      makeTrace("evidence_agent", "failed", {
        error_detail: "网络不可达",
      }),
      makeTrace("risk_agent", "processing"),
    ];

    act(() => {
      useAgentStatusStore.getState().replayFromTraces(traces);
    });

    const { agents } = useAgentStatusStore.getState();
    expect(agents.triage_agent.status).toBe("COMPLETED");
    expect(agents.evidence_agent.status).toBe("FAILED");
    expect(agents.risk_agent.status).toBe("PROCESSING");
  });

  it("setExpanded toggles expanded state", () => {
    const store = useAgentStatusStore.getState();
    expect(store.expanded).toBe(true);

    act(() => {
      store.setExpanded(false);
    });
    expect(useAgentStatusStore.getState().expanded).toBe(false);

    act(() => {
      useAgentStatusStore.getState().setExpanded(true);
    });
    expect(useAgentStatusStore.getState().expanded).toBe(true);
  });
});
