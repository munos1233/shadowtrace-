import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DecisionTraceTimeline from "../../src/components/audit/DecisionTraceTimeline";
import EventAuditPanel from "../../src/components/audit/EventAuditPanel";
import ToolAuditPage from "../../src/pages/ToolAuditPage";
import type {
  DecisionTraceEntry,
  DecisionTraceEntryType,
  ToolCallItem,
} from "../../src/types/trace";

const mockListToolCalls = vi.fn();
const mockGetDecisionTrace = vi.fn();
const mockGetEventToolCalls = vi.fn();
const mockGetTrajectory = vi.fn();

vi.mock("../../src/services/auditApi", () => ({
  listToolCalls: (...args: unknown[]) => mockListToolCalls(...args),
  getDecisionTrace: (...args: unknown[]) => mockGetDecisionTrace(...args),
  getEventToolCalls: (...args: unknown[]) => mockGetEventToolCalls(...args),
  getTrajectory: (...args: unknown[]) => mockGetTrajectory(...args),
}));

let socketHandler:
  | ((event: {
      type: string;
      event_id: string;
      payload: Record<string, unknown>;
    }) => void)
  | undefined;

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    subscribe: vi.fn(),
    onEvent: (
      handler: (event: {
        type: string;
        event_id: string;
        payload: Record<string, unknown>;
      }) => void,
    ) => {
      socketHandler = handler;
      return () => {
        socketHandler = undefined;
      };
    },
  },
}));

function makeToolCall(overrides: Partial<ToolCallItem> = {}): ToolCallItem {
  return {
    call_id: "call-1",
    event_id: "evt-73",
    action_id: "act-1",
    tool_name: "block_ip",
    tool_category: "response",
    status: "success",
    duration_ms: 35,
    provider: "mock_xdr",
    execution_owner: "direct_tool",
    disposition_id: "disp-1",
    writeback_status: "confirmed",
    parameters: {
      target: "203.0.113.9",
      password: "must-never-render",
      raw_payload: { authorization: "must-never-render-raw" },
    },
    result: { accepted: true },
    error_detail: null,
    retry_count: 1,
    started_at: "2026-07-28T01:00:00Z",
    completed_at: "2026-07-28T01:00:01Z",
    truncated: true,
    ...overrides,
  };
}

function renderWithProviders(node: React.ReactNode) {
  return render(
    <AntApp>
      <MemoryRouter>{node}</MemoryRouter>
    </AntApp>,
  );
}

describe("ToolAuditPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    socketHandler = undefined;
    mockListToolCalls.mockResolvedValue({
      data: {
        total: 2,
        page: 1,
        page_size: 20,
        items: [
          makeToolCall(),
          makeToolCall({
            call_id: "call-2",
            tool_name: "query_asset_info",
            status: "failed",
            writeback_status: null,
            disposition_id: null,
          }),
        ],
      },
    });
  });

  it("renders unified audit columns and distinct action/writeback badges", async () => {
    renderWithProviders(<ToolAuditPage />);

    expect(await screen.findByText("block_ip")).toBeInTheDocument();
    expect(screen.getByText("query_asset_info")).toBeInTheDocument();
    expect(screen.getAllByText("provider").length).toBeGreaterThan(0);
    expect(screen.getAllByText("execution_owner").length).toBeGreaterThan(0);
    expect(screen.getAllByText("disposition_id").length).toBeGreaterThan(0);
    expect(screen.getByText("Action success")).toBeInTheDocument();
    expect(screen.getByText("Writeback confirmed")).toBeInTheDocument();
  });

  it("filters by tool name and status", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ToolAuditPage />);
    await screen.findByText("block_ip");

    await user.type(screen.getByLabelText("工具名筛选"), "block_ip");
    await user.click(screen.getByRole("button", { name: "查 询" }));
    await waitFor(() =>
      expect(mockListToolCalls).toHaveBeenLastCalledWith(
        expect.objectContaining({ tool_name: "block_ip" }),
      ),
    );

    fireEvent.mouseDown(
      screen.getByRole("combobox", { name: "调用状态筛选" }),
    );
    await user.click(
      await screen.findByText("成功", {
        selector: ".ant-select-item-option-content",
      }),
    );
    await waitFor(() =>
      expect(mockListToolCalls).toHaveBeenLastCalledWith(
        expect.objectContaining({
          tool_name: "block_ip",
          status: "success",
        }),
      ),
    );
  });

  it("shows safe JSON detail, retry/error metadata and truncated marker", async () => {
    const user = userEvent.setup();
    renderWithProviders(<ToolAuditPage />);

    await user.click(
      await screen.findByRole("button", { name: "查看 block_ip 调用详情" }),
    );
    expect(await screen.findByText("部分内容已截断")).toBeInTheDocument();
    expect(screen.getAllByText(/字段级脱敏/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED]").length).toBeGreaterThan(0);
    expect(screen.queryByText("must-never-render")).not.toBeInTheDocument();
    expect(screen.queryByText("must-never-render-raw")).not.toBeInTheDocument();
    expect(screen.getByText("203.0.113.9")).toBeInTheDocument();
  });
});

const TRACE_TYPES: DecisionTraceEntryType[] = [
  "agent_execution",
  "tool_call",
  "llm_call",
  "state_transition",
  "approval",
  "action_execution",
  "disposition",
  "writeback",
];

function makeTraceEntries(): DecisionTraceEntry[] {
  return TRACE_TYPES.map((entryType, index) => ({
    entry_id: `entry-${index}`,
    entry_type: entryType,
    timestamp: `2026-07-28T01:00:0${7 - index}Z`,
    actor: entryType === "agent_execution" ? "RiskAgent" : "system",
    title: `${entryType} title`,
    detail:
      entryType === "agent_execution"
        ? {
            structured_conclusion: "存在横向移动风险",
            brief: "存在横向移动风险",
            evidence_refs: ["ev-1"],
            rules_applied: ["R-17"],
            model_name: "risk-model",
            model_version: "v2",
            confidence: 0.91,
            warnings: ["需要人工复核"],
            thought: "[NOT_RETAINED]",
            chain_of_thought: "[NOT_RETAINED]",
          }
        : entryType === "writeback"
          ? {
              status: "confirmed",
              disposition_id: "disp-1",
              confirmation_evidence: "XDR receipt #17",
            }
          : entryType === "tool_call"
            ? {
                tool_name: "query_process",
                status: "success",
                duration_ms: 42,
                result_summary: "found suspicious process",
              }
            : entryType === "state_transition"
              ? {
                  from_status: "analyzing",
                  to_status: "scoring",
                  reason: "analysis complete",
                }
              : { status: "success" },
    ref_id: entryType === "tool_call" ? "call-1" : `ref-${index}`,
  }));
}

describe("DecisionTraceTimeline", () => {
  it("defaults duration display to active_duration_ms over wall clock", () => {
    renderWithProviders(
      <DecisionTraceTimeline
        entries={makeTraceEntries()}
        summary={{
          agent_count: 1,
          tool_call_count: 1,
          llm_call_count: 0,
          total_tokens: 0,
          state_transition_count: 2,
          approval_count: 0,
          action_execution_count: 0,
          disposition_count: 0,
          writeback_count: 0,
          total_duration_ms: 32 * 60 * 1000,
          active_duration_ms: 2 * 60 * 1000,
        }}
      />,
    );
    const summary = screen.getByTestId("trace-duration-summary");
    expect(summary).toHaveTextContent("调查耗时");
    expect(summary).toHaveTextContent("2 min");
    expect(summary).toHaveTextContent("有效");
    expect(summary).toHaveTextContent("已排除审批空等");
    expect(summary).toHaveTextContent("墙钟");
    expect(summary).toHaveTextContent("32 min");
  });

  it("renders all eight ordered trace types and safe agent/writeback evidence", () => {
    renderWithProviders(<DecisionTraceTimeline entries={makeTraceEntries()} />);

    for (const label of [
      "Agent 执行",
      "工具调用",
      "模型调用",
      "状态转移",
      "审批",
      "动作执行",
      "处置命令",
      "外部同步",
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("存在横向移动风险")).toBeInTheDocument();
    expect(screen.getByText("ev-1")).toBeInTheDocument();
    expect(screen.getByText("risk-model / v2")).toBeInTheDocument();
    expect(screen.getByText("91%")).toBeInTheDocument();
    expect(screen.getByText("需要人工复核")).toBeInTheDocument();
    expect(screen.getByText("XDR receipt #17")).toBeInTheDocument();
    expect(screen.getByText("query_process")).toBeInTheDocument();
    expect(screen.getByText("found suspicious process")).toBeInTheDocument();
    expect(screen.getByText("analysis complete")).toBeInTheDocument();
    expect(screen.getAllByText("success").length).toBeGreaterThan(0);
    expect(
      screen.queryByText("must-not-render-hidden-reasoning"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("原始思维链未保留（ISSUE-131）")).toBeInTheDocument();
    expect(screen.queryByText("[NOT_RETAINED]")).not.toBeInTheDocument();

    const first = screen.getByTestId("trace-entry-writeback");
    const last = screen.getByTestId("trace-entry-agent_execution");
    expect(first.compareDocumentPosition(last) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("renders summary_unavailable when structured brief is missing", () => {
    renderWithProviders(
      <DecisionTraceTimeline
        entries={[
          {
            entry_id: "entry-empty",
            entry_type: "agent_execution",
            timestamp: "2026-07-28T01:00:00Z",
            actor: "memory_agent",
            title: "memory_agent 完成执行：summary_unavailable=empty_output",
            detail: {
              summary_unavailable: "empty_output",
              thought: "[NOT_RETAINED]",
            },
            ref_id: "trc-1",
          },
        ]}
      />,
    );
    expect(screen.getByText("summary_unavailable=empty_output")).toBeInTheDocument();
    expect(screen.getByText("原始思维链未保留（ISSUE-131）")).toBeInTheDocument();
  });

  it("filters entry types and opens linked tool detail", async () => {
    const onToolCallSelect = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(
      <DecisionTraceTimeline
        entries={makeTraceEntries()}
        onToolCallSelect={onToolCallSelect}
      />,
    );

    await user.click(screen.getByRole("button", { name: /tool_call title/ }));
    expect(onToolCallSelect).toHaveBeenCalledWith("call-1");

    await user.click(screen.getByRole("checkbox", { name: "工具调用" }));
    await waitFor(() =>
      expect(screen.queryByTestId("trace-entry-tool_call")).not.toBeInTheDocument(),
    );
    expect(screen.getByTestId("trace-entry-agent_execution")).toBeInTheDocument();
  });
});

describe("EventAuditPanel degradation and realtime", () => {
  it("falls back to the tool list when decision trace fails", async () => {
    mockGetDecisionTrace.mockRejectedValue(new Error("trace unavailable"));
    mockGetEventToolCalls.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 200, items: [makeToolCall()] },
    });
    mockGetTrajectory.mockResolvedValue({
      data: {
        event_id: "evt-73",
        total_steps: 1,
        agent_invocations: 0,
        tool_calls: 1,
        llm_calls: 0,
        metrics: {},
        findings: [],
        insufficient_trace: false,
      },
    });

    renderWithProviders(<EventAuditPanel eventId="evt-73" />);

    expect(
      await screen.findByText("决策轨迹暂不可用，已降级为工具调用列表"),
    ).toBeInTheDocument();
    expect(screen.getByText("block_ip")).toBeInTheDocument();
  });

  it("appends started/completed socket calls to the event audit", async () => {
    mockGetDecisionTrace.mockResolvedValue({
      data: {
        event_id: "evt-73",
        entries: [],
        summary: {},
        missing_sources: [],
        page: 1,
        page_size: 200,
        total: 0,
      },
    });
    mockGetEventToolCalls.mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    });
    mockGetTrajectory.mockResolvedValue({
      data: {
        event_id: "evt-73",
        total_steps: 0,
        agent_invocations: 0,
        tool_calls: 0,
        llm_calls: 0,
        metrics: {},
        findings: [],
        insufficient_trace: true,
      },
    });
    renderWithProviders(<EventAuditPanel eventId="evt-73" />);
    await screen.findByText("暂无符合条件的决策轨迹");

    await act(async () => {
      socketHandler?.({
        type: "tool_call_started",
        event_id: "evt-73",
        payload: { call_id: "call-live", tool_name: "query_dns" },
      });
    });
    expect(
      await screen.findByRole("button", { name: /query_dns 工具调用/ }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("running").length).toBeGreaterThan(0);

    mockGetEventToolCalls.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          makeToolCall({
            call_id: "call-live",
            tool_name: "query_dns",
            status: "success",
          }),
        ],
      },
    });
    await act(async () => {
      socketHandler?.({
        type: "tool_call_completed",
        event_id: "evt-73",
        payload: {
          call_id: "call-live",
          tool_name: "query_dns",
          status: "success",
        },
      });
    });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /query_dns 工具调用：status=success/ }),
      ).toBeInTheDocument(),
    );
  });

  it("hides the tool table when the decision trace is available", async () => {
    mockGetDecisionTrace.mockResolvedValue({
      data: {
        event_id: "evt-73",
        entries: [
          {
            entry_id: "entry-tool",
            entry_type: "tool_call",
            timestamp: "2026-07-28T01:00:00Z",
            actor: "block_ip",
            title: "block_ip 工具调用：status=success",
            detail: { status: "success" },
            ref_id: "call-1",
          },
        ],
        summary: {},
        missing_sources: [],
        page: 1,
        page_size: 200,
        total: 1,
      },
    });
    mockGetEventToolCalls.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 200, items: [makeToolCall()] },
    });
    mockGetTrajectory.mockResolvedValue({
      data: {
        event_id: "evt-73",
        total_steps: 1,
        agent_invocations: 0,
        tool_calls: 1,
        llm_calls: 0,
        metrics: {},
        findings: [],
        insufficient_trace: false,
      },
    });

    renderWithProviders(<EventAuditPanel eventId="evt-73" />);

    expect(await screen.findByText("block_ip 工具调用：status=success")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "工具" })).not.toBeInTheDocument();
  });
});
