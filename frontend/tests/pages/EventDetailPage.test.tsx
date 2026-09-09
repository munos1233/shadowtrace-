import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import type { EventDetailResponse } from "../../src/types/event";
import { ApiError } from "../../src/services/apiClient";
import { useAgentStatusStore } from "../../src/stores/agentStatusStore";

const mockGetEvent = vi.fn();
const mockGetTimeline = vi.fn();
const mockGetGraph = vi.fn();
const mockGetTraces = vi.fn();
const mockListActions = vi.fn();
const mockListDispositions = vi.fn();
const mockListConnectors = vi.fn();
const mockGetSourceRecord = vi.fn();
const mockGetExecutionJob = vi.fn();
const mockGetWriteback = vi.fn();
const mockGetDecisionTrace = vi.fn();
const mockGetEventToolCalls = vi.fn();
const mockGetTrajectory = vi.fn();
const mockCloseEvent = vi.fn();
const mockResolveUnknownAction = vi.fn();
const mockResolveWriteback = vi.fn();
const mockListMemoryReviews = vi.fn();
const mockApproveAction = vi.fn();
const mockRejectAction = vi.fn();
const mockGenerateReport = vi.fn();
const mockGetReport = vi.fn();

vi.mock("../../src/services/eventApi", () => ({
  getEvent: (...args: unknown[]) => mockGetEvent(...args),
  getTimeline: (...args: unknown[]) => mockGetTimeline(...args),
  getGraph: (...args: unknown[]) => mockGetGraph(...args),
  getTraces: (...args: unknown[]) => mockGetTraces(...args),
  listActions: (...args: unknown[]) => mockListActions(...args),
  listDispositions: (...args: unknown[]) => mockListDispositions(...args),
  listConnectors: (...args: unknown[]) => mockListConnectors(...args),
  getSourceRecord: (...args: unknown[]) => mockGetSourceRecord(...args),
  getExecutionJob: (...args: unknown[]) => mockGetExecutionJob(...args),
  getWriteback: (...args: unknown[]) => mockGetWriteback(...args),
  closeEvent: (...args: unknown[]) => mockCloseEvent(...args),
  resolveUnknownAction: (...args: unknown[]) => mockResolveUnknownAction(...args),
  resolveWriteback: (...args: unknown[]) => mockResolveWriteback(...args),
  approveAction: (...args: unknown[]) => mockApproveAction(...args),
  rejectAction: (...args: unknown[]) => mockRejectAction(...args),
  generateReport: (...args: unknown[]) => mockGenerateReport(...args),
  getReport: (...args: unknown[]) => mockGetReport(...args),
}));

vi.mock("../../src/services/knowledgeApi", () => ({
  listMemoryReviews: (...args: unknown[]) => mockListMemoryReviews(...args),
}));

vi.mock("../../src/utils/eventMemoryReviews", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/utils/eventMemoryReviews")>();
  return {
    ...actual,
    CLOSED_MEMORY_REVIEW_POLL_MS: [0, 20, 40],
  };
});

vi.mock("../../src/services/auditApi", () => ({
  getDecisionTrace: (...args: unknown[]) => mockGetDecisionTrace(...args),
  getEventToolCalls: (...args: unknown[]) => mockGetEventToolCalls(...args),
  getTrajectory: (...args: unknown[]) => mockGetTrajectory(...args),
}));

type SocketHandler = (event: {
  type: string;
  event_id: string;
  payload: Record<string, unknown>;
}) => void;

const socketHandlers = new Set<SocketHandler>();
/** @deprecated keep for tests that emit via the last-registered handler name */
let socketHandler: SocketHandler | undefined;
const mockSocketSubscribe = vi.fn();
const mockForgetEvent = vi.fn();

const MockIntersectionObserver = vi.fn(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
  takeRecords: vi.fn(() => []),
  root: null,
  rootMargin: "",
  thresholds: [],
}));
vi.stubGlobal("IntersectionObserver", MockIntersectionObserver);

function emitSocketEvent(event: {
  type: string;
  event_id: string;
  payload: Record<string, unknown>;
}) {
  for (const handler of [...socketHandlers]) {
    handler(event);
  }
}

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    subscribe: (eventId: string) => mockSocketSubscribe(eventId),
    forgetEvent: (...args: unknown[]) => mockForgetEvent(...args),
    get isConnected() {
      return true;
    },
    onEvent: (handler: SocketHandler) => {
      socketHandlers.add(handler);
      socketHandler = handler;
      return () => {
        socketHandlers.delete(handler);
        if (socketHandler === handler) {
          const remaining = [...socketHandlers];
          socketHandler =
            remaining.length > 0
              ? remaining[remaining.length - 1]
              : undefined;
        }
      };
    },
  },
}));

vi.mock("echarts-for-react", () => ({
  default: () => <div data-testid="risk-radar-chart" />,
}));

function makeInvestigationReport() {
  return {
    report_id: "rpt-70",
    event_id: "evt-70",
    title: "内部泄露调查报告",
    summary: "confirmed threat",
    sections: [
      {
        key: "overview",
        title: "概述",
        content: "分析结论：确认威胁。",
        data: {},
      },
    ],
    final_verdict: "confirmed_threat",
    risk_score: 72,
    severity: "high",
    version: 1,
    generated_by: "llm",
    generated_at: "2026-07-27T08:10:00Z",
    updated_at: "2026-07-27T08:10:00Z",
    report_quality: "complete" as const,
    degraded: false,
  };
}

function makeDetail(overrides: Partial<EventDetailResponse["event"]> = {}): EventDetailResponse {
  return {
    event: {
      event_id: "evt-70",
      event_type: "account_anomaly",
      title: "异常管理员登录",
      description: "登录位置与历史行为不符",
      status: "analyzing",
      severity: "high",
      risk_score: 72,
      confidence: 0.88,
      final_verdict: "confirmed_threat",
      entities: {
        accounts: [
          {
            entity_id: "account-1",
            entity_type: "account",
            username: "alice",
          },
        ],
        hosts: [
          {
            entity_id: "host-1",
            entity_type: "host",
            hostname: "workstation-01",
          },
        ],
        ips: [],
        domains: [],
        processes: [],
        files: [],
      },
      creation_source_ref: {
        source_id: "mock-xdr",
        source_type: "xdr",
        object_kind: "event",
        object_id: "source-event-70",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: "source-record-70",
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: ["alert-70"],
      raw_alert_snapshot: { status: "OPEN" },
      source_type: "xdr",
      occurred_at: "2026-07-27T08:00:00Z",
      created_at: "2026-07-27T08:01:00Z",
      updated_at: "2026-07-27T08:05:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: true,
      row_version: 1,
      event_context_snapshot: {
        source_snapshot: { status: "OPEN", assignee: "soc-l1" },
        source_sync_state: { disposition: "open" },
        risk_assessment: {
          risk_score: 72,
          severity: "high",
          confidence: 0.88,
          possible_false_positive: false,
          scoring_mode: "llm_and_rule",
          risk_factors: [
            ["asset_impact", 80],
            ["behavior_anomaly", 75],
            ["evidence_confidence", 88],
            ["attack_stage", 65],
            ["data_sensitivity", 60],
            ["threat_intel", 55],
          ].map(([factor_name, raw_score]) => ({
            factor_name: String(factor_name),
            raw_score: Number(raw_score),
            weight: 1 / 6,
            weighted_score: Number(raw_score) / 6,
            reasoning: `${factor_name} 研判依据`,
          })),
        },
        evidence_output: {
          evidence_list: [
            {
              evidence_id: "ev-normal",
              event_id: "evt-70",
              source: "identity",
              evidence_type: "login",
              description: "异常地理位置登录",
              confidence: 0.91,
              timestamp: "2026-07-27T08:00:00Z",
              raw_data: {},
              is_conflicting: false,
            },
            {
              evidence_id: "ev-conflict",
              event_id: "evt-70",
              source: "endpoint",
              evidence_type: "host_state",
              description: "终端状态与身份日志不一致",
              confidence: 0.66,
              timestamp: "2026-07-27T08:02:00Z",
              raw_data: {},
              is_conflicting: true,
            },
          ],
          conflicts: [
            {
              conflict_id: "conflict-1",
              event_id: "evt-70",
              description: "终端显示设备离线，但身份源记录到交互登录",
              evidence_ids: ["ev-conflict", "ev-normal"],
              sources: ["endpoint", "identity"],
            },
          ],
          gaps: [],
          success_sources: ["identity", "endpoint"],
          failed_sources: [],
          overall_confidence: 0.82,
          collection_status: "completed",
        },
      },
      ...overrides,
    },
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: null,
    pending_writeback_count: 0,
  };
}

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location-hash">{location.hash}</span>;
}

let EventDetailPage: typeof import("../../src/pages/EventDetailPage").default;

function renderPage(initialPath = "/events/evt-70#source") {
  return render(
    <AntApp>
      <MemoryRouter initialEntries={[initialPath]}>
        <LocationProbe />
        <Routes>
          <Route path="/events/:eventId" element={<EventDetailPage />} />
        </Routes>
      </MemoryRouter>
    </AntApp>,
  );
}

describe("EventDetailPage", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
    useAgentStatusStore.getState().stopWatching();
    socketHandlers.clear();
    socketHandler = undefined;
  });

  beforeEach(async () => {
    vi.clearAllMocks();
    socketHandlers.clear();
    socketHandler = undefined;
    mockGetEvent.mockResolvedValue({ data: makeDetail() });
    mockGetTimeline.mockResolvedValue({
      data: {
        storyline_id: "sty-70",
        event_id: "evt-70",
        narrative_summary: "异常账户登录后收集并外传敏感数据。",
        generated_by: "rule",
        phases: [
          {
            phase_order: 1,
            phase_name: "initial_access",
            tactic: "Initial Access",
            narrative: "攻击者使用有效账户。",
            entries: [
              {
                timestamp: "2026-07-27T08:00:00Z",
                description: "异常管理员登录",
                evidence_id: "ev-normal",
                technique_id: "T1078",
                severity_hint: "high",
              },
            ],
          },
        ],
      },
    });
    mockGetGraph.mockResolvedValue({
      data: {
        nodes: [
          {
            node_id: "node-account",
            event_id: "evt-70",
            entity_type: "account",
            entity_value: "alice",
            properties: {},
          },
          {
            node_id: "node-host",
            event_id: "evt-70",
            entity_type: "host",
            entity_value: "workstation-01",
            properties: {},
          },
        ],
        edges: [
          {
            edge_id: "edge-login",
            event_id: "evt-70",
            source_node_id: "node-account",
            target_node_id: "node-host",
            relation_type: "logged_in_to",
            evidence_id: "ev-normal",
            occurred_at: "2026-07-27T08:00:00Z",
          },
        ],
        central_entities: ["alice"],
        attack_path_candidates: [["node-account", "node-host"]],
      },
    });
    mockGetTraces.mockResolvedValue({
      data: { total: 0, page: 1, page_size: 20, items: [] },
    });
    mockListActions.mockResolvedValue({
      data: { total: 0, page: 1, page_size: 100, items: [] },
    });
    mockListDispositions.mockResolvedValue({ data: { event_id: "evt-70", items: [] } });
    mockListConnectors.mockResolvedValue({
      data: {
        items: [
          {
            connector_id: "conn-1",
            source_product: "mock_xdr",
            display_name: "Mock XDR",
            status: "online",
            capabilities: {
              LOG_INGESTION: "SUPPORTED",
              QUERY: "SUPPORTED",
              EVENT_DISPOSITION: "SUPPORTED",
              ENTITY_RESPONSE: "SUPPORTED",
            },
          },
        ],
      },
    });
    mockGetSourceRecord.mockResolvedValue({
      data: {
        source_record_id: "source-record-70",
        reference: makeDetail().event.creation_source_ref,
        current_source_disposition: "open",
        source_sync_state: "synced",
      },
    });
    mockGetExecutionJob.mockResolvedValue({ data: {} });
    mockGetWriteback.mockResolvedValue({ data: {} });
    mockCloseEvent.mockResolvedValue({
      data: {
        event_id: "evt-70",
        status: "closed",
        background_side_effects_pending: false,
        outstanding_side_effect_count: 0,
      },
    });
    mockResolveUnknownAction.mockResolvedValue({ data: {} });
    mockGenerateReport.mockResolvedValue({ data: { report: {} } });
    mockGetReport.mockRejectedValue(
      new ApiError({ error_code: "not_found", error_message: "report not found" }),
    );
    mockResolveWriteback.mockResolvedValue({ data: {} });
    mockApproveAction.mockResolvedValue({
      data: {
        action_id: "act-70",
        status: "approved",
        message: "approved",
        resume_status: "ok",
        degraded: false,
      },
    });
    mockRejectAction.mockResolvedValue({
      data: {
        action_id: "act-70",
        status: "rejected",
        message: "rejected",
        resume_status: null,
        degraded: false,
      },
    });
    mockListMemoryReviews.mockResolvedValue({ data: { total: 0, items: [] } });
    mockGetDecisionTrace.mockResolvedValue({
      data: {
        event_id: "evt-70",
        entries: [
          {
            entry_id: "entry-agent",
            entry_type: "agent_execution",
            timestamp: "2026-07-27T08:02:00Z",
            actor: "RiskAgent",
            title: "RiskAgent 完成风险评估",
            detail: {
              structured_conclusion: "高风险异常登录",
              evidence_refs: ["ev-normal"],
              confidence: 0.88,
            },
            ref_id: "trace-1",
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
      data: { total: 0, page: 1, page_size: 200, items: [] },
    });
    mockGetTrajectory.mockResolvedValue({
      data: {
        event_id: "evt-70",
        total_steps: 1,
        agent_invocations: 1,
        tool_calls: 0,
        llm_calls: 0,
        metrics: { evidence_yield: 0.8 },
        findings: [],
        insufficient_trace: false,
      },
    });
    ({ default: EventDetailPage } = await import("../../src/pages/EventDetailPage"));
  });

  it("renders overview, entities, six-dimensional risk and source capabilities", async () => {
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    expect(screen.getByTestId("agent-status-panel")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("workstation-01")).toBeInTheDocument();
    expect(screen.getByTestId("risk-radar")).toBeInTheDocument();
    expect(screen.getByText(/资产影响/)).toBeInTheDocument();
    expect(screen.getByText("Mock XDR（online）")).toBeInTheDocument();
    expect(mockSocketSubscribe).toHaveBeenCalledWith("evt-70");
  });

  it("forgets the socket event room on unmount", async () => {
    const { unmount } = renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    unmount();
    expect(mockForgetEvent).toHaveBeenCalledWith("evt-70");
  });

  it("syncs tab changes to the URL hash", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /证据/ }));
    expect(screen.getByTestId("location-hash")).toHaveTextContent("#evidence");
    expect(screen.getByText("异常地理位置登录")).toBeInTheDocument();
  });

  it("loads the attack storyline in the timeline tab", async () => {
    renderPage("/events/evt-70#timeline");

    expect(
      await screen.findByText("异常账户登录后收集并外传敏感数据。"),
    ).toBeInTheDocument();
    expect(screen.getByText("规则生成")).toBeInTheDocument();
    expect(mockGetTimeline).toHaveBeenCalledWith("evt-70");
  });

  it("loads the entity graph in the graph tab", async () => {
    renderPage("/events/evt-70#graph");

    expect(await screen.findByText("实体关系图")).toBeInTheDocument();
    expect(screen.getByText("2 个节点")).toBeInTheDocument();
    expect(screen.getByText("1 条关系")).toBeInTheDocument();
    expect(mockGetGraph).toHaveBeenCalledWith("evt-70");
  });

  it("does not load the entity graph until the graph tab is opened", async () => {
    renderPage("/events/evt-70#source");
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    expect(mockGetGraph).not.toHaveBeenCalled();
  });

  it("integrates decision trace and trajectory metrics in the audit tab", async () => {
    renderPage("/events/evt-70#audit");

    expect(await screen.findByText("完成风险评估")).toBeInTheDocument();
    expect(screen.getByText("高风险异常登录")).toBeInTheDocument();
    expect(screen.getByText("轨迹质量摘要")).toBeInTheDocument();
    expect(screen.getByText("80%")).toBeInTheDocument();
    expect(mockGetDecisionTrace).toHaveBeenCalledWith("evt-70", {
      page: 1,
      page_size: 200,
    });
  });

  it("mounts the optional event Q&A panel in its own tab", async () => {
    renderPage("/events/evt-70#chat");

    expect(await screen.findByText("事件问答")).toBeInTheDocument();
    expect(
      screen.getByText("基于事件上下文、风险评分、证据与决策轨迹回答；引用可直接跳转核验。"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("事件问题")).toBeInTheDocument();
  });

  it("hides the chat tab when VITE_EVENT_CHAT_ENABLED=false", async () => {
    vi.stubEnv("VITE_EVENT_CHAT_ENABLED", "false");
    renderPage("/events/evt-70#chat");

    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "问答" })).not.toBeInTheDocument();
    vi.unstubAllEnvs();
  });

  it("highlights conflicting evidence and exposes its reason", async () => {
    const user = userEvent.setup();
    renderPage("/events/evt-70#evidence");
    expect(await screen.findByText("终端状态与身份日志不一致")).toBeInTheDocument();
    const marker = screen.getByTestId("evidence-conflict-ev-conflict");
    expect(marker).toBeInTheDocument();
    const row = screen.getByTestId("evidence-row-ev-conflict");
    expect(row).toHaveStyle({ background: "rgba(255, 77, 79, 0.08)" });
    await user.hover(marker);
    expect(
      await screen.findByText("终端显示设备离线，但身份源记录到交互登录"),
    ).toBeInTheDocument();
  });

  it("refreshes local status and score after a realtime event", async () => {
    renderPage();
    expect(await screen.findByText("分析中")).toBeInTheDocument();
    mockGetEvent.mockResolvedValueOnce({
      data: makeDetail({
        status: "closed",
        risk_score: 88,
        event_context_snapshot: {
          ...makeDetail().event.event_context_snapshot,
          risk_assessment: {
            ...makeDetail().event.event_context_snapshot!.risk_assessment!,
            risk_score: 88,
          },
        },
      }),
    });
    emitSocketEvent({ type: "risk_updated", event_id: "evt-70", payload: {} });
    await waitFor(() => {
      expect(screen.getByText("已关闭")).toBeInTheDocument();
      expect(screen.getByText("六维风险 · 88")).toBeInTheDocument();
    });
  });

  it("distinguishes deferred actions and labels simulated terminal receipts", async () => {
    const user = userEvent.setup();
    const detail = makeDetail();
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot,
      disposition_receipts: [
        {
          writeback_id: "wb-70",
          sequence: 1,
          disposition_id: "disp-70",
          action_id: "action-70",
          source_record_id: "source-record-70",
          status: "confirmed",
          confirmation_evidence: "readback_verified",
          submitted_at: "2026-07-27T08:10:00Z",
          confirmed_at: "2026-07-27T08:11:00Z",
          simulated: true,
        },
      ],
      writeback_summary: {
        event_id: "evt-70",
        closure_cycle: 2,
        disposition_policy: "required",
        required_action_count: 1,
        applicable_action_count: 1,
        blocked_action_ids: [],
        readiness_counts: { ready: 1 },
        aggregate_readiness: "ready",
        writeback_counts: { confirmed: 1 },
        aggregate_status: "confirmed",
        terminal_event_action_id: "action-70",
        terminal_event_writeback_id: "wb-70",
        terminal_event_disposition: "closed",
        terminal_event_confirmed: true,
        external_unsynced: false,
        updated_at: "2026-07-27T08:11:00Z",
      },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "action-70",
            event_id: "evt-70",
            action_level: "l1",
            action_category: "response",
            action_name: "更新外部事件终态",
            tool_name: "update_source_event_disposition",
            execution_phase: "post_verify",
            activation_condition: "after_effect_resolution",
            parameters: {},
            status: "approved",
            execution_owner: "xdr_managed",
            updated_at: null,
          },
        ],
      },
    });
    mockListDispositions.mockResolvedValue({
      data: {
        event_id: "evt-70",
        items: [
          {
            disposition: {
              disposition_id: "disp-70",
              action_id: "action-70",
              closure_cycle: 2,
              intent_kind: "event_status_update",
              source_locator: {
                source_id: "mock-xdr",
                source_type: "xdr",
                object_kind: "event",
                object_id: "source-event-70",
              },
              operation_code: "close_event",
              operation_params: {},
              target_results: [],
              operator_id: "shadowtrace",
              idempotency_key: "idem-70",
              execution_owner: "xdr_managed",
            },
            writeback_status: "confirmed",
          },
        ],
      },
    });
    mockGetWriteback.mockResolvedValue({
      data: {
        writeback_id: "wb-70",
        disposition_id: "disp-70",
        action_id: "action-70",
        status: "confirmed",
        confirmation_evidence: "readback_verified",
        evidence_tier: "strong",
        provider_code: "OK",
        message_code: null,
        target_results: [],
        simulated: true,
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    expect(await screen.findByText("待效果验证后激活")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /外部写回/ }));
    expect(await screen.findByTestId("simulated-receipt-warning")).toBeInTheDocument();
    expect(screen.getByText(/终态 EVENT_STATUS_UPDATE/)).toBeInTheDocument();
    expect(screen.getByTestId("writeback-row-wb-70")).toHaveStyle({
      background: "rgba(82, 196, 26, 0.10)",
    });
  });

  it("shows simulated warning when only GET writeback carries simulated", async () => {
    const user = userEvent.setup();
    const detail = makeDetail();
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot,
      disposition_receipts: [],
      writeback_summary: {
        event_id: "evt-70",
        closure_cycle: 2,
        disposition_policy: "required",
        required_action_count: 1,
        applicable_action_count: 1,
        blocked_action_ids: [],
        readiness_counts: { ready: 1 },
        aggregate_readiness: "ready",
        writeback_counts: { confirmed: 1 },
        aggregate_status: "confirmed",
        terminal_event_action_id: "action-70",
        terminal_event_writeback_id: "wb-api-370",
        terminal_event_disposition: "closed",
        terminal_event_confirmed: true,
        external_unsynced: false,
        updated_at: "2026-07-27T08:11:00Z",
      },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockListDispositions.mockResolvedValue({
      data: {
        event_id: "evt-70",
        items: [
          {
            disposition: {
              disposition_id: "disp-api-370",
              action_id: "action-70",
              closure_cycle: 2,
              intent_kind: "event_status_update",
              source_locator: {
                source_id: "mock-xdr",
                source_type: "xdr",
                object_kind: "event",
                object_id: "source-event-70",
              },
              operation_code: "close_event",
              operation_params: {},
              target_results: [],
              operator_id: "shadowtrace",
              idempotency_key: "idem-api-370",
              execution_owner: "xdr_managed",
            },
            writeback_status: "confirmed",
          },
        ],
      },
    });
    mockGetWriteback.mockResolvedValue({
      data: {
        writeback_id: "wb-api-370",
        disposition_id: "disp-api-370",
        action_id: "action-70",
        status: "confirmed",
        confirmation_evidence: "readback_verified",
        evidence_tier: "strong",
        provider_code: "OK",
        message_code: null,
        target_results: [],
        simulated: true,
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /外部写回/ }));
    expect(await screen.findByTestId("simulated-receipt-warning")).toBeInTheDocument();
  });

  it("does not paint entity required=true applicable=false as terminal writeback done", async () => {
    const user = userEvent.setup();
    mockListActions.mockResolvedValue({
      data: {
        total: 2,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "act-entity-331",
            event_id: "evt-70",
            action_level: "l3",
            action_category: "response",
            action_name: "阻断 IP",
            tool_name: "block_ip",
            execution_phase: "immediate",
            parameters: {},
            status: "success",
            execution_owner: "xdr_managed",
            writeback_required: true,
            writeback_applicable: false,
            writeback_status: null,
            updated_at: null,
          },
          {
            action_id: "act-terminal-331",
            event_id: "evt-70",
            action_level: "l1",
            action_category: "response",
            action_name: "更新外部事件终态",
            tool_name: "update_source_event_disposition",
            execution_phase: "post_verify",
            activation_condition: "after_effect_resolution",
            parameters: {},
            status: "success",
            execution_owner: "xdr_managed",
            writeback_required: true,
            writeback_applicable: true,
            writeback_status: "confirmed",
            updated_at: null,
          },
        ],
      },
    });
    mockListDispositions.mockResolvedValue({
      data: {
        event_id: "evt-70",
        items: [
          {
            disposition: {
              disposition_id: "disp-entity-331",
              action_id: "act-entity-331",
              closure_cycle: 1,
              intent_kind: "entity_action_submit",
              source_locator: {
                source_id: "mock-xdr",
                source_type: "xdr",
                object_kind: "event",
                object_id: "source-event-70",
              },
              operation_code: "isolate_host",
              operation_params: {},
              target_results: [],
              operator_id: "shadowtrace",
              idempotency_key: "idem-entity-331",
              execution_owner: "xdr_managed",
            },
            writeback_status: "accepted",
          },
        ],
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    expect(await screen.findByTestId("action-writeback-act-entity-331")).toHaveTextContent(
      "不承担终态写回",
    );
    expect(screen.getByTestId("action-writeback-act-terminal-331")).toHaveTextContent(
      "终态写回已确认",
    );
    expect(screen.getAllByText("事件级").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("tab", { name: /外部写回/ }));
    const writebackPanel = await screen.findByRole("tabpanel", { name: /外部写回/ });
    expect(await within(writebackPanel).findByText("实体侧效应已提交")).toBeInTheDocument();
    expect(within(writebackPanel).queryByText("终态写回已确认")).not.toBeInTheDocument();
  });

  it("does not paint pending terminal receipts as confirmed-green", async () => {
    const user = userEvent.setup();
    const detail = makeDetail();
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot,
      disposition_receipts: [
        {
          writeback_id: "wb-pending-331",
          sequence: 1,
          disposition_id: "disp-pending-331",
          action_id: "action-70",
          source_record_id: "source-event-70",
          status: "pending",
          confirmation_evidence: null,
          submitted_at: "2026-07-27T08:10:00Z",
          confirmed_at: null,
          simulated: false,
        },
      ],
      writeback_summary: {
        event_id: "evt-70",
        closure_cycle: 2,
        disposition_policy: "required",
        required_action_count: 1,
        applicable_action_count: 1,
        blocked_action_ids: [],
        readiness_counts: { ready: 1 },
        aggregate_readiness: "ready",
        writeback_counts: { pending: 1 },
        aggregate_status: "pending",
        terminal_event_action_id: "action-70",
        terminal_event_writeback_id: "wb-pending-331",
        terminal_event_disposition: "closed",
        terminal_event_confirmed: false,
        external_unsynced: true,
        updated_at: "2026-07-27T08:10:00Z",
      },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "action-70",
            event_id: "evt-70",
            action_level: "l1",
            action_category: "response",
            action_name: "更新外部事件终态",
            tool_name: "update_source_event_disposition",
            execution_phase: "post_verify",
            activation_condition: "after_effect_resolution",
            parameters: {},
            status: "success",
            execution_owner: "xdr_managed",
            writeback_required: true,
            writeback_applicable: true,
            writeback_status: "pending",
            updated_at: null,
          },
        ],
      },
    });
    mockListDispositions.mockResolvedValue({
      data: {
        event_id: "evt-70",
        items: [
          {
            disposition: {
              disposition_id: "disp-pending-331",
              action_id: "action-70",
              closure_cycle: 2,
              intent_kind: "event_status_update",
              source_locator: {
                source_id: "mock-xdr",
                source_type: "xdr",
                object_kind: "event",
                object_id: "source-event-70",
              },
              operation_code: "close_event",
              operation_params: {},
              target_results: [],
              operator_id: "shadowtrace",
              idempotency_key: "idem-pending-331",
              execution_owner: "xdr_managed",
            },
            writeback_status: "pending",
          },
        ],
      },
    });
    mockGetWriteback.mockResolvedValue({
      data: {
        writeback_id: "wb-pending-331",
        disposition_id: "disp-pending-331",
        action_id: "action-70",
        status: "pending",
        confirmation_evidence: null,
        evidence_tier: null,
        provider_code: null,
        message_code: null,
        target_results: [],
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /外部写回/ }));
    const row = await screen.findByTestId("writeback-row-wb-pending-331");
    expect(row).not.toHaveStyle({ background: "rgba(82, 196, 26, 0.10)" });
    expect(screen.queryByText("终态写回已确认")).not.toBeInTheDocument();
  });

  it("does not treat empty-string terminal writeback id as a confirmed terminal row", async () => {
    const user = userEvent.setup();
    const detail = makeDetail();
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot,
      disposition_receipts: [
        {
          writeback_id: "",
          sequence: 1,
          disposition_id: "disp-empty-331",
          action_id: "act-entity-331",
          source_record_id: "source-event-70",
          status: "accepted",
          confirmation_evidence: null,
          submitted_at: "2026-07-27T08:10:00Z",
          confirmed_at: null,
          simulated: false,
          target_results: [],
        },
      ],
      writeback_summary: {
        event_id: "evt-70",
        closure_cycle: 1,
        disposition_policy: "required",
        required_action_count: 1,
        applicable_action_count: 0,
        blocked_action_ids: [],
        readiness_counts: { not_required: 1 },
        aggregate_readiness: "not_required",
        writeback_counts: { accepted: 1 },
        aggregate_status: "accepted",
        terminal_event_action_id: "",
        terminal_event_writeback_id: "",
        terminal_event_disposition: null,
        terminal_event_confirmed: false,
        external_unsynced: true,
        updated_at: "2026-07-27T08:10:00Z",
      },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "act-entity-331",
            event_id: "evt-70",
            action_level: "l3",
            action_category: "response",
            action_name: "阻断 IP",
            tool_name: "block_ip",
            execution_phase: "immediate",
            parameters: {},
            status: "success",
            execution_owner: "xdr_managed",
            writeback_required: true,
            writeback_applicable: false,
            writeback_status: "accepted",
            updated_at: null,
          },
        ],
      },
    });
    mockListDispositions.mockResolvedValue({
      data: {
        event_id: "evt-70",
        items: [
          {
            disposition: {
              disposition_id: "disp-empty-331",
              action_id: "act-entity-331",
              closure_cycle: 1,
              intent_kind: "entity_action_submit",
              source_locator: {
                source_id: "mock-xdr",
                source_type: "xdr",
                object_kind: "event",
                object_id: "source-event-70",
              },
              operation_code: "isolate_host",
              operation_params: {},
              target_results: [],
              operator_id: "shadowtrace",
              idempotency_key: "idem-empty-331",
              execution_owner: "xdr_managed",
            },
            writeback_status: "accepted",
          },
        ],
      },
    });
    mockGetWriteback.mockResolvedValue({
      data: {
        writeback_id: "",
        disposition_id: "disp-empty-331",
        action_id: "act-entity-331",
        status: "accepted",
        confirmation_evidence: null,
        evidence_tier: null,
        provider_code: null,
        message_code: null,
        target_results: [],
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /外部写回/ }));
    const writebackPanel = await screen.findByRole("tabpanel", { name: /外部写回/ });
    expect(within(writebackPanel).queryByText(/终态 EVENT_STATUS_UPDATE/)).not.toBeInTheDocument();
    expect(within(writebackPanel).queryByText("终态写回已确认")).not.toBeInTheDocument();
    expect(await within(writebackPanel).findByText("实体侧效应已提交")).toBeInTheDocument();
  });

  it("shows POST_VERIFY label after deferred action enters execution", async () => {
    const user = userEvent.setup();
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "action-70",
            event_id: "evt-70",
            action_level: "l1",
            action_category: "response",
            action_name: "更新外部事件终态",
            tool_name: "update_source_event_disposition",
            execution_phase: "post_verify",
            activation_condition: "after_effect_resolution",
            parameters: {},
            status: "executing",
            execution_owner: "xdr_managed",
            updated_at: null,
          },
        ],
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    expect(await screen.findByText("POST_VERIFY")).toBeInTheDocument();
    expect(screen.queryByText("待效果验证后激活")).not.toBeInTheDocument();
  });

  it("shows analysis-only deferred banner without response CTA", async () => {
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "reporting" }),
        response_phase_state: "analysis_complete_deferred",
        next_recommended_action: "none",
        full_loop_available: true,
        phase_message: "分析已完成，未生成/执行处置方案。",
      },
    });

    renderPage("/events/evt-70");
    const banner = await screen.findByTestId("analysis-phase-banner");
    expect(banner).toBeInTheDocument();
    expect(screen.getByText("分析已完成，处置方案未生成")).toBeInTheDocument();
    expect(screen.getAllByText("分析已完成，未生成/执行处置方案。").length).toBeGreaterThan(0);
    expect(screen.queryByTestId("start-response-execution-cta")).not.toBeInTheDocument();
  });

  it("shows todo bar with report pending and operational insights", async () => {
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "reporting", degraded_flags: ["llm_degraded"] }),
        analysis_only_complete: true,
        phase_message: "分析已完成，请生成报告。",
        next_recommended_action: "none",
      },
    });

    renderPage("/events/evt-70");
    expect(await screen.findByTestId("event-todo-bar")).toBeInTheDocument();
    expect(screen.getByText("待生成报告")).toBeInTheDocument();
    expect(screen.getByTestId("event-operational-insights")).toBeInTheDocument();
    expect(screen.getByText("分析已完成，请生成报告。")).toBeInTheDocument();
    expect(screen.getByTestId("event-degraded-flags")).toHaveTextContent("llm_degraded");
  });

  it("navigates to audit tab from decision basis todo", async () => {
    const user = userEvent.setup();
    const scrollIntoView = vi.fn();
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "reporting" }),
        analysis_only_complete: true,
      },
    });
    renderPage("/events/evt-70");
    expect(await screen.findByTestId("event-todo-bar")).toBeInTheDocument();
    await user.click(screen.getByTestId("todo-nav-decision-basis"));
    expect(screen.getByTestId("location-hash")).toHaveTextContent("#audit");
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalled());
  });

  it("scrolls to tabs when the todo target is already open", async () => {
    const user = userEvent.setup();
    const scrollIntoView = vi.fn();
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "reporting" }),
        analysis_only_complete: true,
      },
    });
    renderPage("/events/evt-70#audit");
    expect(await screen.findByTestId("event-todo-bar")).toBeInTheDocument();
    await user.click(screen.getByTestId("todo-nav-decision-basis"));
    expect(screen.getByTestId("location-hash")).toHaveTextContent("#audit");
    expect(scrollIntoView).toHaveBeenCalled();
  });

  it("renders outstanding side-effects panel and todo without actions-tab nav", async () => {
    const detail = makeDetail({ status: "reporting" });
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot!,
      report: { report_id: "evt-70", summary: "ready" },
    };
    mockGetEvent.mockResolvedValue({
      data: {
        ...detail,
        analysis_only_complete: true,
        next_recommended_action: "close",
        gate_applicable_outstanding_count: 1,
        outstanding_side_effect_count: 1,
        outstanding_side_effects: [
          {
            action_id: "act-gate-1",
            scope: "gate_applicable",
            action_status: "executing",
            execution_phase: "post_verify",
            writeback_applicable: true,
            convergence_policy: "terminal_writeback",
            job_status: "running",
            outbox_delivery_status: "ready",
            plan_revision: 1,
            blocking_reason: "executing_action",
          },
        ],
      },
    });

    renderPage("/events/evt-70");
    expect(await screen.findByTestId("outstanding-side-effects-panel")).toBeInTheDocument();
    expect(screen.getByTestId("outstanding-side-effects-table")).toBeInTheDocument();
    expect(screen.getByText(/关单受阻：1 项门禁副作用待收敛/)).toBeInTheDocument();
    expect(screen.queryByTestId("todo-nav-side-effects-pending")).not.toBeInTheDocument();
    const closeButton = await screen.findByTestId("event-close-button");
    expect(closeButton).toBeDisabled();
  });

  it("refreshes detail when close is blocked by closed_side_effects_pending", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    const user = userEvent.setup();
    const detail = {
      ...makeDetail({ status: "reporting" }),
      next_recommended_action: "close" as const,
      gate_applicable_outstanding_count: 0,
      outstanding_side_effect_count: 0,
    };
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot!,
      report: { report_id: "evt-70", summary: "ready" },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockCloseEvent.mockRejectedValueOnce(
      new ApiError({
        error_code: "closed_side_effects_pending",
        error_message: "closed side effects pending",
        details: { gate_applicable_outstanding_count: 2 },
      }),
    );

    renderPage("/events/evt-70");
    const closeButton = await screen.findByTestId("event-close-button");
    await waitFor(() => expect(closeButton).not.toBeDisabled());
    const callsBeforeClose = mockGetEvent.mock.calls.length;
    await user.click(closeButton);
    await user.click(screen.getByRole("button", { name: "确认结案" }));
    await waitFor(() => expect(mockCloseEvent).toHaveBeenCalled());
    await waitFor(() =>
      expect(mockGetEvent.mock.calls.length).toBeGreaterThan(callsBeforeClose),
    );
  });

  it("closes event with reason via todo bar", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    const user = userEvent.setup();
    const detail = makeDetail({ status: "reporting" });
    detail.next_recommended_action = "close";
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot!,
      report: { report_id: "evt-70", summary: "ready" },
    };
    mockGetEvent.mockResolvedValue({ data: detail });

    renderPage("/events/evt-70");
    const closeButton = await screen.findByTestId("event-close-button");
    await waitFor(() => expect(closeButton).not.toBeDisabled());
    await user.click(closeButton);
    await user.click(screen.getByRole("button", { name: "确认结案" }));
    await waitFor(() =>
      expect(mockCloseEvent).toHaveBeenCalledWith("evt-70", {
        reason: "operator closed from event detail",
      }),
    );
  });

  it("warns when close succeeds with pending side effects", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    const user = userEvent.setup();
    const detail = makeDetail({ status: "reporting" });
    detail.next_recommended_action = "close";
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot!,
      report: { report_id: "evt-70", summary: "ready" },
    };
    mockGetEvent.mockResolvedValue({ data: detail });
    mockCloseEvent.mockResolvedValue({
      data: {
        event_id: "evt-70",
        status: "closed",
        background_side_effects_pending: true,
        outstanding_side_effect_count: 1,
      },
    });

    renderPage("/events/evt-70");
    const closeButton = await screen.findByTestId("event-close-button");
    await waitFor(() => expect(closeButton).not.toBeDisabled());
    await user.click(closeButton);
    await user.click(screen.getByRole("button", { name: "确认结案" }));
    expect(await screen.findByText("事件已结案，后台副作用仍在处理")).toBeInTheDocument();
  });

  it("resolves unknown action from todo bar", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "admin");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "act-unknown",
            event_id: "evt-70",
            action_name: "block_ip",
            action_category: "security",
            tool_name: "mock_tool",
            status: "unknown",
            target: "1.2.3.4",
            execution_owner: "DIRECT_TOOL",
            execution_phase: "immediate",
            created_at: "2026-08-01T00:00:00Z",
            updated_at: "2026-08-01T00:00:00Z",
          },
        ],
      },
    });
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "executing_response" }),
        execution_substate: "manual_resolution",
      },
    });
    renderPage("/events/evt-70");
    expect(await screen.findByText("写回待处理")).toBeInTheDocument();
    await user.click(screen.getByTestId("event-resolve-unknown-button"));
    await user.type(screen.getByLabelText("裁决说明"), "人工确认外部已生效");
    await user.click(screen.getByRole("button", { name: "提交裁决" }));
    await waitFor(() =>
      expect(mockResolveUnknownAction).toHaveBeenCalledWith("act-unknown", {
        resolution: "manual_confirmed",
        comment: "人工确认外部已生效",
      }),
    );
  });

  it("disables close for approver-only roles", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "approver");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const detail = makeDetail({ status: "reporting" });
    detail.next_recommended_action = "close";
    detail.event.event_context_snapshot = {
      ...detail.event.event_context_snapshot!,
      report: { report_id: "evt-70", summary: "ready" },
    };
    mockGetEvent.mockResolvedValue({ data: detail });

    renderPage("/events/evt-70");
    const closeButton = await screen.findByTestId("event-close-button");
    expect(closeButton).toBeDisabled();
    expect(screen.getByText(/结案需 analyst 或 admin/)).toBeInTheDocument();
  });

  it("disables resolve-unknown for non-admin roles", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    mockListActions.mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "act-unknown",
            event_id: "evt-70",
            action_name: "block_ip",
            action_category: "security",
            tool_name: "mock_tool",
            status: "unknown",
            target: "1.2.3.4",
            execution_owner: "DIRECT_TOOL",
            execution_phase: "immediate",
            created_at: "2026-08-01T00:00:00Z",
            updated_at: "2026-08-01T00:00:00Z",
          },
        ],
      },
    });
    mockGetEvent.mockResolvedValue({
      data: {
        ...makeDetail({ status: "executing_response" }),
        execution_substate: "manual_resolution",
      },
    });
    renderPage("/events/evt-70");
    const resolveButton = await screen.findByTestId("event-resolve-unknown-button");
    expect(resolveButton).toBeDisabled();
    expect(screen.getByText("裁决 UNKNOWN 需 admin 角色")).toBeInTheDocument();
  });

  it("refreshes detail after writeback_updated socket event", async () => {
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    const callsBefore = mockGetEvent.mock.calls.length;
    emitSocketEvent({
      type: "writeback_updated",
      event_id: "evt-70",
      payload: { writeback_id: "wbk-1", status: "confirmed" },
    });
    await waitFor(() => expect(mockGetEvent.mock.calls.length).toBeGreaterThan(callsBefore));
  });

  it("refreshes detail after report_generated socket event", async () => {
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    const callsBefore = mockGetEvent.mock.calls.length;
    mockGetEvent.mockResolvedValueOnce({
      data: makeDetail({
        status: "reporting",
        event_context_snapshot: {
          ...makeDetail().event.event_context_snapshot,
          report: { report_id: "evt-70", summary: "generated" },
        },
      }),
    });
    emitSocketEvent({ type: "report_generated", event_id: "evt-70", payload: {} });
    await waitFor(() => expect(mockGetEvent.mock.calls.length).toBeGreaterThan(callsBefore));
  });

  // ---- ISSUE-207: inline approval in event detail -----------------------

  function waitingApprovalActionsFixture() {
    return {
      data: {
        total: 1,
        page: 1,
        page_size: 100,
        items: [
          {
            action_id: "act-70",
            event_id: "evt-70",
            action_level: "l4",
            action_category: "response",
            action_name: "block_ip",
            tool_name: "block_ip",
            execution_phase: "immediate",
            status: "waiting_approval",
            target: "198.51.100.7",
            target_type: "ip",
            execution_owner: "xdr_managed",
            parameters: {},
            updated_at: "2026-07-27T08:06:00Z",
          },
        ],
      },
    };
  }

  it("approves a waiting_approval action inline, shows resume feedback and refreshes tables", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({
      data: makeDetail({ status: "waiting_approval" }),
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    const listCallsBefore = mockListActions.mock.calls.length;
    const eventCallsBefore = mockGetEvent.mock.calls.length;

    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    await waitFor(() => {
      expect(mockApproveAction).toHaveBeenCalledWith(
        "act-70",
        expect.objectContaining({ decision_id: expect.any(String) }),
      );
    });
    // resume_status=ok feedback surfaced (ISSUE-207).
    expect(
      await screen.findByText("动作 act-70 已批准，调查流程已继续"),
    ).toBeInTheDocument();
    // Locked refresh: actions table + event are re-fetched, not just a toast.
    await waitFor(() => {
      expect(mockListActions.mock.calls.length).toBeGreaterThan(listCallsBefore);
    });
    await waitFor(() => {
      expect(mockGetEvent.mock.calls.length).toBeGreaterThan(eventCallsBefore);
    });
  });

  it("surfaces failed resume without pretending the investigation continued", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });
    mockApproveAction.mockResolvedValueOnce({
      data: {
        action_id: "act-70",
        status: "approved",
        message: "approved",
        resume_status: "failed",
        degraded: true,
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      await screen.findByText(
        "动作 act-70 已批准，但调查流程继续失败，请查看事件状态（降级模式运行）",
      ),
    ).toBeInTheDocument();
  });

  it("includes backend message detail when resume failed", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });
    mockApproveAction.mockResolvedValueOnce({
      data: {
        action_id: "act-70",
        status: "approved",
        message: "graph resume timeout",
        resume_status: "failed",
        degraded: false,
      },
    });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      await screen.findByText(
        "动作 act-70 已批准，但调查流程继续失败，请查看事件状态：graph resume timeout",
      ),
    ).toBeInTheDocument();
  });

  it("rejects a waiting_approval action inline", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("reject-action-act-70");
    await user.click(screen.getByTestId("reject-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "拒绝动作" });
    await user.type(within(dialog).getByPlaceholderText("请填写拒绝原因"), "不符合处置策略");
    await user.click(within(dialog).getByRole("button", { name: /拒\s*绝/ }));

    await waitFor(() => {
      expect(mockRejectAction).toHaveBeenCalledWith(
        "act-70",
        expect.objectContaining({ comment: "不符合处置策略" }),
      );
    });
    expect(await screen.findByText("动作 act-70 已拒绝")).toBeInTheDocument();
  });

  it("disables inline approval buttons and explains role without approver", async () => {
    // Single-token dev/compose mode: known token + explicit analyst override.
    vi.stubEnv("VITE_AUTH_ROLES", "analyst");
    vi.stubEnv("VITE_DEV_AUTH_TOKEN", "e2e-token");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    expect(screen.getByTestId("approve-action-act-70")).toBeDisabled();
    expect(screen.getByTestId("reject-action-act-70")).toBeDisabled();
    expect(screen.getByTestId("approval-role-hint")).toHaveTextContent(
      "当前角色无审批权限",
    );
    expect(screen.getByText(/需要 approver 或 admin 角色/)).toBeInTheDocument();
  });

  it("shows a 403 permission hint when approve is forbidden by backend", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });
    mockApproveAction.mockRejectedValueOnce(
      new ApiError({ error_code: "forbidden", error_message: "requires one of roles: approver" }),
    );

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      await screen.findByText("无审批权限（403）：需要 approver 角色，请联系管理员授权。"),
    ).toBeInTheDocument();
  });

  it("keeps inline approval enabled when roles are unknown (production trusted-proxy)", async () => {
    // No VITE_AUTH_ROLES / VITE_DEV_AUTH_TOKEN stubbed → hasKnownAuthRoles() is
    // false; the real principal comes from the backend (trusted-proxy X-Auth-Roles),
    // so the UI must not hard-disable the button (ISSUE-207 review blocker fix).
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    const approveButton = await screen.findByTestId("approve-action-act-70");
    expect(approveButton).not.toBeDisabled();
    expect(screen.queryByTestId("approval-role-hint")).not.toBeInTheDocument();
  });

  it("warns when approval succeeded but the follow-up refresh fails", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions
      .mockResolvedValueOnce(waitingApprovalActionsFixture())
      .mockRejectedValueOnce(new Error("actions 500"))
      .mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent
      .mockResolvedValueOnce({ data: makeDetail({ status: "waiting_approval" }) })
      .mockRejectedValueOnce(new Error("event 500"))
      .mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    // Approval fact itself succeeded; only the re-sync failed — surfaced as a
    // refresh warning, never as an approval failure (ISSUE-207 review).
    expect(
      await screen.findByText("审批已成功，但页面刷新失败，请手动刷新查看最新状态。"),
    ).toBeInTheDocument();
    // The stale row must not offer a second submit: the action is locally
    // marked as decided while awaiting re-sync (ISSUE-207 review).
    expect(screen.getByTestId("approval-decided-act-70")).toBeInTheDocument();
    expect(screen.queryByTestId("approve-action-act-70")).not.toBeInTheDocument();
    expect(screen.queryByTestId("reject-action-act-70")).not.toBeInTheDocument();
  });

  it("handles approval_decision_conflict by closing dialog, refreshing and explaining", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions.mockResolvedValue(waitingApprovalActionsFixture());
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "waiting_approval" }) });
    mockApproveAction.mockRejectedValueOnce(
      new ApiError({
        error_code: "approval_decision_conflict",
        error_message: "already decided by another approver",
      }),
    );

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    const listCallsBefore = mockListActions.mock.calls.length;
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    expect(
      await screen.findByText("该审批已由其他审批者处理，已刷新最新状态。"),
    ).toBeInTheDocument();
    // Dialog closed and actions/event re-fetched instead of offering stale retries.
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "批准动作" })).not.toBeInTheDocument(),
    );
    await waitFor(() => {
      expect(mockListActions.mock.calls.length).toBeGreaterThan(listCallsBefore);
    });
  });

  it("409 with a failed refresh still blocks a second approve", async () => {
    vi.stubEnv("VITE_AUTH_ROLES", "analyst,approver");
    const user = userEvent.setup();
    mockListActions
      .mockResolvedValueOnce(waitingApprovalActionsFixture()) // initial load
      .mockRejectedValueOnce(new Error("actions 500")); // refresh after 409
    mockGetEvent
      .mockResolvedValueOnce({ data: makeDetail({ status: "waiting_approval" }) })
      .mockRejectedValueOnce(new Error("event 500"));
    mockApproveAction.mockRejectedValueOnce(
      new ApiError({
        error_code: "approval_decision_conflict",
        error_message: "already decided",
      }),
    );

    renderPage("/events/evt-70#actions");
    await user.click(await screen.findByRole("tab", { name: /安全处置/ }));
    await screen.findByTestId("approve-action-act-70");
    await user.click(screen.getByTestId("approve-action-act-70"));
    const dialog = await screen.findByRole("dialog", { name: "批准动作" });
    await user.click(within(dialog).getByRole("button", { name: /批\s*准/ }));

    // 409 is reported, and the failed re-sync is not disguised as a success.
    expect(
      await screen.findByText(
        "该审批已由其他审批者处理，但页面刷新未完成，请手动刷新查看最新状态。",
      ),
    ).toBeInTheDocument();
    // Even with the refresh failed, the row must not offer a second approve
    // (locally marked decided on 409 — ISSUE-207 review).
    expect(screen.getByTestId("approval-decided-act-70")).toBeInTheDocument();
    expect(screen.queryByTestId("approve-action-act-70")).not.toBeInTheDocument();
    expect(screen.queryByTestId("reject-action-act-70")).not.toBeInTheDocument();
  });

  it("renders GET /report when snapshot only has report_generated", async () => {
    mockGetEvent.mockResolvedValue({
      data: makeDetail({
        status: "closed",
        event_context_snapshot: {
          ...makeDetail().event.event_context_snapshot,
          report_generated: true,
        },
      }),
    });
    mockGetReport.mockResolvedValue({
      data: { report: makeInvestigationReport() },
    });
    renderPage("/events/evt-70#report");
    expect(await screen.findByTestId("report-viewer")).toBeInTheDocument();
    expect(screen.getByText("内部泄露调查报告")).toBeInTheDocument();
    expect(screen.queryByText("报告尚未生成")).not.toBeInTheDocument();
  });

  it("polls pending memory reviews after close until candidates appear", async () => {
    mockGetEvent.mockResolvedValue({
      data: makeDetail({ status: "closed" }),
    });
    mockListMemoryReviews
      .mockResolvedValueOnce({ data: { total: 0, items: [] } })
      .mockResolvedValueOnce({ data: { total: 0, items: [] } })
      .mockResolvedValue({
        data: {
          total: 1,
          items: [
            {
              review_id: "rev-1",
              kb_name: "history_case_kb",
              candidate_type: "history_case",
              payload: { event_id: "evt-70" },
              status: "pending",
              confidence: 0.9,
              created_at: "2026-08-24T00:00:00Z",
            },
          ],
        },
      });
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    expect(screen.queryByText("待知识审核")).not.toBeInTheDocument();
    expect(await screen.findByText("待知识审核")).toBeInTheDocument();
  });

  // ---- ISSUE-206: on-demand report generation ---------------------------------

  it("generates a report from the empty-state CTA and refreshes", async () => {
    const user = userEvent.setup();
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "reporting" }) });
    renderPage("/events/evt-70#report");
    expect(await screen.findByText("报告尚未生成")).toBeInTheDocument();

    await user.click(screen.getByTestId("report-generate-button"));

    await waitFor(() => expect(mockGenerateReport).toHaveBeenCalledWith("evt-70", undefined));
    expect(await screen.findByText("报告已生成")).toBeInTheDocument();
    // Event snapshot is refreshed so the report tab updates without a reload.
    expect(mockGetEvent.mock.calls.length).toBeGreaterThan(1);
  });

  it("offers force-generate on 422 report_quality_incomplete", async () => {
    const user = userEvent.setup();
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "reporting" }) });
    mockGenerateReport.mockRejectedValueOnce(
      new ApiError({
        error_code: "report_quality_incomplete",
        error_message: "incomplete placeholder present",
      }),
    );
    renderPage("/events/evt-70#report");
    await screen.findByTestId("report-generate-button");

    await user.click(screen.getByTestId("report-generate-button"));
    expect(
      await screen.findByText("报告质量不完整：存在占位章节。可强制生成以存档降级件。"),
    ).toBeInTheDocument();

    const modal = await screen.findByTestId("report-quality-confirm-modal");
    await user.click(within(modal).getByRole("button", { name: /强制生成/ }));
    await waitFor(() =>
      expect(mockGenerateReport).toHaveBeenLastCalledWith("evt-70", { force: true }),
    );
  });

  it("confirms downgrade overwrite on 409 report_quality_conflict", async () => {
    const user = userEvent.setup();
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "reporting" }) });
    mockGenerateReport.mockRejectedValueOnce(
      new ApiError({
        error_code: "report_quality_conflict",
        error_message: "complete report exists",
      }),
    );
    renderPage("/events/evt-70#report");
    await screen.findByTestId("report-generate-button");

    await user.click(screen.getByTestId("report-generate-button"));
    expect(
      await screen.findByText("已有完整报告：覆盖为降级报告需确认降级。"),
    ).toBeInTheDocument();

    const modal = await screen.findByTestId("report-quality-confirm-modal");
    await user.click(within(modal).getByRole("button", { name: /确认覆盖/ }));
    await waitFor(() =>
      expect(mockGenerateReport).toHaveBeenLastCalledWith("evt-70", {
        confirm_downgrade: true,
      }),
    );
  });

  it("surfaces invalid_state_transition when report generation is too early", async () => {
    const user = userEvent.setup();
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "reporting" }) });
    mockGenerateReport.mockRejectedValueOnce(
      new ApiError({
        error_code: "invalid_state_transition",
        error_message: "report generation requires analysis to be complete",
      }),
    );
    renderPage("/events/evt-70#report");
    await screen.findByTestId("report-generate-button");

    await user.click(screen.getByTestId("report-generate-button"));

    expect(
      await screen.findByText("分析尚未完成，请待事件进入「报告生成」状态后再生成报告。"),
    ).toBeInTheDocument();
  });

  it("does not pretend a timed-out generation succeeded", async () => {
    const user = userEvent.setup();
    mockGetEvent.mockResolvedValue({ data: makeDetail({ status: "reporting" }) });
    mockGenerateReport.mockRejectedValueOnce(
      new ApiError({
        error_code: "llm_timeout",
        error_message: "LLM request timed out",
      }),
    );
    renderPage("/events/evt-70#report");
    await screen.findByTestId("report-generate-button");

    await user.click(screen.getByTestId("report-generate-button"));

    expect(
      await screen.findByText("报告生成超时：模型未写完，不会用模板充数。请稍后重试。"),
    ).toBeInTheDocument();
    expect(screen.getByText("报告尚未生成")).toBeInTheDocument();
  });

  it("warns when the report is generated but the follow-up refresh fails", async () => {
    const user = userEvent.setup();
    mockGetEvent
      .mockResolvedValueOnce({ data: makeDetail({ status: "reporting" }) }) // initial load
      .mockRejectedValueOnce(new Error("event 500")); // refresh after POST
    renderPage("/events/evt-70#report");
    await screen.findByTestId("report-generate-button");

    await user.click(screen.getByTestId("report-generate-button"));

    // The POST succeeded, but the re-sync failed — surfaced as a sync warning,
    // never as a plain success with stale UI.
    expect(await screen.findByText("报告已生成，但页面同步失败，请刷新查看最新状态。")).toBeInTheDocument();
    expect(mockGenerateReport).toHaveBeenCalledWith("evt-70", undefined);
  });
});
