import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import type { EventDetailResponse } from "../../src/types/event";

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
}));

let socketHandler: ((event: { type: string; event_id: string; payload: Record<string, unknown> }) => void) | undefined;
const mockSocketSubscribe = vi.fn();

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    subscribe: (eventId: string) => mockSocketSubscribe(eventId),
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

vi.mock("echarts-for-react", () => ({
  default: () => <div data-testid="risk-radar" />,
}));

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
  beforeEach(async () => {
    vi.clearAllMocks();
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
    ({ default: EventDetailPage } = await import("../../src/pages/EventDetailPage"));
  });

  it("renders overview, entities, six-dimensional risk and source capabilities", async () => {
    renderPage();
    expect(await screen.findByText("异常管理员登录")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("workstation-01")).toBeInTheDocument();
    expect(screen.getByTestId("risk-radar")).toBeInTheDocument();
    expect(screen.getByText(/资产影响/)).toBeInTheDocument();
    expect(screen.getByText("Mock XDR（online）")).toBeInTheDocument();
    expect(mockSocketSubscribe).toHaveBeenCalledWith("evt-70");
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
    socketHandler?.({ type: "risk_updated", event_id: "evt-70", payload: {} });
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
      },
    });

    renderPage("/events/evt-70#actions");
    expect(await screen.findByText("待效果验证后激活")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /外部写回/ }));
    expect(await screen.findByTestId("simulated-receipt-warning")).toBeInTheDocument();
    expect(screen.getByText(/终态 EVENT_STATUS_UPDATE/)).toBeInTheDocument();
    expect(screen.getByTestId("writeback-row-wb-70")).toHaveStyle({
      background: "rgba(82, 196, 26, 0.10)",
    });
  });

  it("shows POST_VERIFY label after deferred action enters execution", async () => {
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
    expect(await screen.findByText("POST_VERIFY")).toBeInTheDocument();
    expect(screen.queryByText("待效果验证后激活")).not.toBeInTheDocument();
  });
});
