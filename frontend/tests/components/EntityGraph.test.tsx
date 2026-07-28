import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import EntityGraph from "../../src/components/graph/EntityGraph";
import type {
  GraphEntityType,
  GraphOutput,
  GraphRelationType,
} from "../../src/types/event";

interface MockChartNode {
  id: string;
  name: string;
  symbolSize: number;
  itemStyle: { borderWidth: number };
}

interface MockChartEdge {
  edgeId: string;
  relationLabel: string;
  lineStyle?: { width?: number; color?: string };
}

interface MockChartOption {
  animation: boolean;
  series: Array<{
    layout: string;
    data: MockChartNode[];
    links: MockChartEdge[];
  }>;
}

vi.mock("echarts-for-react", () => ({
  default: ({
    option,
    onEvents,
  }: {
    option: MockChartOption;
    onEvents?: {
      click?: (params: {
        dataType: string;
        data: MockChartEdge;
      }) => void;
    };
  }) => {
    const series = option.series[0];
    return (
      <div
        data-testid="entity-graph-chart"
        data-node-count={series.data.length}
        data-edge-count={series.links.length}
        data-layout={series.layout}
        data-animation={String(option.animation)}
      >
        {series.data.map((node) => (
          <span
            key={node.id}
            data-testid={`mock-node-${node.id}`}
            data-symbol-size={node.symbolSize}
            data-border-width={node.itemStyle.borderWidth}
          >
            {node.name}
          </span>
        ))}
        {series.links.map((edge) => (
          <button
            key={edge.edgeId}
            type="button"
            data-testid={`mock-edge-${edge.edgeId}`}
            data-line-width={edge.lineStyle?.width ?? 0}
            onClick={() =>
              onEvents?.click?.({ dataType: "edge", data: edge })
            }
          >
            {edge.relationLabel}
          </button>
        ))}
      </div>
    );
  },
}));

const NODE_SPECS: Array<[string, GraphEntityType, string]> = [
  ["node-account", "account", "alice"],
  ["node-host", "host", "workstation-01"],
  ["node-ip", "ip", "203.0.113.8"],
  ["node-domain", "domain", "files.example.test"],
  ["node-process", "process", "powershell.exe"],
  ["node-file", "file", "archive.zip"],
];

const EDGE_SPECS: Array<
  [string, string, string, GraphRelationType, string]
> = [
  ["edge-1", "node-account", "node-ip", "logged_in_from", "ev-1"],
  ["edge-2", "node-account", "node-host", "logged_in_to", "ev-2"],
  ["edge-3", "node-account", "node-process", "executed", "ev-3"],
  ["edge-4", "node-process", "node-file", "accessed", "ev-4"],
  ["edge-5", "node-host", "node-ip", "connected_to", "ev-5"],
  ["edge-6", "node-domain", "node-ip", "resolved", "ev-6"],
  ["edge-7", "node-process", "node-domain", "requested", "ev-7"],
  ["edge-8", "node-file", "node-domain", "uploaded_to", "ev-8"],
];

function makeGraph(): GraphOutput {
  return {
    nodes: NODE_SPECS.map(([nodeId, entityType, entityValue]) => ({
      node_id: nodeId,
      event_id: "evt-071",
      entity_type: entityType,
      entity_value: entityValue,
      properties: { source: "test", entity_type: entityType },
    })),
    edges: EDGE_SPECS.map(
      ([edgeId, source, target, relationType, evidenceId], index) => ({
        edge_id: edgeId,
        event_id: "evt-071",
        source_node_id: source,
        target_node_id: target,
        relation_type: relationType,
        evidence_id: evidenceId,
        occurred_at: `2026-07-28T01:00:0${index}Z`,
      }),
    ),
    central_entities: ["alice"],
    attack_path_candidates: [
      ["node-account", "node-host", "node-ip"],
      [
        "node-account",
        "node-process",
        "node-file",
        "node-domain",
        "node-ip",
      ],
    ],
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("EntityGraph", () => {
  it("renders six entity types, eight labeled edges and highlights the center", () => {
    render(<EntityGraph graph={makeGraph()} />);

    const chart = screen.getByTestId("entity-graph-chart");
    expect(chart).toHaveAttribute("data-node-count", "6");
    expect(chart).toHaveAttribute("data-edge-count", "8");
    expect(chart).toHaveAttribute("data-layout", "force");
    expect(screen.getAllByTestId(/^mock-edge-/)).toHaveLength(8);

    const central = screen.getByTestId("mock-node-node-account");
    const regular = screen.getByTestId("mock-node-node-host");
    expect(central).toHaveAttribute("data-symbol-size", "42");
    expect(central).toHaveAttribute("data-border-width", "3");
    expect(regular).toHaveAttribute("data-symbol-size", "28");
  });

  it("filters nodes by entity type and removes disconnected edges", async () => {
    const user = userEvent.setup();
    render(<EntityGraph graph={makeGraph()} />);

    await user.click(screen.getByTestId("graph-filter-account"));

    const chart = screen.getByTestId("entity-graph-chart");
    expect(chart).toHaveAttribute("data-node-count", "5");
    expect(Number(chart.getAttribute("data-edge-count"))).toBeLessThan(8);
    expect(
      screen.queryByTestId("mock-node-node-account"),
    ).not.toBeInTheDocument();
  });

  it("shows the associated evidence id when an edge is clicked", async () => {
    const user = userEvent.setup();
    render(<EntityGraph graph={makeGraph()} />);

    await user.click(screen.getByTestId("mock-edge-edge-8"));

    const evidence = screen.getByTestId("graph-edge-evidence");
    expect(within(evidence).getByText("关联证据 ev-8")).toBeInTheDocument();
    expect(within(evidence).getByText("上传到")).toBeInTheDocument();
  });

  it("plays an attack path in node order at 500ms intervals", async () => {
    vi.useFakeTimers();
    render(<EntityGraph graph={makeGraph()} />);

    fireEvent.click(screen.getByRole("button", { name: "播放路径" }));
    expect(screen.getByTestId("attack-path-step")).toHaveAttribute(
      "data-current-node",
      "node-account",
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.getByTestId("attack-path-step")).toHaveAttribute(
      "data-current-node",
      "node-host",
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.getByTestId("attack-path-step")).toHaveAttribute(
      "data-current-node",
      "node-ip",
    );
    expect(screen.getByTestId("mock-node-node-ip")).toHaveAttribute(
      "data-border-width",
      "4",
    );
    expect(screen.getByTestId("mock-edge-edge-5")).toHaveAttribute(
      "data-line-width",
      "4",
    );
  });

  it("uses a non-animated static layout above 200 visible nodes", () => {
    const graph = makeGraph();
    graph.nodes = Array.from({ length: 201 }, (_, index) => ({
      node_id: `node-${index}`,
      event_id: "evt-large",
      entity_type: "ip" as const,
      entity_value: `203.0.113.${index}`,
      properties: {},
    }));
    graph.edges = [];
    graph.central_entities = [];
    graph.attack_path_candidates = [];

    render(<EntityGraph graph={graph} />);

    expect(screen.getByTestId("entity-graph-chart")).toHaveAttribute(
      "data-layout",
      "none",
    );
    expect(screen.getByTestId("entity-graph-chart")).toHaveAttribute(
      "data-animation",
      "false",
    );
    expect(
      screen.getByText("大规模图谱已切换为静态布局"),
    ).toBeInTheDocument();
  });

  it("shows the graph-not-generated placeholder for an empty graph", () => {
    render(
      <EntityGraph
        graph={{
          nodes: [],
          edges: [],
          central_entities: [],
          attack_path_candidates: [],
        }}
      />,
    );

    expect(screen.getByText("图谱未生成")).toBeInTheDocument();
  });
});
