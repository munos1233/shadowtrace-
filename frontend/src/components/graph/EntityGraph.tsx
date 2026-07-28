import { Alert, Button, Card, Empty, Skeleton, Space, Tag, Typography } from "antd";
import ReactECharts from "echarts-for-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getGraph } from "../../services/eventApi";
import type {
  GraphEdge,
  GraphEntityType,
  GraphOutput,
} from "../../types/event";
import AttackPathPlayer from "./AttackPathPlayer";
import {
  ENTITY_COLORS,
  ENTITY_LABELS,
  ENTITY_TYPES,
  RELATION_LABELS,
} from "./constants";
import GraphLegend from "./GraphLegend";

type LoadState = "idle" | "loading" | "ready" | "error";

interface ChartClickParams {
  dataType?: string;
  data?: {
    edgeId?: string;
  };
}

interface TooltipParams {
  dataType?: string;
  data?: Record<string, unknown>;
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function tooltipFormatter(params: TooltipParams): string {
  const data = params.data ?? {};
  if (params.dataType === "edge") {
    return [
      `<strong>${escapeHtml(data.relationLabel)}</strong>`,
      `证据 ID：${escapeHtml(data.evidenceId)}`,
      data.occurredAt ? `时间：${escapeHtml(data.occurredAt)}` : "",
    ]
      .filter(Boolean)
      .join("<br/>");
  }
  const properties =
    data.properties && typeof data.properties === "object"
      ? JSON.stringify(data.properties, null, 2)
      : "{}";
  return [
    `<strong>${escapeHtml(data.name)}</strong>`,
    `类型：${escapeHtml(data.entityLabel)}`,
    `<pre style="margin:4px 0 0">${escapeHtml(properties)}</pre>`,
  ].join("<br/>");
}

function edgeKey(source: string, target: string): string {
  return `${source}\u0000${target}`;
}

export default function EntityGraph({
  eventId,
  graph: controlledGraph,
  refreshToken,
}: {
  eventId?: string;
  graph?: GraphOutput | null;
  refreshToken?: string | null;
}) {
  const controlled = controlledGraph !== undefined;
  const [graph, setGraph] = useState<GraphOutput | null>(
    controlledGraph ?? null,
  );
  const [loadState, setLoadState] = useState<LoadState>(
    controlled ? "ready" : "idle",
  );
  const [visibleTypes, setVisibleTypes] = useState<Set<GraphEntityType>>(
    () => new Set(ENTITY_TYPES),
  );
  const [activePathNodeIds, setActivePathNodeIds] = useState<string[]>([]);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  const load = useCallback(async () => {
    if (controlled) {
      setGraph(controlledGraph ?? null);
      setLoadState("ready");
      return;
    }
    if (!eventId) {
      setGraph(null);
      setLoadState("ready");
      return;
    }
    setLoadState("loading");
    try {
      const response = await getGraph(eventId);
      setGraph(response.data);
      setLoadState("ready");
    } catch {
      setGraph(null);
      setLoadState("error");
    }
  }, [controlled, controlledGraph, eventId]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const handlePathProgress = useCallback((nodeIds: string[]) => {
    setActivePathNodeIds(nodeIds);
  }, []);

  const activeNodeIds = useMemo(
    () => new Set(activePathNodeIds),
    [activePathNodeIds],
  );
  const activeEdgeKeys = useMemo(() => {
    const keys = new Set<string>();
    for (let index = 1; index < activePathNodeIds.length; index += 1) {
      keys.add(
        edgeKey(activePathNodeIds[index - 1], activePathNodeIds[index]),
      );
    }
    return keys;
  }, [activePathNodeIds]);

  const chart = useMemo(() => {
    if (!graph) {
      return { option: null, filteredNodeCount: 0, filteredEdgeCount: 0 };
    }
    const filteredNodes = graph.nodes.filter((node) =>
      visibleTypes.has(node.entity_type),
    );
    const visibleNodeIds = new Set(filteredNodes.map((node) => node.node_id));
    const filteredEdges = graph.edges.filter(
      (edge) =>
        visibleNodeIds.has(edge.source_node_id) &&
        visibleNodeIds.has(edge.target_node_id),
    );
    const centralEntities = new Set(graph.central_entities);
    const staticLayout = filteredNodes.length > 200;
    const radius = Math.max(260, filteredNodes.length * 3);
    const nodes = filteredNodes.map((node, index) => {
      const central =
        centralEntities.has(node.node_id) ||
        centralEntities.has(node.entity_value);
      const active = activeNodeIds.has(node.node_id);
      const angle =
        filteredNodes.length > 0
          ? (Math.PI * 2 * index) / filteredNodes.length
          : 0;
      return {
        id: node.node_id,
        name: node.entity_value,
        value: node.entity_value,
        entityType: node.entity_type,
        entityLabel: ENTITY_LABELS[node.entity_type],
        properties: node.properties,
        category: ENTITY_TYPES.indexOf(node.entity_type),
        symbolSize: central ? 42 : 28,
        ...(staticLayout
          ? {
              x: Math.cos(angle) * radius,
              y: Math.sin(angle) * radius,
            }
          : {}),
        itemStyle: {
          color: ENTITY_COLORS[node.entity_type],
          borderColor: active ? "#ff4d4f" : central ? "#10239e" : "#ffffff",
          borderWidth: active ? 4 : central ? 3 : 1,
          shadowBlur: active ? 14 : central ? 8 : 0,
          shadowColor: active
            ? "rgba(255,77,79,.55)"
            : "rgba(16,35,158,.35)",
        },
      };
    });
    const links = filteredEdges.map((edge) => {
      const active = activeEdgeKeys.has(
        edgeKey(edge.source_node_id, edge.target_node_id),
      );
      return {
        source: edge.source_node_id,
        target: edge.target_node_id,
        edgeId: edge.edge_id,
        relationType: edge.relation_type,
        relationLabel: RELATION_LABELS[edge.relation_type],
        evidenceId: edge.evidence_id,
        occurredAt: edge.occurred_at,
        lineStyle: {
          color: active ? "#ff4d4f" : "#8c8c8c",
          width: active ? 4 : 1.5,
          opacity: active ? 1 : 0.72,
          curveness: 0.08,
        },
      };
    });
    return {
      filteredNodeCount: filteredNodes.length,
      filteredEdgeCount: filteredEdges.length,
      option: {
        animation: !staticLayout,
        tooltip: {
          trigger: "item",
          confine: true,
          formatter: tooltipFormatter,
        },
        legend: { show: false },
        series: [
          {
            type: "graph",
            layout: staticLayout ? "none" : "force",
            roam: true,
            draggable: true,
            data: nodes,
            links,
            categories: ENTITY_TYPES.map((entityType) => ({
              name: ENTITY_LABELS[entityType],
              itemStyle: { color: ENTITY_COLORS[entityType] },
            })),
            force: staticLayout
              ? undefined
              : {
                  repulsion: 180,
                  edgeLength: [90, 170],
                  gravity: 0.08,
                },
            label: {
              show: true,
              position: "right",
              formatter: "{b}",
            },
            edgeLabel: {
              show: true,
              formatter: (params: { data?: { relationLabel?: string } }) =>
                params.data?.relationLabel ?? "",
              color: "#595959",
              fontSize: 11,
            },
            emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
          },
        ],
      },
    };
  }, [activeEdgeKeys, activeNodeIds, graph, visibleTypes]);

  if (loadState === "idle" || loadState === "loading") {
    return <Skeleton active paragraph={{ rows: 12 }} />;
  }

  if (loadState === "error") {
    return (
      <Alert
        type="error"
        showIcon
        message="攻击图谱加载失败"
        description="请检查网络连接后重试。"
        action={<Button onClick={() => void load()}>重试</Button>}
      />
    );
  }

  if (!graph || graph.nodes.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="图谱未生成"
      />
    );
  }

  const staticLayout = chart.filteredNodeCount > 200;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card size="small">
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <Space wrap>
            <Typography.Title level={4} style={{ margin: 0 }}>
              实体关系图
            </Typography.Title>
            <Tag color="blue">{chart.filteredNodeCount} 个节点</Tag>
            <Tag>{chart.filteredEdgeCount} 条关系</Tag>
          </Space>
          <GraphLegend
            visibleTypes={visibleTypes}
            onToggle={(entityType) => {
              setVisibleTypes((current) => {
                const next = new Set(current);
                if (next.has(entityType)) next.delete(entityType);
                else next.add(entityType);
                return next;
              });
              setSelectedEdge(null);
            }}
          />
          <AttackPathPlayer
            candidates={graph.attack_path_candidates}
            nodes={graph.nodes}
            onProgress={handlePathProgress}
          />
          {staticLayout && (
            <Alert
              type="info"
              showIcon
              message="大规模图谱已切换为静态布局"
              description="当前可见节点超过 200 个，已关闭力导向动画以保证交互性能。"
            />
          )}
        </Space>
      </Card>
      <Card size="small" styles={{ body: { padding: 0 } }}>
        {chart.option && (
          <ReactECharts
            option={chart.option}
            notMerge
            lazyUpdate
            style={{ height: 600, width: "100%" }}
            onEvents={{
              click: (params: ChartClickParams) => {
                if (params.dataType !== "edge" || !params.data?.edgeId) return;
                setSelectedEdge(
                  graph.edges.find(
                    (edge) => edge.edge_id === params.data?.edgeId,
                  ) ?? null,
                );
              },
            }}
          />
        )}
      </Card>
      {selectedEdge && (
        <Alert
          type="info"
          showIcon
          data-testid="graph-edge-evidence"
          message={`关联证据 ${selectedEdge.evidence_id}`}
          description={
            <Space wrap>
              <Tag>{RELATION_LABELS[selectedEdge.relation_type]}</Tag>
              <Typography.Text>
                {selectedEdge.occurred_at ?? "时间未知"}
              </Typography.Text>
            </Space>
          }
        />
      )}
    </Space>
  );
}
