import { CaretRightOutlined, ReloadOutlined } from "@ant-design/icons";
import { Button, Select, Space, Tag, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import type { GraphNode } from "../../types/event";

export default function AttackPathPlayer({
  candidates,
  nodes,
  onProgress,
}: {
  candidates: string[][];
  nodes: GraphNode[];
  onProgress: (activeNodeIds: string[]) => void;
}) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [currentStep, setCurrentStep] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const selectedPath = useMemo(
    () => candidates[selectedIndex] ?? [],
    [candidates, selectedIndex],
  );
  const labelsById = useMemo(
    () => new Map(nodes.map((node) => [node.node_id, node.entity_value])),
    [nodes],
  );

  useEffect(() => {
    if (selectedIndex >= candidates.length) {
      setSelectedIndex(0);
    }
    setCurrentStep(-1);
    setPlaying(false);
  }, [candidates, selectedIndex]);

  useEffect(() => {
    const activeNodeIds =
      currentStep >= 0 ? selectedPath.slice(0, currentStep + 1) : [];
    onProgress(activeNodeIds);
  }, [currentStep, onProgress, selectedPath]);

  useEffect(() => {
    if (!playing) return;
    if (currentStep >= selectedPath.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => {
      setCurrentStep((step) => step + 1);
    }, 500);
    return () => window.clearTimeout(timer);
  }, [currentStep, playing, selectedPath.length]);

  if (candidates.length === 0) {
    return (
      <Typography.Text type="secondary">暂无攻击路径候选</Typography.Text>
    );
  }

  const currentNodeId =
    currentStep >= 0 ? (selectedPath[currentStep] ?? null) : null;

  return (
    <Space wrap>
      <Typography.Text strong>攻击路径</Typography.Text>
      <Select
        aria-label="选择攻击路径"
        value={selectedIndex}
        onChange={(value) => {
          setSelectedIndex(value);
          setCurrentStep(-1);
          setPlaying(false);
        }}
        options={candidates.map((path, index) => ({
          value: index,
          label: `候选 ${index + 1}（${path.length} 个节点）`,
        }))}
        style={{ minWidth: 190 }}
      />
      <Button
        type="primary"
        icon={currentStep >= 0 ? <ReloadOutlined /> : <CaretRightOutlined />}
        aria-label={currentStep >= 0 ? "重新播放" : "播放路径"}
        disabled={selectedPath.length === 0 || playing}
        onClick={() => {
          setCurrentStep(0);
          setPlaying(selectedPath.length > 1);
        }}
      >
        {currentStep >= 0 ? "重新播放" : "播放路径"}
      </Button>
      <Tag
        color={playing ? "processing" : currentStep >= 0 ? "success" : "default"}
        data-testid="attack-path-step"
        data-current-node={currentNodeId ?? ""}
        aria-live="polite"
      >
        {currentNodeId
          ? `${currentStep + 1}/${selectedPath.length} · ${
              labelsById.get(currentNodeId) ?? currentNodeId
            }`
          : "等待播放"}
      </Tag>
    </Space>
  );
}
