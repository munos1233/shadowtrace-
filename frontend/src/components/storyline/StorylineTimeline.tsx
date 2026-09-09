import { Alert, Button, Card, Skeleton, Space, Tag, Typography } from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import EvidenceList from "../event/EvidenceList";
import { getTimeline } from "../../services/eventApi";
import { ApiError } from "../../services/apiClient";
import type {
  AttackStoryline,
  Evidence,
  EvidenceConflict,
  StorylinePhase,
  StorylinePhaseName,
} from "../../types/event";
import PhaseSection from "./PhaseSection";

const PHASE_ORDER: StorylinePhaseName[] = [
  "initial_access",
  "collection",
  "staging",
  "exfiltration",
  "post_action",
];

type LoadState = "idle" | "loading" | "ready" | "not_ready" | "error";

function isStorylineNotReady(error: unknown): boolean {
  if (error instanceof ApiError && error.error_code === "storyline_not_ready") {
    return true;
  }
  if (!error || typeof error !== "object") return false;
  const response = (error as { response?: { status?: number; data?: unknown } })
    .response;
  if (response?.status !== 404) return false;
  const data = response.data;
  return (
    typeof data === "object" &&
    data !== null &&
    "error_code" in data &&
    (data as { error_code?: unknown }).error_code === "storyline_not_ready"
  );
}

function buildPhases(
  storyline: AttackStoryline,
): Array<StorylinePhase & { isPlaceholder: boolean }> {
  const byName = new Map(
    storyline.phases.map((phase) => [phase.phase_name, phase]),
  );
  return PHASE_ORDER.map((phaseName, index) => {
    const existing = byName.get(phaseName);
    if (existing) {
      return { ...existing, isPlaceholder: false };
    }
    return {
      phase_order: index + 1,
      phase_name: phaseName,
      tactic: null,
      narrative: "",
      entries: [],
      isPlaceholder: true,
    };
  });
}

function timestampValue(value: string | null): number {
  if (!value) return Number.POSITIVE_INFINITY;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
}

export default function StorylineTimeline({
  eventId,
  evidence = [],
  conflicts = [],
  storyline: controlledStoryline,
  refreshToken,
}: {
  eventId?: string;
  evidence?: Evidence[];
  conflicts?: EvidenceConflict[];
  storyline?: AttackStoryline | null;
  refreshToken?: string | null;
}) {
  const controlled = controlledStoryline !== undefined;
  const [storyline, setStoryline] = useState<AttackStoryline | null>(
    controlledStoryline ?? null,
  );
  const [loadState, setLoadState] = useState<LoadState>(
    controlled ? (controlledStoryline ? "ready" : "not_ready") : "idle",
  );
  const storylineRef = useRef(storyline);
  storylineRef.current = storyline;

  const load = useCallback(async () => {
    if (controlled) {
      setStoryline(controlledStoryline ?? null);
      setLoadState(controlledStoryline ? "ready" : "not_ready");
      return;
    }
    if (!eventId) {
      setLoadState("not_ready");
      return;
    }
    const hadStoryline = storylineRef.current != null;
    if (!hadStoryline) setLoadState("loading");
    try {
      const response = await getTimeline(eventId);
      setStoryline(response.data);
      setLoadState("ready");
    } catch (error) {
      const notReady = isStorylineNotReady(error);
      if (hadStoryline && !notReady) {
        setLoadState("ready");
      } else {
        setStoryline(null);
        setLoadState(notReady ? "not_ready" : "error");
      }
    }
  }, [controlled, controlledStoryline, eventId, refreshToken]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const evidenceById = useMemo(
    () => new Map(evidence.map((item) => [item.evidence_id, item])),
    [evidence],
  );
  const fallbackEvidence = useMemo(
    () =>
      [...evidence].sort(
        (left, right) =>
          timestampValue(left.timestamp) - timestampValue(right.timestamp),
      ),
    [evidence],
  );

  if (loadState === "idle" || loadState === "loading") {
    return (
      <div data-testid="storyline-timeline-loading">
        <Skeleton active paragraph={{ rows: 8 }} />
      </div>
    );
  }

  if (loadState === "error") {
    return (
      <div data-testid="storyline-timeline-error">
        <Alert
          type="error"
          showIcon
          message="攻击故事线加载失败"
          description="请检查网络连接后重试。"
          action={<Button onClick={() => void load()}>重试</Button>}
        />
      </div>
    );
  }

  if (!storyline) {
    return (
      <Space
        direction="vertical"
        size={16}
        style={{ width: "100%" }}
        data-testid="storyline-timeline-fallback"
      >
        <Alert
          type="info"
          showIcon
          message="故事线未生成"
          description="当前按时间顺序展示已收集证据，故事线生成后将自动切换为分阶段视图。"
        />
        <EvidenceList evidence={fallbackEvidence} conflicts={conflicts} />
      </Space>
    );
  }

  const phases = buildPhases(storyline);

  return (
    <Space
      direction="vertical"
      size={16}
      style={{ width: "100%" }}
      data-testid="storyline-timeline"
    >
      <Card size="small">
        <Space direction="vertical" size={8} style={{ width: "100%" }}>
          <Space wrap>
            <Typography.Title level={4} style={{ margin: 0 }}>
              攻击故事线
            </Typography.Title>
            <Tag color={storyline.generated_by === "rule" ? "blue" : "purple"}>
              {storyline.generated_by === "rule" ? "规则生成" : "AI 生成"}
            </Tag>
          </Space>
          <Typography.Paragraph style={{ margin: 0 }}>
            {storyline.narrative_summary}
          </Typography.Paragraph>
        </Space>
      </Card>
      {phases.map((phase) => (
        <PhaseSection
          key={phase.phase_name}
          phase={phase}
          evidenceById={evidenceById}
          isPlaceholder={phase.isPlaceholder}
        />
      ))}
    </Space>
  );
}
