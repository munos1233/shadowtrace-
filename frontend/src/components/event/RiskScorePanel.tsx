import { Card, Empty, Space, Tag, Tooltip, Typography } from "antd";
import ReactECharts from "echarts-for-react";
import type { RiskAssessment, RiskFactor } from "../../types/event";

// eslint-disable-next-line react-refresh/only-export-components
export const RISK_FACTOR_LABELS: Record<string, string> = {
  asset_impact: "资产影响",
  behavior_anomaly: "行为异常",
  evidence_confidence: "证据置信",
  attack_stage: "攻击阶段",
  data_sensitivity: "数据敏感度",
  threat_intel: "威胁情报",
};

const FACTOR_ORDER = Object.keys(RISK_FACTOR_LABELS);

function normalizeFactors(assessment: RiskAssessment): RiskFactor[] {
  const byName = new Map(
    assessment.risk_factors.map((factor) => [factor.factor_name, factor]),
  );
  return FACTOR_ORDER.map(
    (factorName) =>
      byName.get(factorName) ?? {
        factor_name: factorName,
        weight: 0,
        raw_score: 0,
        weighted_score: 0,
        reasoning: "暂无数据",
      },
  );
}

export default function RiskScorePanel({
  assessment,
  fallbackScore,
}: {
  assessment?: RiskAssessment | null;
  fallbackScore?: number;
}) {
  if (!assessment) {
    return (
      <Card title={`六维风险${fallbackScore === undefined ? "" : ` · ${fallbackScore}`}`} style={{ height: "100%" }}>
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
      </Card>
    );
  }

  const factors = normalizeFactors(assessment);
  const option = {
    animation: false,
    tooltip: { trigger: "item", confine: true },
    radar: {
      radius: "62%",
      indicator: factors.map((factor) => ({
        name: RISK_FACTOR_LABELS[factor.factor_name] ?? factor.factor_name,
        max: 100,
      })),
      splitNumber: 4,
    },
    series: [
      {
        type: "radar",
        data: [
          {
            name: "风险评分",
            value: factors.map((factor) => Math.max(0, Math.min(100, factor.raw_score))),
            areaStyle: { color: "rgba(22,119,255,.22)" },
            lineStyle: { color: "#1677ff" },
          },
        ],
      },
    ],
  };

  return (
    <Card
      title={`六维风险 · ${assessment.risk_score}`}
      data-testid="risk-score-panel"
      style={{ height: "100%" }}
    >
      <ReactECharts option={option} style={{ height: 260 }} />
      <Space wrap>
        {factors.map((factor) => (
          <Tooltip key={factor.factor_name} title={factor.reasoning || "暂无数据"}>
            <Tag>
              {RISK_FACTOR_LABELS[factor.factor_name] ?? factor.factor_name}{" "}
              <Typography.Text strong>{Math.round(factor.raw_score)}</Typography.Text>
            </Tag>
          </Tooltip>
        ))}
      </Space>
    </Card>
  );
}
