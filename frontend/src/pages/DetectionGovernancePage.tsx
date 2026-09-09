/** Detection shadow governance page: artifacts, decisions, and promotion saga. */

import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Input,
  Modal,
  Popconfirm,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { ReloadOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";
import { useCallback, useEffect, useMemo, useState } from "react";
import { canDecideDetectionGovernance } from "../config/auth";
import { ApiError } from "../services/apiClient";
import {
  assessEligibility,
  createPromotion,
  evaluatePromotionGate,
  getEvaluationArtifactByPath,
  listDetectionCandidates,
  listGovernanceDecisions,
  listPromotions,
  recordDecisionFromPath,
  revokeGovernanceDecision,
} from "../services/detectionGovernanceApi";
import type {
  DetectionCandidate,
  DetectionEvaluationArtifact,
  DetectionGovernanceDecision,
  DetectionGovernanceEligibility,
  DetectionGovernancePromotionGate,
  DetectionPromotionRecord,
  DetectionPromotionStatus,
} from "../types/detectionGovernance";

export const DEFAULT_ARTIFACT_PATH = "detection_shadow_v1/baseline_artifact.json";
export const DEFAULT_THRESHOLD_MANIFEST_PATH =
  "detection_shadow_v1/threshold_manifest.json";

const SAGA_TAG_COLOR: Record<DetectionPromotionStatus, string> = {
  pending: "default",
  source_persisted: "processing",
  event_linked: "processing",
  completed: "success",
  retry: "warning",
  dead: "error",
  manual: "warning",
};

function isForbiddenError(err: unknown): boolean {
  return err instanceof ApiError && err.error_code === "forbidden";
}

function packageIdFrom(artifact: DetectionEvaluationArtifact | null): string | undefined {
  const packageId = artifact?.config?.candidate_refs?.package_id;
  return typeof packageId === "string" && packageId.trim() ? packageId : undefined;
}

function describeLoadFailure(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.details?.reason === "tenant_scope_denied") {
      return `当前账号租户无权访问制品租户 ${String(err.details.tenant_id ?? "")}。本地演示请改用 bootstrap-token（admin）。`;
    }
    return err.message || "加载失败";
  }
  return "请确认 confined 相对路径位于 data/evaluation 下。";
}

function formatRate(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) {
    return "—";
  }
  return `${Math.round(value * 100)}%`;
}

export default function DetectionGovernancePage() {
  const [artifactPath, setArtifactPath] = useState(DEFAULT_ARTIFACT_PATH);
  const [manifestPath, setManifestPath] = useState(DEFAULT_THRESHOLD_MANIFEST_PATH);
  const [loadedPath, setLoadedPath] = useState<string | null>(null);
  const [artifact, setArtifact] = useState<DetectionEvaluationArtifact | null>(null);
  const [tenantId, setTenantId] = useState("");
  const [eligibility, setEligibility] = useState<DetectionGovernanceEligibility | null>(
    null,
  );
  const [gate, setGate] = useState<DetectionGovernancePromotionGate | null>(null);
  const [decisions, setDecisions] = useState<DetectionGovernanceDecision[]>([]);
  const [candidates, setCandidates] = useState<DetectionCandidate[]>([]);
  const [promotions, setPromotions] = useState<DetectionPromotionRecord[]>([]);
  const [reasonNote, setReasonNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [relatedError, setRelatedError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [promotingId, setPromotingId] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<DetectionGovernanceDecision | null>(
    null,
  );
  const [revokeReason, setRevokeReason] = useState("");
  const [revokeSubmitting, setRevokeSubmitting] = useState(false);
  const [canDecide, setCanDecide] = useState(() => canDecideDetectionGovernance());

  const loadRelated = useCallback(
    async (tenant: string, packageId?: string) => {
      if (!tenant) {
        setDecisions([]);
        setCandidates([]);
        setPromotions([]);
        setRelatedError(null);
        return;
      }
      try {
        const [decisionRes, candidateRes, promotionRes] = await Promise.all([
          listGovernanceDecisions({ tenant_id: tenant }),
          listDetectionCandidates({ tenant_id: tenant, package_id: packageId }),
          listPromotions({ tenant_id: tenant }),
        ]);
        setDecisions(decisionRes.data.items);
        setCandidates(candidateRes.data.items);
        setPromotions(promotionRes.data.items);
        setRelatedError(null);
      } catch (err: unknown) {
        setDecisions([]);
        setCandidates([]);
        setPromotions([]);
        setRelatedError(describeLoadFailure(err));
      }
    },
    [],
  );

  const loadArtifact = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    setRelatedError(null);
    setEligibility(null);
    setGate(null);
    try {
      const response = await getEvaluationArtifactByPath(artifactPath.trim());
      const nextArtifact = response.data.artifact;
      setArtifact(nextArtifact);
      setLoadedPath(response.data.path);
      setTenantId(nextArtifact.tenant_id);
      await loadRelated(nextArtifact.tenant_id, packageIdFrom(nextArtifact));
    } catch (err: unknown) {
      setArtifact(null);
      setLoadedPath(null);
      setLoadError(describeLoadFailure(err));
    } finally {
      setLoading(false);
    }
  }, [artifactPath, loadRelated]);

  useEffect(() => {
    void loadArtifact();
  }, [loadArtifact]);

  const handleForbidden = useCallback((err: unknown): boolean => {
    if (!isForbiddenError(err)) {
      return false;
    }
    setCanDecide(false);
    message.error("当前账号无权操作影子治理，已隐藏写操作按钮");
    return true;
  }, []);

  const handleAssess = useCallback(async () => {
    if (!artifact) {
      return;
    }
    setActionBusy(true);
    try {
      const [eligibilityRes, gateRes] = await Promise.all([
        assessEligibility({
          artifact,
          threshold_manifest_path: manifestPath.trim() || undefined,
        }),
        evaluatePromotionGate({ artifact }),
      ]);
      setEligibility(eligibilityRes.data);
      setGate(gateRes.data);
    } catch (err: unknown) {
      if (!handleForbidden(err) && err instanceof ApiError) {
        message.error(err.message || err.error_code || "资格评估失败");
      } else if (!handleForbidden(err)) {
        message.error("资格评估失败");
      }
    } finally {
      setActionBusy(false);
    }
  }, [artifact, handleForbidden, manifestPath]);

  const handleDecide = useCallback(
    async (decision: "approve" | "reject") => {
      if (!loadedPath) {
        return;
      }
      if (decision === "approve" && !manifestPath.trim()) {
        message.error("批准必须填写 threshold_manifest_path");
        return;
      }
      setActionBusy(true);
      try {
        await recordDecisionFromPath({
          artifact_path: loadedPath,
          decision,
          reason_note: reasonNote,
          threshold_manifest_path:
            decision === "approve" ? manifestPath.trim() : undefined,
        });
        message.success(decision === "approve" ? "已批准" : "已驳回");
        if (tenantId) {
          await loadRelated(tenantId, packageIdFrom(artifact));
        }
      } catch (err: unknown) {
        if (!handleForbidden(err) && err instanceof ApiError) {
          message.error(err.message || err.error_code || "决策失败");
        } else if (!handleForbidden(err)) {
          message.error("决策失败");
        }
      } finally {
        setActionBusy(false);
      }
    },
    [
      artifact,
      handleForbidden,
      loadedPath,
      loadRelated,
      manifestPath,
      reasonNote,
      tenantId,
    ],
  );

  const handleRevoke = useCallback(async () => {
    if (!revokeTarget || !tenantId) {
      return;
    }
    if (!revokeReason.trim()) {
      message.error("撤销必须填写原因");
      return;
    }
    setRevokeSubmitting(true);
    try {
      await revokeGovernanceDecision(
        revokeTarget.decision_id,
        tenantId,
        revokeReason.trim(),
      );
      message.success("决策已撤销");
      setRevokeTarget(null);
      setRevokeReason("");
      await loadRelated(tenantId, packageIdFrom(artifact));
    } catch (err: unknown) {
      if (!handleForbidden(err) && err instanceof ApiError) {
        message.error(err.message || err.error_code || "撤销失败");
      } else if (!handleForbidden(err)) {
        message.error("撤销失败");
      }
    } finally {
      setRevokeSubmitting(false);
    }
  }, [artifact, handleForbidden, loadRelated, revokeReason, revokeTarget, tenantId]);

  const handlePromote = useCallback(
    async (candidateId: string) => {
      if (!loadedPath || !tenantId) {
        return;
      }
      setPromotingId(candidateId);
      try {
        const result = await createPromotion({
          tenant_id: tenantId,
          candidate_detection_id: candidateId,
          artifact_path: loadedPath,
        });
        const projectionError = result.data.context_projection_error;
        if (projectionError) {
          message.warning(`升进上下文投影失败：${projectionError.message || projectionError.reason}`);
        } else {
          message.success(`升进已提交（${result.data.status}）`);
        }
        await loadRelated(tenantId, packageIdFrom(artifact));
      } catch (err: unknown) {
        if (handleForbidden(err)) {
          return;
        }
        if (err instanceof ApiError) {
          const codes = err.details?.reason_codes;
          const extra = Array.isArray(codes) ? `：${codes.join(", ")}` : "";
          message.error((err.message || err.error_code || "升进失败") + extra);
        } else {
          message.error("升进失败");
        }
      } finally {
        setPromotingId(null);
      }
    },
    [artifact, handleForbidden, loadedPath, loadRelated, tenantId],
  );

  const decisionColumns: ColumnsType<DetectionGovernanceDecision> = useMemo(() => {
    const columns: ColumnsType<DetectionGovernanceDecision> = [
      { title: "决策 ID", dataIndex: "decision_id", key: "decision_id" },
      {
        title: "结论",
        dataIndex: "decision",
        key: "decision",
        render: (value: DetectionGovernanceDecision["decision"]) => (
          <Tag color={value === "approve" ? "success" : value === "reject" ? "error" : "default"}>
            {value}
          </Tag>
        ),
      },
      { title: "审批人", dataIndex: "reviewer_subject", key: "reviewer_subject" },
      { title: "时间", dataIndex: "decided_at", key: "decided_at" },
      { title: "备注", dataIndex: "reason_note", key: "reason_note" },
    ];
    if (canDecide) {
      columns.push({
        title: "操作",
        key: "actions",
        render: (_, record) =>
          record.decision === "approve" ? (
            <Button
              type="link"
              size="small"
              danger
              data-testid={`revoke-${record.decision_id}`}
              onClick={() => {
                setRevokeTarget(record);
                setRevokeReason("");
              }}
            >
              撤销
            </Button>
          ) : null,
      });
    }
    return columns;
  }, [canDecide]);

  const candidateColumns: ColumnsType<DetectionCandidate> = useMemo(() => {
    const columns: ColumnsType<DetectionCandidate> = [
      {
        title: "候选 ID",
        dataIndex: "candidate_detection_id",
        key: "candidate_detection_id",
      },
      { title: "规则", dataIndex: "rule_id", key: "rule_id" },
      { title: "包", dataIndex: "package_id", key: "package_id" },
      { title: "严重级别", dataIndex: "severity", key: "severity" },
      {
        title: "shadow",
        dataIndex: "shadow_only",
        key: "shadow_only",
        render: (value: boolean) => (value ? "是" : "否"),
      },
    ];
    if (canDecide) {
      columns.push({
        title: "操作",
        key: "actions",
        render: (_, record) => (
          <Popconfirm
            title="确认升进该影子候选？批准不等于升进，仍须过升进门禁。"
            okText="升进"
            cancelText="取消"
            onConfirm={() => void handlePromote(record.candidate_detection_id)}
          >
            <Button
              type="link"
              size="small"
              loading={promotingId === record.candidate_detection_id}
              data-testid={`promote-${record.candidate_detection_id}`}
            >
              升进
            </Button>
          </Popconfirm>
        ),
      });
    }
    return columns;
  }, [canDecide, handlePromote, promotingId]);

  const promotionColumns: ColumnsType<DetectionPromotionRecord> = [
    { title: "升进 ID", dataIndex: "promotion_id", key: "promotion_id" },
    {
      title: "Saga",
      dataIndex: "status",
      key: "status",
      render: (status: DetectionPromotionStatus, record) => (
        <Tag
          color={SAGA_TAG_COLOR[status] ?? "default"}
          data-testid={`promotion-status-${record.promotion_id}`}
        >
          {status}
        </Tag>
      ),
    },
    {
      title: "候选",
      dataIndex: "candidate_detection_id",
      key: "candidate_detection_id",
    },
    {
      title: "上下文投影",
      key: "context_projection_error",
      render: (_, record) => record.context_projection_error ? (
        <Typography.Text type="warning" data-testid={`projection-error-${record.promotion_id}`}>
          投影失败：{record.context_projection_error.message || record.context_projection_error.reason}
        </Typography.Text>
      ) : record.reason_codes.includes("context_projection_failed") ? (
        <Typography.Text type="warning">上下文投影失败，请重试</Typography.Text>
      ) : "—",
    },
    {
      title: "原因码",
      dataIndex: "reason_codes",
      key: "reason_codes",
      render: (codes: string[]) => (codes.length > 0 ? codes.join(", ") : "—"),
    },
    {
      title: "事件",
      dataIndex: "event_id",
      key: "event_id",
      render: (eventId: string | null | undefined, record) =>
        eventId ? (
          <Link
            to={`/events/${encodeURIComponent(eventId)}`}
            data-testid={`promotion-event-${record.promotion_id}`}
          >
            {eventId}
          </Link>
        ) : (
          "—"
        ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Typography.Title level={3} style={{ marginBottom: 4 }}>
          影子治理
        </Typography.Title>
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          加载评测制品、记录治理决策，并在门禁通过后升进影子候选。批准不等于升进。
        </Typography.Paragraph>
      </div>

      {!canDecide && (
        <Alert
          type="warning"
          showIcon
          message="当前账号仅可查看制品与决策，批准/驳回/升进需 approver 角色。"
        />
      )}

      {loadError && (
        <Alert
          type="error"
          showIcon
          message="制品加载失败"
          description={loadError}
          action={
            <Button data-testid="detection-governance-retry" onClick={() => void loadArtifact()}>
              重试
            </Button>
          }
        />
      )}

      {relatedError && !loadError && (
        <Alert
          type="warning"
          showIcon
          data-testid="related-load-error"
          message="决策/候选列表加载失败"
          description={relatedError}
        />
      )}

      <Card title="制品" size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Input
            aria-label="制品相对路径"
            value={artifactPath}
            onChange={(event) => setArtifactPath(event.target.value)}
            style={{ width: 420 }}
          />
          <Button
            type="primary"
            icon={<ReloadOutlined />}
            loading={loading}
            onClick={() => void loadArtifact()}
            data-testid="load-artifact"
          >
            加载
          </Button>
        </Space>
        {artifact ? (
          <Descriptions
            size="small"
            column={{ xs: 1, sm: 2, lg: 3 }}
            bordered
            data-testid="artifact-summary"
          >
            <Descriptions.Item label="路径">{loadedPath}</Descriptions.Item>
            <Descriptions.Item label="evaluation_id">
              {artifact.evaluation_id}
            </Descriptions.Item>
            <Descriptions.Item label="tenant_id">{artifact.tenant_id}</Descriptions.Item>
            <Descriptions.Item label="status">{artifact.status}</Descriptions.Item>
            <Descriptions.Item label="gate">
              {artifact.gate?.verdict ?? "—"}
            </Descriptions.Item>
            <Descriptions.Item label="pass_rate">
              {formatRate(artifact.aggregates?.pass_rate)}
            </Descriptions.Item>
            <Descriptions.Item label="case_count">
              {artifact.aggregates?.case_count ?? "—"}
            </Descriptions.Item>
            <Descriptions.Item label="reason_codes">
              {(artifact.gate?.reason_codes ?? []).join(", ") || "—"}
            </Descriptions.Item>
          </Descriptions>
        ) : (
          !loading && <Empty description="尚未加载制品" />
        )}
      </Card>

      <Card title="决策" size="small">
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <Input
            aria-label="threshold_manifest_path"
            value={manifestPath}
            onChange={(event) => setManifestPath(event.target.value)}
            placeholder="批准必填：threshold_manifest_path"
          />
          <Input.TextArea
            aria-label="决策备注"
            value={reasonNote}
            onChange={(event) => setReasonNote(event.target.value)}
            placeholder="决策备注（可选）"
            rows={2}
          />
          <Space wrap>
            <Button
              onClick={() => void handleAssess()}
              loading={actionBusy}
              disabled={!artifact}
              data-testid="assess-eligibility"
            >
              评估资格
            </Button>
            {canDecide && (
              <>
                <Button
                  type="primary"
                  onClick={() => void handleDecide("approve")}
                  loading={actionBusy}
                  disabled={!artifact}
                  data-testid="approve-decision"
                >
                  批准
                </Button>
                <Button
                  danger
                  onClick={() => void handleDecide("reject")}
                  loading={actionBusy}
                  disabled={!artifact}
                  data-testid="reject-decision"
                >
                  驳回
                </Button>
              </>
            )}
          </Space>
          {eligibility && (
            <Alert
              type={eligibility.eligible ? "success" : "warning"}
              showIcon
              data-testid="eligibility-result"
              message={eligibility.eligible ? "具备治理资格" : "资格未通过"}
              description={
                (eligibility.messages ?? []).join("；") ||
                (eligibility.reason_codes ?? []).join(", ") ||
                undefined
              }
            />
          )}
          {gate && (
            <Alert
              type={gate.allowed ? "success" : "info"}
              showIcon
              data-testid="promotion-gate-result"
              message={gate.allowed ? "升进门禁已打开" : "升进门禁关闭"}
              description={
                (gate.messages ?? []).join("；") ||
                (gate.reason_codes ?? []).join(", ") ||
                undefined
              }
            />
          )}
          <Table
            size="small"
            rowKey="decision_id"
            columns={decisionColumns}
            dataSource={decisions}
            pagination={false}
            locale={{ emptyText: "暂无治理决策" }}
          />
        </Space>
      </Card>

      <Card title="升进" size="small">
        <Typography.Paragraph type="secondary">
          仅列出该制品绑定租户下的 shadow 候选。升进须先有有效批准并过门禁。
        </Typography.Paragraph>
        <Table
          size="small"
          rowKey="candidate_detection_id"
          columns={candidateColumns}
          dataSource={candidates}
          pagination={false}
          locale={{ emptyText: "暂无影子候选" }}
          style={{ marginBottom: 16 }}
        />
        <Table
          size="small"
          rowKey="promotion_id"
          columns={promotionColumns}
          dataSource={promotions}
          pagination={false}
          locale={{ emptyText: "暂无升进 saga 记录" }}
        />
      </Card>

      <Modal
        title="撤销治理决策"
        open={revokeTarget != null}
        okText="确认撤销"
        cancelText="取消"
        confirmLoading={revokeSubmitting}
        onOk={() => void handleRevoke()}
        onCancel={() => {
          setRevokeTarget(null);
          setRevokeReason("");
        }}
      >
        <Typography.Paragraph>
          撤销 {revokeTarget?.decision_id}。撤销后升进门禁关闭。
        </Typography.Paragraph>
        <Input.TextArea
          aria-label="撤销原因"
          value={revokeReason}
          onChange={(event) => setRevokeReason(event.target.value)}
          rows={3}
        />
      </Modal>
    </Space>
  );
}
