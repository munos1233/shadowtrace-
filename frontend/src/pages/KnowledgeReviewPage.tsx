/** Knowledge memory review queue (ISSUE-213). */

import {
  Alert,
  Button,
  Card,
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
import { Link, useSearchParams } from "react-router-dom";
import { ReloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useMemo, useState } from "react";
import { canPromoteKnowledgeReviews } from "../config/auth";
import {
  listMemoryReviews,
  promoteMemoryReview,
  rejectMemoryReview,
} from "../services/knowledgeApi";
import { ApiError } from "../services/apiClient";
import type {
  MemoryReviewCandidateType,
  MemoryReviewItem,
} from "../types/knowledge";

const CANDIDATE_TYPE_LABELS: Record<MemoryReviewCandidateType, string> = {
  profile: "实体画像",
  fp_rule: "误报规则",
  history_case: "历史案例",
};

const CANDIDATE_TYPE_COLORS: Record<MemoryReviewCandidateType, string> = {
  profile: "blue",
  fp_rule: "gold",
  history_case: "purple",
};

const EXPECTED_TIMING_NOTE =
  "结案（CLOSED）前通常仅见 profile 待审核（依赖 ISSUE-208 画像入队）；" +
  "fp_rule / history_case 须在事件 CLOSED 后由 MemoryAgent 入队。";

function readSourceEventId(item: MemoryReviewItem): string | null {
  const payload = item.payload;
  const keys = ["source_event_id", "event_id"] as const;
  for (const key of keys) {
    const value = payload[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function readSummary(item: MemoryReviewItem): string {
  const payload = item.payload;
  switch (item.candidate_type) {
    case "fp_rule":
      return (
        (typeof payload.rule_summary === "string" && payload.rule_summary) ||
        (typeof payload.alert_signature === "string" && payload.alert_signature) ||
        "—"
      );
    case "history_case":
      return (typeof payload.summary === "string" && payload.summary) || "—";
    case "profile": {
      const entityType =
        typeof payload.entity_type === "string" ? payload.entity_type : "?";
      const entityValue =
        typeof payload.entity_value === "string" ? payload.entity_value : "?";
      const tags = Array.isArray(payload.behavior_tags)
        ? payload.behavior_tags.filter((tag): tag is string => typeof tag === "string")
        : [];
      const tagHint = tags.length > 0 ? ` · ${tags.slice(0, 3).join(", ")}` : "";
      return `${entityType}:${entityValue}${tagHint}`;
    }
    default:
      return "—";
  }
}

function formatConfidence(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function isForbiddenError(err: unknown): boolean {
  return err instanceof ApiError && err.error_code === "forbidden";
}

export default function KnowledgeReviewPage() {
  const [searchParams] = useSearchParams();
  const eventIdFilter = searchParams.get("event_id")?.trim() || undefined;
  const [items, setItems] = useState<MemoryReviewItem[]>([]);
  const [total, setTotal] = useState(0);
  const [kbFilterInput, setKbFilterInput] = useState("");
  const [kbFilter, setKbFilter] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [actionReviewId, setActionReviewId] = useState<string | null>(null);
  const [rejectTarget, setRejectTarget] = useState<MemoryReviewItem | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [rejectSubmitting, setRejectSubmitting] = useState(false);
  // Start from env/token role hints; revoke if API returns forbidden (token/roles drift).
  const [canDecide, setCanDecide] = useState(() => canPromoteKnowledgeReviews());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await listMemoryReviews({
        kb_name: kbFilter || undefined,
      });
      setItems(response.data.items);
      setTotal(response.data.total);
      setLoadError(false);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [kbFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const handlePromote = useCallback(async (reviewId: string) => {
    setActionReviewId(reviewId);
    try {
      await promoteMemoryReview(reviewId);
      message.success("候选已入库");
      await load();
    } catch (err: unknown) {
      if (isForbiddenError(err)) {
        setCanDecide(false);
        message.error("当前账号无权入库，已隐藏操作按钮");
      } else if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "入库失败");
      } else {
        message.error("入库失败");
      }
    } finally {
      setActionReviewId(null);
    }
  }, [load]);

  const openRejectModal = useCallback((item: MemoryReviewItem) => {
    setRejectTarget(item);
    setRejectReason("");
  }, []);

  const closeRejectModal = useCallback(() => {
    // Block cancel/ESC while submit in flight; success path clears state directly.
    if (rejectSubmitting) {
      return;
    }
    setRejectTarget(null);
    setRejectReason("");
  }, [rejectSubmitting]);

  const submitReject = async () => {
    if (!rejectTarget) {
      return;
    }
    const reason = rejectReason.trim();
    if (!reason) {
      message.warning("请填写拒绝原因");
      return;
    }
    const reviewId = rejectTarget.review_id;
    setRejectSubmitting(true);
    setActionReviewId(reviewId);
    try {
      await rejectMemoryReview(reviewId, { reason });
      message.success("候选已拒绝");
      // Clear modal state while submit flag is still true — do not call closeRejectModal().
      setRejectTarget(null);
      setRejectReason("");
      await load();
    } catch (err: unknown) {
      if (isForbiddenError(err)) {
        setCanDecide(false);
        setRejectTarget(null);
        setRejectReason("");
        message.error("当前账号无权拒绝，已隐藏操作按钮");
      } else if (err instanceof ApiError) {
        message.error(err.message || err.error_code || "拒绝失败");
      } else {
        message.error("拒绝失败");
      }
    } finally {
      setRejectSubmitting(false);
      setActionReviewId(null);
    }
  };

  const visibleItems = useMemo(() => {
    if (!eventIdFilter) return items;
    return items.filter((item) => readSourceEventId(item) === eventIdFilter);
  }, [eventIdFilter, items]);

  const columns: ColumnsType<MemoryReviewItem> = useMemo(() => {
    const base: ColumnsType<MemoryReviewItem> = [
      {
        title: "审核 ID",
        dataIndex: "review_id",
        key: "review_id",
        width: 140,
        render: (value: string) => (
          <Typography.Text code copyable={{ text: value }}>
            {value}
          </Typography.Text>
        ),
      },
      {
        title: "候选类型",
        dataIndex: "candidate_type",
        key: "candidate_type",
        width: 120,
        render: (value: MemoryReviewCandidateType) => (
          <Tag color={CANDIDATE_TYPE_COLORS[value]} data-testid={`candidate-type-${value}`}>
            {CANDIDATE_TYPE_LABELS[value]}
          </Tag>
        ),
      },
      {
        title: "知识库",
        dataIndex: "kb_name",
        key: "kb_name",
        width: 140,
      },
      {
        title: "来源事件",
        key: "source_event",
        width: 160,
        render: (_value, record) => {
          const eventId = readSourceEventId(record);
          if (!eventId) {
            return "—";
          }
          return <Link to={`/events/${eventId}`}>{eventId}</Link>;
        },
      },
      {
        title: "摘要",
        key: "summary",
        ellipsis: true,
        render: (_value, record) => readSummary(record),
      },
      {
        title: "置信度",
        dataIndex: "confidence",
        key: "confidence",
        width: 90,
        render: (value: number) => formatConfidence(value),
      },
      {
        title: "创建时间",
        dataIndex: "created_at",
        key: "created_at",
        width: 190,
        render: (value: string) => new Date(value).toLocaleString(),
      },
    ];

    if (canDecide) {
      base.push({
        title: "操作",
        key: "actions",
        width: 180,
        fixed: "right",
        render: (_value, record) => {
          const busy = actionReviewId === record.review_id;
          return (
            <Space size="small">
              <Popconfirm
                title="确认将该候选入库？"
                okText="入库"
                cancelText="取消"
                onConfirm={() => void handlePromote(record.review_id)}
                disabled={busy}
              >
                <Button type="link" size="small" loading={busy} data-testid={`promote-${record.review_id}`}>
                  入库
                </Button>
              </Popconfirm>
              <Button
                type="link"
                size="small"
                danger
                disabled={busy}
                onClick={() => openRejectModal(record)}
                data-testid={`reject-${record.review_id}`}
              >
                拒绝
              </Button>
            </Space>
          );
        },
      });
    }

    return base;
  }, [actionReviewId, canDecide, handlePromote, openRejectModal]);

  const hasClosedLoopTypes = visibleItems.some(
    (item) => item.candidate_type === "fp_rule" || item.candidate_type === "history_case",
  );
  const hasProfileOnly =
    visibleItems.length > 0 &&
    visibleItems.every((item) => item.candidate_type === "profile");

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Typography.Title level={3} style={{ marginBottom: 4 }}>
          知识审核
        </Typography.Title>
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          审查 MemoryAgent / ISSUE-208 入队的 pending 候选，人工确认后 promote 入库或 reject 拒绝。
        </Typography.Paragraph>
      </div>

      <Alert
        type="info"
        showIcon
        message="候选出现时机（预期行为）"
        description={
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            <li>{EXPECTED_TIMING_NOTE}</li>
            <li>列表为空且尚无 ISSUE-208 画像入队时，不代表本页未实现。</li>
          </ul>
        }
        data-testid="knowledge-review-timing-note"
      />

      {!canDecide && (
        <Alert
          type="warning"
          showIcon
          message="当前账号仅可查看待审核列表，入库/拒绝需 approver 角色。"
        />
      )}

      {eventIdFilter && (
        <Alert
          type="info"
          showIcon
          message={`按事件筛选：${eventIdFilter}`}
          description={
            visibleItems.length === 0
              ? "该事件暂无 pending 候选（或 API 未返回相关记录）。"
              : `显示 ${visibleItems.length} / ${total} 条候选。`
          }
          data-testid="knowledge-review-event-filter"
        />
      )}

      <Card size="small">
        <Space wrap>
          <Input
            allowClear
            aria-label="知识库筛选"
            placeholder="按 kb_name 筛选（可选）"
            value={kbFilterInput}
            onChange={(event) => setKbFilterInput(event.target.value)}
            onPressEnter={() => setKbFilter(kbFilterInput.trim() || undefined)}
            style={{ width: 280 }}
          />
          <Button type="primary" onClick={() => setKbFilter(kbFilterInput.trim() || undefined)}>
            查询
          </Button>
          <Button
            icon={<ReloadOutlined />}
            loading={loading}
            onClick={() => void load()}
          >
            刷新
          </Button>
        </Space>
      </Card>

      {loadError && (
        <Alert
          type="error"
          showIcon
          message="待审核列表加载失败"
          description="请检查后端 /knowledge/reviews 连接后重试。"
          action={
            <Button data-testid="knowledge-review-retry" onClick={() => void load()}>
              重试
            </Button>
          }
        />
      )}

      <Card>
        <Table
          rowKey="review_id"
          columns={columns}
          dataSource={visibleItems}
          loading={loading}
          pagination={false}
          scroll={{ x: 1100 }}
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description={
                  <Space direction="vertical" size={4}>
                    <span>当前暂无 pending 候选</span>
                    <Typography.Text type="secondary">
                      若 ISSUE-208 尚未入队画像，或尚无 CLOSED 事件触发 MemoryAgent，
                      列表为空属预期。{EXPECTED_TIMING_NOTE}
                    </Typography.Text>
                  </Space>
                }
              />
            ),
          }}
        />
        {total > 0 && (
          <Typography.Text type="secondary" style={{ display: "block", marginTop: 12 }}>
            {eventIdFilter
              ? `显示 ${visibleItems.length} / ${total} 条待审核（已按事件筛选）`
              : `共 ${total} 条待审核`}
            {hasProfileOnly ? "（当前均为 profile，符合 CLOSED 前预期）" : ""}
            {hasClosedLoopTypes ? "（含须 CLOSED 后入队的 fp_rule / history_case）" : ""}
          </Typography.Text>
        )}
      </Card>

      <Modal
        title="拒绝知识候选"
        open={rejectTarget !== null}
        okText="确认拒绝"
        cancelText="取消"
        confirmLoading={rejectSubmitting}
        onOk={() => void submitReject()}
        onCancel={closeRejectModal}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          审核 ID：{rejectTarget?.review_id}
        </Typography.Paragraph>
        <Input.TextArea
          aria-label="拒绝原因"
          rows={4}
          maxLength={1000}
          showCount
          placeholder="请说明拒绝原因（必填）"
          value={rejectReason}
          onChange={(event) => setRejectReason(event.target.value)}
        />
      </Modal>
    </Space>
  );
}
