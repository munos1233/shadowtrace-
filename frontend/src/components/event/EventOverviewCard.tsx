/** Event overview: type chip, low-confidence, reclassify modal (ISSUE-209). */

import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Descriptions,
  Form,
  Input,
  Modal,
  Progress,
  Row,
  Select,
  Space,
  Tag,
  Typography,
  message,
} from "antd";
import { useMemo, useState } from "react";
import type { ClassificationSource, EventDetailResponse, EventType } from "../../types/event";
import { currentAuthRoles } from "../../config/auth";
import { patchEventClassification } from "../../services/eventApi";
import { ApiError } from "../../services/apiClient";
import StatusBadge from "./StatusBadge";
import SeverityTag from "./SeverityTag";
import VerdictTag from "./VerdictTag";
import WritebackBadge from "./WritebackBadge";

const EVENT_TYPE_OPTIONS: { value: EventType; label: string }[] = [
  { value: "account_anomaly", label: "account_anomaly" },
  { value: "host_compromise", label: "host_compromise" },
  { value: "data_exfiltration", label: "data_exfiltration" },
  { value: "insider_threat", label: "insider_threat" },
  { value: "malicious_process", label: "malicious_process" },
  { value: "suspicious_domain", label: "suspicious_domain" },
  { value: "lateral_movement", label: "lateral_movement" },
  { value: "other", label: "other" },
];

const SOURCE_LABEL: Record<ClassificationSource, string> = {
  source: "源映射",
  heuristic: "启发式",
  llm_fallback: "LLM 回退",
  human: "人工",
};

function isLowConfidenceClassification(
  eventType: EventType | string | undefined,
  source: ClassificationSource | null | undefined,
): boolean {
  if (eventType === "other") return true;
  return source === "heuristic" || source === "llm_fallback";
}

interface Props {
  detail: EventDetailResponse;
  onRefresh?: () => Promise<void>;
}

export default function EventOverviewCard({ detail, onRefresh }: Props) {
  const { event } = detail;
  const roles = currentAuthRoles();
  const canReclassify = roles.includes("analyst") || roles.includes("admin");
  const classificationSource = event.classification_source ?? "source";
  const lowConfidence = isLowConfidenceClassification(event.event_type, classificationSource);

  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm<{
    event_type: EventType;
    reason: string;
    reinvestigate: boolean;
  }>();

  const typeChipColor = useMemo(() => {
    if (classificationSource === "human") return "blue";
    if (lowConfidence) return "orange";
    return "default";
  }, [classificationSource, lowConfidence]);

  const openModal = () => {
    form.setFieldsValue({
      event_type: event.event_type,
      reason: "",
      reinvestigate: false,
    });
    setOpen(true);
  };

  const submit = async () => {
    const values = await form.validateFields();
    setSubmitting(true);
    try {
      const response = await patchEventClassification(event.event_id, {
        event_type: values.event_type,
        reason: values.reason.trim(),
        reinvestigate: Boolean(values.reinvestigate),
      });
      const result = response.data;
      message.success(
        result.reinvestigate_started
          ? "类型已更新，并已启动受控重调查"
          : "事件类型已更新（已审计）",
      );
      setOpen(false);
      await onRefresh?.();
    } catch (err) {
      if (err instanceof ApiError) {
        message.error(err.message || "改类型失败");
      } else {
        message.error("改类型失败");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card data-testid="event-overview-card">
      <Row gutter={[24, 16]} align="middle">
        <Col flex="auto">
          <Space direction="vertical" size={6}>
            <Typography.Title level={3} style={{ margin: 0 }}>
              {event.title || "暂无数据"}
            </Typography.Title>
            <Typography.Text type="secondary">{event.event_id}</Typography.Text>
            <Space wrap>
              <StatusBadge status={event.status} />
              <SeverityTag severity={event.severity} />
              <VerdictTag verdict={event.final_verdict} />
              {event.external_unsynced && <Tag color="orange">外部状态未同步</Tag>}
            </Space>
          </Space>
        </Col>
        <Col xs={24} sm={8} md={6}>
          <Typography.Text type="secondary">综合风险</Typography.Text>
          <Progress
            percent={Math.round(event.risk_score ?? 0)}
            status={event.risk_score >= 80 ? "exception" : "normal"}
            strokeColor={event.risk_score >= 60 ? "#fa8c16" : "#1677ff"}
          />
        </Col>
      </Row>
      <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} style={{ marginTop: 20 }}>
        <Descriptions.Item label="事件类型">
          <Space wrap size={6}>
            <Tag color={typeChipColor} data-testid="event-type-chip">
              {event.event_type || "暂无数据"}
            </Tag>
            <Tag data-testid="classification-source-chip">
              {SOURCE_LABEL[classificationSource] ?? classificationSource}
            </Tag>
            {lowConfidence && (
              <Tag color="warning" data-testid="low-confidence-chip">
                低置信
              </Tag>
            )}
            {canReclassify && (
              <Button
                type="link"
                size="small"
                onClick={openModal}
                data-testid="reclassify-open"
                style={{ paddingInline: 0 }}
              >
                改类型
              </Button>
            )}
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="置信度">
          {Number.isFinite(event.confidence) ? `${Math.round(event.confidence * 100)}%` : "暂无数据"}
        </Descriptions.Item>
        <Descriptions.Item label="发生时间">{event.occurred_at || "暂无数据"}</Descriptions.Item>
        <Descriptions.Item label="外部写回">
          <WritebackBadge
            required={detail.writeback_required}
            status={detail.writeback_overall_status}
            eventStatus={event.status}
            externalUnsynced={event.external_unsynced}
          />
        </Descriptions.Item>
      </Descriptions>

      <Modal
        title="修正事件类型"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void submit()}
        confirmLoading={submitting}
        okText="保存"
        destroyOnClose
        data-testid="reclassify-modal"
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="改类型可能影响 severity 判定与后续处置规则；请填写审计原因。"
        />
        <Form form={form} layout="vertical" requiredMark>
          <Form.Item
            name="event_type"
            label="事件类型"
            rules={[{ required: true, message: "请选择事件类型" }]}
          >
            <Select options={EVENT_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="reason"
            label="原因（审计）"
            rules={[
              { required: true, message: "请填写改类型原因" },
              { min: 1, message: "原因不能为空" },
            ]}
          >
            <Input.TextArea rows={3} maxLength={500} showCount placeholder="说明为何覆盖当前类型" />
          </Form.Item>
          <Form.Item name="reinvestigate" valuePropName="checked" initialValue={false}>
            <Checkbox>
              同时触发受控重调查（仅 NEW 状态会立即启动；将获取调查租约并调度分析）
            </Checkbox>
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
