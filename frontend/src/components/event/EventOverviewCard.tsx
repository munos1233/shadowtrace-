import { Card, Col, Descriptions, Progress, Row, Space, Tag, Typography } from "antd";
import type { EventDetailResponse } from "../../types/event";
import StatusBadge from "./StatusBadge";
import SeverityTag from "./SeverityTag";
import VerdictTag from "./VerdictTag";
import WritebackBadge from "./WritebackBadge";

interface Props {
  detail: EventDetailResponse;
}

export default function EventOverviewCard({ detail }: Props) {
  const { event } = detail;
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
        <Descriptions.Item label="事件类型">{event.event_type || "暂无数据"}</Descriptions.Item>
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
    </Card>
  );
}
