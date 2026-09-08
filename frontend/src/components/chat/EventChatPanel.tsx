import {
  Alert,
  Button,
  Card,
  Empty,
  Input,
  List,
  Space,
  Tag,
  Typography,
} from "antd";
import {
  LinkOutlined,
  RobotOutlined,
  SendOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { askEventQuestion } from "../../services/chatApi";
import type {
  ChatHistoryItem,
  ChatReference,
  ChatRole,
} from "../../types/chat";

interface DisplayMessage {
  id: number;
  role: ChatRole;
  content: string;
  references: ChatReference[];
}

const REFERENCE_LABELS = {
  evidence: "证据",
  trace: "轨迹",
  report: "报告",
} as const;

const REFERENCE_TABS = {
  evidence: "evidence",
  trace: "audit",
  report: "report",
} as const;

export default function EventChatPanel({ eventId }: { eventId: string }) {
  const navigate = useNavigate();
  const location = useLocation();
  const sequence = useRef(0);
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  const nextId = () => {
    sequence.current += 1;
    return sequence.current;
  };

  const jumpToReference = (reference: ChatReference) => {
    navigate(
      {
        pathname: location.pathname,
        search: location.search,
        hash: REFERENCE_TABS[reference.ref_type],
      },
      { replace: true },
    );
  };

  const send = async () => {
    const trimmed = question.trim();
    if (!trimmed || loading) return;

    const history: ChatHistoryItem[] = messages
      .map(({ role, content }) => ({ role, content }))
      .slice(-10);
    const userMessage: DisplayMessage = {
      id: nextId(),
      role: "user",
      content: trimmed,
      references: [],
    };
    setMessages((current) => [...current, userMessage]);
    setQuestion("");
    setLoading(true);
    setUnavailable(false);

    try {
      const response = await askEventQuestion(eventId, {
        question: trimmed,
        history,
      });
      setMessages((current) => [
        ...current,
        {
          id: nextId(),
          role: "assistant",
          content: response.data.answer,
          references: response.data.references,
        },
      ]);
    } catch {
      setUnavailable(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Typography.Title level={4} style={{ marginBottom: 4 }}>
          事件问答
        </Typography.Title>
        <Typography.Text type="secondary">
          基于事件上下文、风险评分、证据与决策轨迹回答；引用可直接跳转核验。
        </Typography.Text>
      </div>

      {unavailable && (
        <Alert
          type="warning"
          showIcon
          message="问答暂不可用"
          description="事件详情和其他研判功能不受影响，请稍后重试。"
        />
      )}

      <Card size="small" styles={{ body: { minHeight: 260, maxHeight: 480, overflowY: "auto" } }}>
        {messages.length === 0 ? (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="可以询问：为什么判定为高危？有哪些关键证据？为何执行该处置？"
          />
        ) : (
          <List
            split={false}
            dataSource={messages}
            renderItem={(message) => (
              <List.Item
                key={message.id}
                style={{
                  justifyContent: message.role === "user" ? "flex-end" : "flex-start",
                }}
              >
                <Card
                  size="small"
                  style={{
                    maxWidth: "82%",
                    background: message.role === "user" ? "#e6f4ff" : "#fafafa",
                  }}
                >
                  <Space direction="vertical" size={8}>
                    <Space size={6}>
                      {message.role === "user" ? <UserOutlined /> : <RobotOutlined />}
                      <Typography.Text strong>
                        {message.role === "user" ? "你" : "ShadowTrace"}
                      </Typography.Text>
                    </Space>
                    <Typography.Paragraph style={{ marginBottom: 0, whiteSpace: "pre-wrap" }}>
                      {message.content}
                    </Typography.Paragraph>
                    {message.references.length > 0 && (
                      <Space wrap size={[4, 4]} aria-label="回答引用">
                        {message.references.map((reference) => (
                          <Button
                            key={`${reference.ref_type}-${reference.ref_id}`}
                            type="link"
                            size="small"
                            icon={<LinkOutlined />}
                            onClick={() => jumpToReference(reference)}
                            style={{ paddingInline: 0 }}
                          >
                            <Tag color="blue">
                              {REFERENCE_LABELS[reference.ref_type]} {reference.ref_id}
                            </Tag>
                          </Button>
                        ))}
                      </Space>
                    )}
                  </Space>
                </Card>
              </List.Item>
            )}
          />
        )}
      </Card>

      <Space.Compact style={{ width: "100%" }}>
        <Input.TextArea
          aria-label="事件问题"
          value={question}
          autoSize={{ minRows: 2, maxRows: 5 }}
          maxLength={2000}
          placeholder="输入事件相关问题，Enter 发送，Shift+Enter 换行"
          disabled={loading}
          onChange={(event) => setQuestion(event.target.value)}
          onPressEnter={(event) => {
            if (!event.shiftKey) {
              event.preventDefault();
              void send();
            }
          }}
        />
        <Button
          type="primary"
          icon={<SendOutlined />}
          loading={loading}
          disabled={!question.trim()}
          onClick={() => void send()}
          style={{ height: "auto" }}
        >
          发送
        </Button>
      </Space.Compact>
    </Space>
  );
}
