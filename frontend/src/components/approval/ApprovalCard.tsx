/** ApprovalCard — single pending-approval action (ISSUE-073). */

import { memo } from "react";
import { Card, Tag, Typography, Space, theme } from "antd";
import { ClockCircleOutlined, WarningOutlined } from "@ant-design/icons";
import type { Action } from "../../types/action";

const { Text, Title } = Typography;
const { useToken } = theme;

interface ApprovalCardProps {
  action: Action;
  timedOut: boolean;
  onApprove: (actionId: string) => void;
  onReject: (actionId: string) => void;
}

function ApprovalCard({ action, timedOut, onApprove, onReject }: ApprovalCardProps) {
  const { token } = useToken();

  const isDeferred = action.execution_phase === "post_verify";
  const levelColors: Record<string, string> = {
    l0: token.colorSuccess,
    l1: token.colorSuccess,
    l2: token.colorWarning,
    l3: token.colorWarning,
    l4: token.colorError,
    l5: token.colorError,
  };

  const cardStyle: React.CSSProperties = timedOut
    ? { opacity: 0.5, borderColor: token.colorBorderSecondary }
    : {};

  return (
    <Card
      size="small"
      style={cardStyle}
      title={
        <Space>
          <Text strong>{action.action_name || action.tool_name}</Text>
          <Tag color={levelColors[action.action_level] || "default"}>
            {action.action_level.toUpperCase()}
          </Tag>
          {isDeferred && (
            <Tag color="purple">
              <WarningOutlined /> POST_VERIFY
            </Tag>
          )}
          {timedOut && (
            <Tag color="default">
              <ClockCircleOutlined /> 已超时
            </Tag>
          )}
        </Space>
      }
      extra={
        !timedOut ? (
          <Space>
            <a onClick={() => onApprove(action.action_id)}>批准</a>
            <a style={{ color: token.colorError }} onClick={() => onReject(action.action_id)}>
              拒绝
            </a>
          </Space>
        ) : (
          <Text type="secondary">超时（后续端判定为准）</Text>
        )
      }
    >
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        <div>
          <Text type="secondary">目标：</Text>
          <Text>{action.target || "—"}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            类型：
          </Text>
          <Text>{action.target_type || "—"}</Text>
        </div>
        <div>
          <Text type="secondary">执行者：</Text>
          <Text>{action.execution_owner || "—"}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            阶段：
          </Text>
          <Text>{action.execution_phase}</Text>
        </div>
        {isDeferred && (
          <Text type="warning">
            <WarningOutlined /> 效果验证后激活，须先批准。分析内容仅本地保存，不写回。
          </Text>
        )}
        <div>
          <Text type="secondary">事件：</Text>
          <Text code>{action.event_id}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            动作：
          </Text>
          <Text code>{action.action_id}</Text>
        </div>
      </Space>
    </Card>
  );
}

export default memo(ApprovalCard);
