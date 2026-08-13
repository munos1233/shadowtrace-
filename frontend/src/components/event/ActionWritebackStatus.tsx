/** Per-action writeback lamp — splits obligation vs applicability (ISSUE-331). */

import { Tooltip, Typography } from "antd";
import {
  CheckCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
  MinusCircleOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import type { ActionWritebackInput } from "../../utils/actionWritebackDisplay";
import {
  resolveActionWritebackDisplay,
  type ActionWritebackDisplayTone,
} from "../../utils/actionWritebackDisplay";

export interface ActionWritebackStatusProps extends ActionWritebackInput {
  "data-testid"?: string;
}

const TONE_COLORS: Record<ActionWritebackDisplayTone, string> = {
  neutral: "#8c8c8c",
  success: "#52c41a",
  warning: "#faad14",
  error: "#ff4d4f",
  info: "#1677ff",
};

function ToneIcon({ tone }: { tone: ActionWritebackDisplayTone }) {
  if (tone === "success") return <CheckCircleFilled />;
  if (tone === "error") return <CloseCircleFilled />;
  if (tone === "warning") return <ExclamationCircleFilled />;
  if (tone === "info") return <SyncOutlined />;
  return <MinusCircleOutlined />;
}

export default function ActionWritebackStatus({
  writeback_required,
  writeback_applicable,
  writeback_status,
  "data-testid": testId,
}: ActionWritebackStatusProps) {
  const display = resolveActionWritebackDisplay({
    writeback_required,
    writeback_applicable,
    writeback_status,
  });
  const color = TONE_COLORS[display.tone];

  return (
    <Tooltip title={display.tooltip}>
      <span data-testid={testId} style={{ fontSize: 12, color }}>
        <ToneIcon tone={display.tone} />
        <Typography.Text style={{ marginLeft: 4, color, fontSize: 12 }}>
          {display.label}
        </Typography.Text>
      </span>
    </Tooltip>
  );
}
