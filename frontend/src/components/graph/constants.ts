import type {
  GraphEntityType,
  GraphRelationType,
} from "../../types/event";

export const ENTITY_COLORS: Record<GraphEntityType, string> = {
  account: "#1677ff",
  host: "#52c41a",
  ip: "#fa8c16",
  domain: "#722ed1",
  process: "#d4b106",
  file: "#13c2c2",
};

export const ENTITY_LABELS: Record<GraphEntityType, string> = {
  account: "账户",
  host: "主机",
  ip: "IP 地址",
  domain: "域名",
  process: "进程",
  file: "文件",
};

export const ENTITY_TYPES = Object.keys(ENTITY_COLORS) as GraphEntityType[];

export const RELATION_LABELS: Record<GraphRelationType, string> = {
  logged_in_from: "登录来源",
  logged_in_to: "登录到",
  executed: "执行",
  accessed: "访问",
  connected_to: "连接到",
  resolved: "解析为",
  requested: "请求",
  uploaded_to: "上传到",
};
