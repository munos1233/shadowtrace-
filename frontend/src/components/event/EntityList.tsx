import { Card, Empty, Space, Tag, Typography } from "antd";
import type { EntityItem, EntitySet } from "../../types/event";

const ENTITY_GROUPS: {
  key: keyof EntitySet;
  label: string;
  color: string;
}[] = [
  { key: "accounts", label: "账号", color: "blue" },
  { key: "hosts", label: "主机", color: "cyan" },
  { key: "ips", label: "IP", color: "geekblue" },
  { key: "domains", label: "域名", color: "purple" },
  { key: "processes", label: "进程", color: "orange" },
  { key: "files", label: "文件", color: "gold" },
];

function entityName(entity: EntityItem): string {
  switch (entity.entity_type) {
    case "account":
      return entity.username || entity.display_name || entity.entity_id;
    case "host":
      return entity.hostname || entity.ip || entity.entity_id;
    case "ip":
      return entity.address || entity.entity_id;
    case "domain":
      return entity.fqdn || entity.entity_id;
    case "process":
      return entity.name || entity.command_line || entity.entity_id;
    case "file":
      return entity.path || entity.name || entity.hash || entity.entity_id;
  }
}

export default function EntityList({ entities }: { entities?: EntitySet | null }) {
  const count = ENTITY_GROUPS.reduce(
    (total, group) => total + (entities?.[group.key]?.length ?? 0),
    0,
  );
  return (
    <Card title={`关联实体（${count}）`} data-testid="entity-list" style={{ height: "100%" }}>
      {count === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
      ) : (
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          {ENTITY_GROUPS.map((group) => {
            const items = entities?.[group.key] ?? [];
            if (items.length === 0) return null;
            return (
              <div key={group.key}>
                <Typography.Text type="secondary">{group.label}</Typography.Text>
                <div style={{ marginTop: 6 }}>
                  {items.map((entity) => (
                    <Tag key={entity.entity_id} color={group.color} style={{ marginBottom: 6 }}>
                      {entityName(entity)}
                    </Tag>
                  ))}
                </div>
              </div>
            );
          })}
        </Space>
      )}
    </Card>
  );
}
