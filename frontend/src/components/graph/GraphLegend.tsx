import { Checkbox, Space, Typography } from "antd";
import type { GraphEntityType } from "../../types/event";
import { ENTITY_COLORS, ENTITY_LABELS, ENTITY_TYPES } from "./constants";

export default function GraphLegend({
  visibleTypes,
  onToggle,
}: {
  visibleTypes: ReadonlySet<GraphEntityType>;
  onToggle: (entityType: GraphEntityType) => void;
}) {
  return (
    <Space wrap size={[16, 8]} aria-label="实体类型图例">
      {ENTITY_TYPES.map((entityType) => (
        <Checkbox
          key={entityType}
          checked={visibleTypes.has(entityType)}
          onChange={() => onToggle(entityType)}
          data-testid={`graph-filter-${entityType}`}
        >
          <Space size={6}>
            <span
              aria-hidden="true"
              style={{
                display: "inline-block",
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: ENTITY_COLORS[entityType],
              }}
            />
            <Typography.Text>{ENTITY_LABELS[entityType]}</Typography.Text>
          </Space>
        </Checkbox>
      ))}
    </Space>
  );
}
