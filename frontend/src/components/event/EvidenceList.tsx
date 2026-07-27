import { Select, Space, Table, Tag, Tooltip, Typography } from "antd";
import { WarningOutlined } from "@ant-design/icons";
import { useMemo, useState } from "react";
import type { ColumnsType } from "antd/es/table";
import type { Evidence, EvidenceConflict } from "../../types/event";

function conflictReason(evidenceId: string, conflicts: EvidenceConflict[]): string | null {
  const reasons = conflicts
    .filter((conflict) => conflict.evidence_ids.includes(evidenceId))
    .map((conflict) => conflict.description);
  return reasons.length > 0 ? reasons.join("；") : null;
}

export default function EvidenceList({
  evidence,
  conflicts,
}: {
  evidence: Evidence[];
  conflicts: EvidenceConflict[];
}) {
  const [source, setSource] = useState<string>();
  const sources = useMemo(
    () => [...new Set(evidence.map((item) => item.source))].sort(),
    [evidence],
  );
  const rows = source ? evidence.filter((item) => item.source === source) : evidence;

  const columns: ColumnsType<Evidence> = [
    { title: "evidence_id", dataIndex: "evidence_id", width: 170 },
    { title: "source", dataIndex: "source", width: 130 },
    { title: "evidence_type", dataIndex: "evidence_type", width: 150 },
    {
      title: "timestamp",
      dataIndex: "timestamp",
      width: 180,
      render: (value: string | null) => value || "暂无数据",
    },
    {
      title: "description",
      dataIndex: "description",
      render: (value: string, record) => {
        const reason = conflictReason(record.evidence_id, conflicts);
        const isConflicting = record.is_conflicting || Boolean(reason);
        return (
          <Space>
            <Typography.Text>{value || "暂无数据"}</Typography.Text>
            {isConflicting && (
              <Tooltip title={reason || "存在冲突，但暂无冲突原因"}>
                <Tag color="error" icon={<WarningOutlined />} data-testid={`evidence-conflict-${record.evidence_id}`}>
                  冲突证据
                </Tag>
              </Tooltip>
            )}
          </Space>
        );
      },
    },
    {
      title: "confidence",
      dataIndex: "confidence",
      width: 110,
      render: (value: number) => `${Math.round((value ?? 0) * 100)}%`,
    },
    {
      title: "is_conflicting",
      dataIndex: "is_conflicting",
      width: 120,
      render: (value: boolean, record) =>
        value || conflictReason(record.evidence_id, conflicts) ? (
          <Tag color="red">是</Tag>
        ) : (
          <Tag>否</Tag>
        ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Select
        allowClear
        placeholder="按证据来源筛选"
        value={source}
        onChange={setSource}
        options={sources.map((item) => ({ label: item, value: item }))}
        style={{ width: 220 }}
        data-testid="evidence-source-filter"
      />
      <Table
        rowKey="evidence_id"
        columns={columns}
        dataSource={rows}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
        locale={{ emptyText: "暂无数据" }}
        scroll={{ x: 1050 }}
        onRow={(record) => ({
          "data-testid": `evidence-row-${record.evidence_id}`,
          style: record.is_conflicting || conflictReason(record.evidence_id, conflicts)
            ? { background: "rgba(255, 77, 79, 0.08)", borderLeft: "3px solid #ff4d4f" }
            : undefined,
        })}
      />
    </Space>
  );
}
