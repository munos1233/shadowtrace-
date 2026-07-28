/** Global header search box with grouped results dropdown (ISSUE-084). */

import { useCallback, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AutoComplete,
  Empty,
  Input,
  Space,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { SearchOutlined, WarningOutlined } from "@ant-design/icons";
import { search } from "../../services/eventApi";
import type { SearchResultItem, SearchScope } from "../../types/event";

const SEARCH_DEBOUNCE_MS = 300;
const MIN_QUERY_LENGTH = 2;

const INDEX_COLORS: Record<string, string> = {
  "shadowtrace-tool-calls": "blue",
  tool_call_log: "blue",
  "shadowtrace-audit-logs": "green",
  event_audit_log: "green",
  "shadowtrace-evidence": "orange",
  evidence: "orange",
};

const INDEX_LABELS: Record<string, string> = {
  "shadowtrace-tool-calls": "工具调用",
  tool_call_log: "工具调用",
  "shadowtrace-audit-logs": "审计日志",
  event_audit_log: "审计日志",
  "shadowtrace-evidence": "证据",
  evidence: "证据",
};

interface OptionItem {
  value: string;
  label: React.ReactNode;
  item: SearchResultItem;
}

function highlightHtml(text: string): string {
  // OpenSearch returns <em> tags; strip for plain display in dropdown.
  return text.replace(/<\/?em>/g, "");
}

export default function GlobalSearchBox() {
  const navigate = useNavigate();
  const [options, setOptions] = useState<OptionItem[]>([]);
  const [degraded, setDegraded] = useState(false);
  const [searching, setSearching] = useState(false);
  const [inputValue, setInputValue] = useState("");
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const doSearch = useCallback(
    async (query: string, scope: SearchScope = "all") => {
      if (query.trim().length < MIN_QUERY_LENGTH) {
        setOptions([]);
        setDegraded(false);
        return;
      }
      setSearching(true);
      try {
        const response = await search({ q: query.trim(), scope, page_size: 10 });
        setDegraded(response.data.degraded);
        const items: OptionItem[] = response.data.items.map(
          (item: SearchResultItem) => ({
            value: item.doc_id,
            label: (
              <Space direction="vertical" size={0} style={{ width: "100%" }}>
                <Space size={4}>
                  <Tag
                    color={INDEX_COLORS[item.index] ?? "default"}
                    style={{ fontSize: 11, lineHeight: "18px" }}
                  >
                    {INDEX_LABELS[item.index] ?? item.index}
                  </Tag>
                  {response.data.degraded && (
                    <Tooltip title="搜索降级至 PostgreSQL，无高亮">
                      <WarningOutlined
                        style={{ color: "#faad14", fontSize: 12 }}
                      />
                    </Tooltip>
                  )}
                </Space>
                <Typography.Text
                  ellipsis
                  style={{ fontSize: 13, maxWidth: 480 }}
                >
                  {item.highlight
                    ? highlightHtml(item.highlight)
                    : item.source_summary}
                </Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                  {item.event_id}
                </Typography.Text>
              </Space>
            ),
            item,
          }),
        );
        setOptions(items);
      } catch {
        setOptions([]);
        setDegraded(false);
      } finally {
        setSearching(false);
      }
    },
    [],
  );

  const handleSearch = useCallback(
    (value: string) => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
      timerRef.current = setTimeout(() => {
        void doSearch(value);
      }, SEARCH_DEBOUNCE_MS);
    },
    [doSearch],
  );

  const handleSelect = useCallback(
    (_value: string, option: unknown) => {
      const opt = option as OptionItem;
      const { item } = opt;
      // Navigate based on index type.
      if (item.event_id) {
        navigate(`/events/${item.event_id}`);
      } else if (
        item.index === "shadowtrace-tool-calls" ||
        item.index === "tool_call_log"
      ) {
        navigate("/tools-audit");
      } else {
        navigate("/events");
      }
      setInputValue("");
      setOptions([]);
    },
    [navigate],
  );

  const handleChange = useCallback(
    (value: string) => {
      setInputValue(value);
      handleSearch(value);
    },
    [handleSearch],
  );

  const groupedOptions = useMemo(() => {
    const groups: Record<string, OptionItem[]> = {};
    for (const opt of options) {
      const label = INDEX_LABELS[opt.item.index] ?? opt.item.index;
      if (!groups[label]) groups[label] = [];
      groups[label].push(opt);
    }
    return Object.entries(groups).flatMap(([label, items]) => [
      { label: <Typography.Text strong>{label}</Typography.Text>, value: `__group__${label}`, disabled: true },
      ...items,
    ]);
  }, [options]);

  return (
    <Space style={{ minWidth: 320 }}>
      {degraded && (
        <Tooltip title="OpenSearch 不可用，已降级至数据库搜索">
          <WarningOutlined style={{ color: "#faad14" }} />
        </Tooltip>
      )}
      <AutoComplete
        value={inputValue}
        options={groupedOptions}
        onSearch={handleChange}
        onSelect={handleSelect}
        notFoundContent={
          searching ? (
            <Typography.Text type="secondary">搜索中…</Typography.Text>
          ) : inputValue.length >= MIN_QUERY_LENGTH ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="未找到结果"
            />
          ) : null
        }
        style={{ width: 360 }}
        popupMatchSelectWidth={500}
      >
        <Input
          prefix={<SearchOutlined />}
          placeholder="搜索工具调用、审计日志、证据…"
          allowClear
          onClear={() => {
            setOptions([]);
            setDegraded(false);
          }}
        />
      </AutoComplete>
    </Space>
  );
}
