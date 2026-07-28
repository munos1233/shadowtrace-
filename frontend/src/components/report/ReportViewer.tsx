/** ReportViewer — 15-chapter report with TOC, Markdown rendering, export (ISSUE-074). */

import { useMemo, useRef, useEffect } from "react";
import { Alert, Spin, Typography, Divider } from "antd";
import { FileTextOutlined } from "@ant-design/icons";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { InvestigationReport } from "../../types/report";
import ReportToc from "./ReportToc";
import ReportExportButtons from "./ReportExportButtons";
import { CHAPTER_KEYS } from "../../utils/exportMarkdown";

const { Title, Text } = Typography;

/** Print stylesheet — injected once per page lifecycle. */
const PRINT_STYLES = `
@media print {
  .shadowtrace-sidebar, .shadowtrace-header, .shadowtrace-toc, .shadowtrace-export-btns {
    display: none !important;
  }
  .shadowtrace-report-viewer { padding: 0 !important; max-width: 100% !important; }
}
`;

interface ReportViewerProps {
  report: InvestigationReport | null;
  loading: boolean;
  eventStatus?: string;
}

export default function ReportViewer({ report, loading, eventStatus }: ReportViewerProps) {
  const printStyleRef = useRef<HTMLStyleElement | null>(null);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const style = document.createElement("style");
    style.textContent = PRINT_STYLES;
    document.head.appendChild(style);
    printStyleRef.current = style;
    return () => {
      if (printStyleRef.current) {
        document.head.removeChild(printStyleRef.current);
        printStyleRef.current = null;
      }
    };
  }, []);
  const sections = useMemo(() => {
    if (!report) return [];
    return CHAPTER_KEYS
      .filter((k) => report.sections.some((s) => s.key === k))
      .map((k) => report.sections.find((s) => s.key === k)!);
  }, [report]);

  // Loading state
  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 48 }}>
        <Spin size="large" />
        <Text type="secondary" style={{ display: "block", marginTop: 16 }}>
          正在生成报告...
        </Text>
      </div>
    );
  }

  // Not yet generated
  if (!report || sections.length === 0) {
    const isReporting = eventStatus === "reporting";
    return (
      <div style={{ textAlign: "center", padding: 48 }}>
        <FileTextOutlined style={{ fontSize: 48, color: "#d9d9d9" }} />
        <Text type="secondary" style={{ display: "block", marginTop: 16 }}>
          {isReporting ? "报告生成中，请稍候..." : "报告尚未生成"}
        </Text>
      </div>
    );
  }

  const isTemplate = report.generated_by === "template";

  return (
    <div style={{ display: "flex", gap: 24 }}>
      <div className="shadowtrace-toc">
        <ReportToc report={report} />
      </div>

      <div className="shadowtrace-report-viewer" style={{ flex: 1, maxWidth: 800 }}>
        {isTemplate && (
          <Alert
            message="模板生成（LLM 降级）"
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        <div className="shadowtrace-export-btns" style={{ marginBottom: 16 }}>
          <ReportExportButtons report={report} />
        </div>

        <Title level={4}>
          <FileTextOutlined style={{ marginRight: 8 }} />
          {report.title}
        </Title>
        <Text type="secondary">
          判定：{report.final_verdict} | 风险分：{report.risk_score} | 严重程度：{report.severity}
        </Text>

        <Divider />

        {sections.map((section) => (
          <div key={section.key} id={section.key} style={{ marginBottom: 32 }}>
            <Title level={5} id={`${section.key}-title`}>
              {section.title}
            </Title>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {section.content}
            </ReactMarkdown>
          </div>
        ))}
      </div>
    </div>
  );
}
