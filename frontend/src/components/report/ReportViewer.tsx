/** ReportViewer — 15-chapter report with TOC, export (ISSUE-074).

Sections are rendered in the order returned by the backend
(ReportSectionBuilder.SECTION_SPECS).  The TOC and Markdown export
use CHAPTER_KEYS for stable ordering / dedup.
*/

import { useRef, useEffect } from "react";
import { Alert, Button, Spin, Typography, Divider } from "antd";
import { FileTextOutlined, ReloadOutlined } from "@ant-design/icons";
import type { InvestigationReport, ReportQuality } from "../../types/report";
import { resolveReportQuality } from "../../types/report";
import ReportToc from "./ReportToc";
import ReportExportButtons from "./ReportExportButtons";
import ReportSectionContent from "./ReportSectionContent";

const { Title, Text } = Typography;

/** Print stylesheet — injected once per page lifecycle. */
const PRINT_STYLES = `
@media print {
  .shadowtrace-sidebar, .shadowtrace-header, .shadowtrace-toc, .shadowtrace-export-btns,
  .shadowtrace-event-toolbar, .shadowtrace-event-tabs .ant-tabs-nav {
    display: none !important;
  }
  .shadowtrace-report-viewer { padding: 0 !important; max-width: 100% !important; }
}
`;

interface ReportViewerProps {
  report: InvestigationReport | null;
  loading: boolean;
  eventStatus?: string;
  /** ISSUE-206: on-demand generation (empty state CTA). */
  onGenerate?: () => void;
  /** ISSUE-206: regenerate an existing report (with confirmation upstream). */
  onRegenerate?: () => void;
  generating?: boolean;
}

function qualityAlert(report: InvestigationReport): {
  message: string;
  type: "warning" | "info" | "error";
} | null {
  const quality: ReportQuality = resolveReportQuality(report);
  if (quality === "complete" && !report.degraded) {
    return null;
  }
  if (quality === "degraded_template") {
    return { message: "模板生成（LLM 降级）— 非完整合格报告", type: "warning" };
  }
  if (quality === "quick_close") {
    return {
      message: "快速结案报告 — 逃生舱薄报告，非完整调查交付",
      type: "info",
    };
  }
  if (quality === "incomplete_placeholder") {
    return {
      message: "报告质量不完整 — 已执行阶段仍含占位章节，不可视为合格完整报告",
      type: "error",
    };
  }
  if (report.degraded) {
    return { message: `报告已降级（${quality}）`, type: "warning" };
  }
  return null;
}

export default function ReportViewer({
  report,
  loading,
  eventStatus,
  onGenerate,
  onRegenerate,
  generating = false,
}: ReportViewerProps) {
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

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 48 }}>
        <Spin size="large" />
        <Text type="secondary" style={{ display: "block", marginTop: 16 }}>
          加载中...
        </Text>
      </div>
    );
  }

  if (!report || report.sections.length === 0) {
    const isReporting = eventStatus === "reporting";
    return (
      <div style={{ textAlign: "center", padding: 48 }}>
        <FileTextOutlined style={{ fontSize: 48, color: "#d9d9d9" }} />
        <Text type="secondary" style={{ display: "block", marginTop: 16 }}>
          {isReporting ? "报告生成中，请稍候..." : "报告尚未生成"}
        </Text>
        {!isReporting && onGenerate && (
          <Button
            type="primary"
            icon={<FileTextOutlined />}
            loading={generating}
            style={{ marginTop: 16 }}
            onClick={onGenerate}
            data-testid="report-generate-button"
          >
            生成完整报告
          </Button>
        )}
      </div>
    );
  }

  const alert = qualityAlert(report);

  return (
    <div data-testid="report-viewer" style={{ display: "flex", gap: 24 }}>
      <div className="shadowtrace-toc">
        <ReportToc report={report} />
      </div>

      <div className="shadowtrace-report-viewer" style={{ flex: 1, maxWidth: 800 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <div className="shadowtrace-export-btns">
            <ReportExportButtons report={report} />
          </div>
          {onRegenerate && eventStatus !== "reporting" && (
            <Button
              size="small"
              icon={<ReloadOutlined />}
              loading={generating}
              onClick={onRegenerate}
              data-testid="report-regenerate-button"
            >
              重新生成
            </Button>
          )}
        </div>

        {alert && (
          <Alert
            message={alert.message}
            type={alert.type}
            showIcon
            style={{ marginBottom: 16 }}
            data-testid="report-quality-alert"
          />
        )}

        <Title level={4}>
          <FileTextOutlined style={{ marginRight: 8 }} />
          {report.title}
        </Title>
        <Text type="secondary">
          判定：{report.final_verdict} | 风险分：{report.risk_score} | 严重程度：
          {report.severity}
          {report.report_quality ? ` | 质量：${report.report_quality}` : ""}
        </Text>

        <Divider />

        {report.sections.map((section) => (
          <div key={section.key} id={section.key} style={{ marginBottom: 32 }}>
            <Title level={5} id={`${section.key}-title`}>
              {section.title}
            </Title>
            <ReportSectionContent content={section.content} />
          </div>
        ))}
      </div>
    </div>
  );
}
