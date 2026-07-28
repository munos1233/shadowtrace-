/** ReportViewer tests (ISSUE-074). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import ReportViewer from "../../src/components/report/ReportViewer";

describe("ReportViewer", () => {
  const mockReport = {
    report_id: "rpt-abc12345",
    event_id: "evt-test001",
    title: "数据外泄调查报告",
    summary: "",
    sections: [
      { key: "overview", title: "事件概述", content: "事件概述内容...", data: {} },
      { key: "triage", title: "分诊结果", content: "分诊结果内容...", data: {} },
      { key: "evidence", title: "证据采集", content: "证据详情...", data: {} },
      { key: "risk", title: "风险评估", content: "**高风险** 数据外泄", data: {} },
      { key: "summary", title: "总结", content: "总结内容...", data: {} },
    ],
    final_verdict: "confirmed_threat",
    risk_score: 85,
    severity: "high",
    version: 1,
    generated_by: null,
    generated_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading spinner when loading", () => {
    render(<ReportViewer report={null} loading={true} />);
    expect(screen.getByText("正在生成报告...")).toBeDefined();
  });

  it("shows placeholder when no report and not generating", () => {
    render(<ReportViewer report={null} loading={false} />);
    expect(screen.getByText("报告尚未生成")).toBeDefined();
  });

  it("shows generating message when event is REPORTING", () => {
    render(<ReportViewer report={null} loading={false} eventStatus="reporting" />);
    expect(screen.getByText("报告生成中，请稍候...")).toBeDefined();
  });

  it("renders report title and sections", () => {
    render(<ReportViewer report={mockReport} loading={false} />);
    expect(screen.getByText("数据外泄调查报告")).toBeDefined();
    expect(screen.getByText("事件概述")).toBeDefined();
    expect(screen.getByText("分诊结果")).toBeDefined();
    expect(screen.getByText("风险评估")).toBeDefined();
    expect(screen.getByText("总结")).toBeDefined();
  });

  it("shows template warning when generated_by=template", () => {
    render(
      <ReportViewer
        report={{ ...mockReport, generated_by: "template" }}
        loading={false}
      />,
    );
    expect(screen.getByText("模板生成（LLM 降级）")).toBeDefined();
  });

  it("renders markdown content", () => {
    render(<ReportViewer report={mockReport} loading={false} />);
    // Markdown bold should render as <strong>
    const strong = document.querySelector("strong");
    expect(strong).toBeTruthy();
    expect(strong?.textContent).toBe("高风险");
  });
});
