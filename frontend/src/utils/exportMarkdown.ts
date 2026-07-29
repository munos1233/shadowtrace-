/** Markdown export utility (ISSUE-074). */

import type { InvestigationReport } from "../types/report";

/** 15 chapter keys matching backend ReportSectionBuilder.SECTION_KEYS (ISSUE-036). */
const CHAPTER_KEYS = [
  "overview", "severity_level", "risk_scoring", "involved_accounts",
  "involved_assets", "involved_processes", "involved_files",
  "involved_external_addresses", "evidence_chain", "attack_storyline",
  "attack_mapping", "executed_actions", "verification_results",
  "recommendations", "appendix_index",
] as const;

/** Build a complete Markdown document from report sections. */
export function buildReportMarkdown(report: InvestigationReport): string {
  const lines: string[] = [];
  lines.push(`# ${report.title}`);
  lines.push("");
  lines.push(`- **报告 ID**: ${report.report_id}`);
  lines.push(`- **事件 ID**: ${report.event_id}`);
  lines.push(`- **最终判定**: ${report.final_verdict}`);
  lines.push(`- **风险评分**: ${report.risk_score}`);
  lines.push(`- **严重程度**: ${report.severity}`);
  if (report.generated_by === "template") {
    lines.push("");
    lines.push("> ⚠️ 模板生成（LLM 降级）");
  }
  lines.push("");

  for (const key of CHAPTER_KEYS) {
    const section = report.sections.find((s) => s.key === key);
    if (!section || !section.content) continue;
    lines.push(`## ${section.title}`);
    lines.push("");
    lines.push(section.content);
    lines.push("");
  }

  return lines.join("\n");
}

/** Download a Markdown file for the report. */
export function downloadReportMarkdown(report: InvestigationReport): void {
  const md = buildReportMarkdown(report);
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `shadowtrace-report-${report.event_id}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export { CHAPTER_KEYS };
