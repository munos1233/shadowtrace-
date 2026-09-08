/** Turn stored report payloads into operator-facing markdown.

LLM report_generate sometimes echoes the JSON schema (`markdown string` /
`string`) into title, summary, and section bodies. The draft facts still sit
in leftover labeled lines and `section.data`; this module strips the schema
echo and rebuilds readable chapters for the current event.
*/

import type { Action } from "../types/action";
import type { EntitySet } from "../types/event";
import type { InvestigationReport, ReportSection } from "../types/report";

const SCHEMA_TOKEN = /^(markdown string|string|\.{3})$/i;

const FIELD_LABELS: Record<string, string> = {
  decision_brief: "研判摘要",
  evidence_summary: "证据摘要",
  actions_status_summary: "处置状态",
  evidence_limited_reason: "证据受限说明",
  content_sha256: "内容指纹",
};

const SEVERITY_LABELS: Record<string, string> = {
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
};

export interface ReportDisplayContext {
  eventTitle?: string | null;
  entities?: EntitySet | null;
  storylineSummary?: string | null;
  actions?: Action[];
}

export function isSchemaPlaceholder(text: string | null | undefined): boolean {
  return SCHEMA_TOKEN.test((text ?? "").trim());
}

export function stripSchemaPlaceholders(content: string): string {
  const lines: string[] = [];
  for (const raw of content.split("\n")) {
    const trimmed = raw.trim();
    if (!trimmed || SCHEMA_TOKEN.test(trimmed)) continue;
    if (/^markdown string\b/i.test(trimmed)) {
      const rest = trimmed.replace(/^markdown string\b/i, "").trim();
      if (rest && !SCHEMA_TOKEN.test(rest)) lines.push(rest);
      continue;
    }
    lines.push(raw);
  }
  return lines.join("\n").trim();
}

function formatLabeledMarkdown(content: string): string {
  const lines = content.split("\n").map((line) => line.trim()).filter(Boolean);
  const blocks: string[] = [];
  for (const line of lines) {
    const match = line.match(/^([a-z_]+):\s*(.*)$/i);
    if (!match) {
      blocks.push(line);
      continue;
    }
    const [, key, value] = match;
    const label = FIELD_LABELS[key] ?? key;
    if (key === "content_sha256") continue;
    blocks.push(`**${label}**`);
    blocks.push(value || "—");
  }
  return blocks.join("\n\n").trim();
}

function entityLabels(
  entities: EntitySet | null | undefined,
  group: keyof EntitySet,
): string[] {
  const items = entities?.[group] ?? [];
  return items.map((entity) => {
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
  }).filter(Boolean);
}

function bullets(values: string[], empty: string): string {
  if (values.length === 0) return empty;
  return values.map((value) => `- ${value}`).join("\n");
}

function formatDataFallback(
  section: ReportSection,
  report: InvestigationReport,
  context: ReportDisplayContext,
): string {
  const data = section.data ?? {};
  switch (section.key) {
    case "overview": {
      const parts = [
        data.decision_brief,
        data.evidence_summary,
        data.actions_status_summary,
      ].filter((item): item is string => typeof item === "string" && item.trim().length > 0);
      if (parts.length > 0) {
        return formatLabeledMarkdown(
          [
            `decision_brief: ${data.decision_brief ?? ""}`,
            `evidence_summary: ${data.evidence_summary ?? ""}`,
            `actions_status_summary: ${data.actions_status_summary ?? ""}`,
          ].join("\n"),
        );
      }
      return [
        `事件：${context.eventTitle || report.title}`,
        `类型：${report.final_verdict}`,
        `严重级别：${SEVERITY_LABELS[report.severity] ?? report.severity}`,
        `风险分：${report.risk_score}`,
      ].join("\n");
    }
    case "severity_level":
      return SEVERITY_LABELS[report.severity] ?? report.severity;
    case "risk_scoring": {
      const score =
        typeof data.risk_score === "number" ? data.risk_score : report.risk_score;
      const factors = Array.isArray(data.factors) ? data.factors : [];
      const factorLines = factors.flatMap((factor) => {
        if (!factor || typeof factor !== "object") return [];
        const row = factor as Record<string, unknown>;
        const name = String(row.factor_name ?? "factor");
        const weighted = row.weighted_score;
        return [`- ${name}：加权 ${weighted ?? "—"}`];
      });
      return [`风险分：**${score}**`, ...factorLines].join("\n");
    }
    case "involved_accounts":
      return bullets(entityLabels(context.entities, "accounts"), "暂无涉及账号");
    case "involved_assets": {
      const hosts = entityLabels(context.entities, "hosts");
      const ips = entityLabels(context.entities, "ips");
      return bullets([...hosts, ...ips], "暂无涉及资产");
    }
    case "involved_processes":
      return bullets(entityLabels(context.entities, "processes"), "暂无涉及进程");
    case "involved_files":
      return bullets(entityLabels(context.entities, "files"), "暂无涉及文件");
    case "involved_external_addresses": {
      const domains = entityLabels(context.entities, "domains");
      const ips = entityLabels(context.entities, "ips").filter((value) =>
        (context.entities?.ips ?? []).some(
          (ip) => (ip.address || ip.entity_id) === value && ip.scope === "external",
        ),
      );
      const values = domains.length > 0 || ips.length > 0 ? [...domains, ...ips] : domains;
      return bullets(values.length > 0 ? values : domains, "暂无涉及外部地址");
    }
    case "attack_storyline":
      return context.storylineSummary?.trim() || "故事线未写入报告正文，请查看「攻击故事线」页签。";
    case "executed_actions": {
      const summary =
        typeof data.actions_status_summary === "string" ? data.actions_status_summary : "";
      const fromActions = (context.actions ?? [])
        .filter((action) => action.action_category !== "system")
        .map((action) => `- ${action.tool_name}（${action.status}）`);
      const rows = Array.isArray(data.writeback_rows) ? data.writeback_rows : [];
      const fromData = rows.flatMap((row) => {
        if (!row || typeof row !== "object") return [];
        const item = row as Record<string, unknown>;
        const tool = item.tool_name ? String(item.tool_name) : null;
        return tool ? [`- ${tool}`] : [];
      });
      const lines = fromActions.length > 0 ? fromActions : fromData;
      return [summary, ...lines].filter(Boolean).join("\n") || "暂无已执行处置记录";
    }
    case "verification_results": {
      const status = data.overall_status;
      if (status === "success") return "验证结果：通过。处置效果已核对。";
      if (typeof status === "string" && status.trim()) return `验证结果：${status}`;
      return "暂无独立验证章节，请结合处置动作状态查看。";
    }
    case "recommendations":
      return "持续监控相关账号、主机与外联；已执行的封禁/隔离保持有效，必要时升级人工值守。";
    case "appendix_index": {
      const evidenceCount = data.evidence_count;
      const actionCount = data.response_action_count;
      const bits = [
        typeof evidenceCount === "number" ? `证据 ${evidenceCount} 条` : null,
        typeof actionCount === "number" ? `处置动作 ${actionCount} 个` : null,
      ].filter(Boolean);
      return bits.length > 0 ? bits.join("；") : "附录索引见事件详情其它页签。";
    }
    case "evidence_chain":
      return typeof data.evidence_summary === "string"
        ? data.evidence_summary
        : "证据链详见「证据」页签。";
    case "attack_mapping":
      return context.storylineSummary?.trim()
        ? "攻击阶段映射见「攻击故事线」页签。"
        : "暂无攻击映射正文。";
    default:
      return "";
  }
}

export function displaySectionContent(
  section: ReportSection,
  report: InvestigationReport,
  context: ReportDisplayContext = {},
): string {
  const stripped = stripSchemaPlaceholders(section.content);
  if (stripped) return formatLabeledMarkdown(stripped);
  return formatDataFallback(section, report, context);
}

export function displayReportTitle(
  report: InvestigationReport,
  context: ReportDisplayContext = {},
): string {
  if (!isSchemaPlaceholder(report.title) && report.title.trim()) return report.title;
  return context.eventTitle?.trim() || "调查报告";
}

export function displayReportSummary(report: InvestigationReport): string {
  if (isSchemaPlaceholder(report.summary)) return "";
  return report.summary.trim();
}

export function prepareReportForDisplay(
  report: InvestigationReport,
  context: ReportDisplayContext = {},
): InvestigationReport {
  return {
    ...report,
    title: displayReportTitle(report, context),
    summary: displayReportSummary(report),
    sections: report.sections.map((section) => ({
      ...section,
      content: displaySectionContent(section, report, context),
    })),
  };
}
