/** Report models — matching backend app/models/report.py + openapi.json */

export interface ReportSection {
  key: string;
  title: string;
  content: string;
  data: Record<string, unknown>;
}

export interface InvestigationReport {
  report_id: string;
  event_id: string;
  title: string;
  summary: string;
  sections: ReportSection[];
  final_verdict: string;
  risk_score: number;
  severity: string;
  version: number;
  generated_by: string | null;
  generated_at: string | null;
  updated_at: string | null;
}
