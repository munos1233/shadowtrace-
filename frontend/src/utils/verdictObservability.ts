/** ISSUE-241: explain high risk_score + final_verdict=none demotion. */

export const EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT =
  "evidence_limited_demoted_from_confirmed_threat";
export const UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT =
  "unresolved_identity_endpoint_conflict";

const REASON_LABELS: Record<string, string> = {
  [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT]:
    "证据不足：已从 confirmed_threat 降级为 none（风险分≠威胁结论）",
  [UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT]:
    "身份/终端冲突未消解：IAM 无登录但 EDR 观察到该账号进程（iam_absent_but_edr_active）",
};

export function labelVerdictReasonCode(code: string): string {
  return REASON_LABELS[code] ?? code;
}

export function isHighRiskNoneMismatch(params: {
  riskScore?: number | null;
  finalVerdict?: string | null;
}): boolean {
  return (params.riskScore ?? 0) >= 70 && (params.finalVerdict ?? "none") === "none";
}

export function resolveVerdictDemotionCodes(params: {
  riskScore?: number | null;
  finalVerdict?: string | null;
  evidenceLimited?: boolean | null;
  verdictReasonCodes?: string[] | null;
}): string[] {
  const codes = (params.verdictReasonCodes ?? [])
    .map((code) => String(code).trim())
    .filter(Boolean);
  if (codes.length > 0) {
    return [...new Set(codes)];
  }
  if (
    isHighRiskNoneMismatch(params) &&
    params.evidenceLimited
  ) {
    return [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT];
  }
  return [];
}
