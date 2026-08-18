import { describe, expect, it } from "vitest";
import {
  EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
  UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT,
  isHighRiskNoneMismatch,
  labelVerdictReasonCode,
  resolveVerdictDemotionCodes,
} from "../../src/utils/verdictObservability";

describe("verdictObservability", () => {
  it("detects high risk + none mismatch", () => {
    expect(
      isHighRiskNoneMismatch({ riskScore: 70, finalVerdict: "none" }),
    ).toBe(true);
    expect(
      isHighRiskNoneMismatch({ riskScore: 69, finalVerdict: "none" }),
    ).toBe(false);
    expect(
      isHighRiskNoneMismatch({
        riskScore: 90,
        finalVerdict: "confirmed_threat",
      }),
    ).toBe(false);
  });

  it("prefers explicit verdict_reason_codes", () => {
    expect(
      resolveVerdictDemotionCodes({
        riskScore: 70,
        finalVerdict: "none",
        evidenceLimited: true,
        verdictReasonCodes: [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
      }),
    ).toEqual([EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT]);
  });

  it("infers demotion code for evidence_limited high-risk none", () => {
    expect(
      resolveVerdictDemotionCodes({
        riskScore: 72,
        finalVerdict: "none",
        evidenceLimited: true,
      }),
    ).toEqual([EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT]);
  });

  it("labels known demotion code", () => {
    expect(
      labelVerdictReasonCode(EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT),
    ).toContain("证据不足");
  });

  it("labels unresolved identity/endpoint conflict", () => {
    expect(labelVerdictReasonCode(UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT)).toContain(
      "iam_absent_but_edr_active",
    );
  });
});
