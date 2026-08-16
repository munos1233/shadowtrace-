import { describe, expect, it } from "vitest";
import { mergeWritebacks } from "../../src/hooks/useEventDetail";
import type { EventWriteback } from "../../src/hooks/useEventDetail";
import type { WritebackResponse } from "../../src/types/event";

describe("mergeWritebacks", () => {
  it("preserves snapshot simulated when API omits the field", () => {
    const context: EventWriteback[] = [
      {
        writeback_id: "wbk-1",
        disposition_id: "disp-1",
        action_id: "act-1",
        status: "confirmed",
        confirmation_evidence: "readback_verified",
        evidence_tier: "strong",
        provider_code: null,
        message_code: null,
        target_results: [],
        simulated: true,
        sequence: 1,
      },
    ];
    const api: WritebackResponse[] = [
      {
        writeback_id: "wbk-1",
        disposition_id: "disp-1",
        action_id: "act-1",
        status: "confirmed",
        confirmation_evidence: "readback_verified",
        evidence_tier: "strong",
        provider_code: null,
        message_code: null,
        target_results: [],
        simulated: undefined as unknown as boolean,
      },
    ];
    const merged = mergeWritebacks(context, api);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.simulated).toBe(true);
  });

  it("prefers API simulated when explicitly provided", () => {
    const context: EventWriteback[] = [
      {
        writeback_id: "wbk-2",
        disposition_id: "disp-2",
        action_id: "act-2",
        status: "confirmed",
        confirmation_evidence: "manual_confirmed",
        evidence_tier: "strong",
        provider_code: null,
        message_code: null,
        target_results: [],
        simulated: true,
      },
    ];
    const api: WritebackResponse[] = [
      {
        writeback_id: "wbk-2",
        disposition_id: "disp-2",
        action_id: "act-2",
        status: "confirmed",
        confirmation_evidence: "manual_confirmed",
        evidence_tier: "strong",
        provider_code: null,
        message_code: null,
        target_results: [],
        simulated: false,
      },
    ];
    const merged = mergeWritebacks(context, api);
    expect(merged[0]?.simulated).toBe(false);
  });
});
