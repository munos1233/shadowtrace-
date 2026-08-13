/** actionWritebackDisplay unit tests (ISSUE-331). */

import { describe, expect, it } from "vitest";
import {
  resolveActionWritebackDisplay,
  resolveWritebackReceiptDisplay,
} from "../../src/utils/actionWritebackDisplay";

describe("resolveActionWritebackDisplay", () => {
  it("does not treat required=true + applicable=false as confirmed writeback", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: false,
      writeback_status: null,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.label).toContain("不承担终态写回");
    expect(display.tone).toBe("neutral");
  });

  it("shows confirmed only when applicable and status confirmed", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: true,
      writeback_status: "confirmed",
    });
    expect(display.isConfirmedApplicableWriteback).toBe(true);
    expect(display.tone).toBe("success");
  });

  it("does not show success when required but status confirmed without applicable", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: false,
      writeback_status: "confirmed",
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.tone).toBe("neutral");
  });
});

describe("resolveWritebackReceiptDisplay", () => {
  it("labels entity ACCEPTED as side-effect submit, not terminal done", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "accepted",
      intentKind: "entity_action_submit",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: false,
      },
      terminal: false,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.label).toBe("实体侧效应已提交");
    expect(display.tone).not.toBe("success");
  });

  it("allows green terminal confirmed for EVENT_STATUS_UPDATE row", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "confirmed",
      intentKind: "event_status_update",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: true,
      },
      terminal: true,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(true);
    expect(display.tone).toBe("success");
  });
});
