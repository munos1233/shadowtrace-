/** EventOverviewCard classification UI tests (ISSUE-209). */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import EventOverviewCard, {
  isLowConfidenceClassification,
} from "../../src/components/event/EventOverviewCard";
import { ApiError } from "../../src/services/apiClient";
import type { EventDetailResponse } from "../../src/types/event";

const mockPatch = vi.fn();
const mockCanRoles = vi.fn(() => ["analyst"]);

vi.mock("../../src/services/eventApi", () => ({
  patchEventClassification: (...args: unknown[]) => mockPatch(...args),
}));

vi.mock("../../src/config/auth", () => ({
  currentAuthRoles: () => mockCanRoles(),
}));

function makeDetail(
  overrides: Partial<EventDetailResponse["event"]> = {},
): EventDetailResponse {
  return {
    event: {
      event_id: "evt-209",
      event_type: "other",
      title: "Classification overview",
      description: "test",
      status: "new",
      severity: "medium",
      risk_score: 40,
      confidence: 0.5,
      final_verdict: "none",
      entities: {
        accounts: [],
        hosts: [],
        ips: [],
        domains: [],
        processes: [],
        files: [],
      },
      creation_source_ref: {
        source_id: "mock",
        source_type: "xdr",
        object_kind: "event",
        object_id: "obj-209",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-06T00:00:00Z",
      created_at: "2026-08-06T00:00:00Z",
      updated_at: "2026-08-06T00:00:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {},
      classification_source: "heuristic",
      ...overrides,
    },
    writeback_required: false,
    writeback_readiness: "not_required",
    writeback_overall_status: null,
    pending_writeback_count: 0,
  };
}

function renderCard(detail: EventDetailResponse, onRefresh = vi.fn()) {
  return render(
    <AntApp>
      <EventOverviewCard detail={detail} onRefresh={onRefresh} />
    </AntApp>,
  );
}

describe("isLowConfidenceClassification", () => {
  it("flags other / heuristic / llm_fallback", () => {
    expect(isLowConfidenceClassification("other", "source")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "heuristic")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "llm_fallback")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "source")).toBe(false);
    expect(isLowConfidenceClassification("account_anomaly", "human")).toBe(false);
  });
});

describe("EventOverviewCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCanRoles.mockReturnValue(["analyst"]);
    mockPatch.mockResolvedValue({
      data: {
        event_id: "evt-209",
        event_type: "data_exfiltration",
        classification_source: "human",
        previous_event_type: "other",
        reinvestigate_requested: false,
        reinvestigate_started: false,
        side_effects: [],
      },
    });
  });

  it("shows low-confidence chip and reclassify entry for analyst", () => {
    renderCard(makeDetail());
    expect(screen.getByTestId("low-confidence-chip")).toBeInTheDocument();
    expect(screen.getByTestId("classification-source-chip")).toHaveTextContent("启发式");
    expect(screen.getByTestId("reclassify-open")).toBeInTheDocument();
  });

  it("hides reclassify for non-analyst roles", () => {
    mockCanRoles.mockReturnValue(["approver"]);
    renderCard(makeDetail({ event_type: "account_anomaly", classification_source: "source" }));
    expect(screen.queryByTestId("reclassify-open")).not.toBeInTheDocument();
    expect(screen.queryByTestId("low-confidence-chip")).not.toBeInTheDocument();
  });

  it("submits trimmed reason and refreshes on success", async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    renderCard(makeDetail(), onRefresh);

    await user.click(screen.getByTestId("reclassify-open"));
    await user.type(screen.getByLabelText(/原因/), "  source mismatch  ");
    await user.click(screen.getByRole("button", { name: "保 存" }));

    await waitFor(() =>
      expect(mockPatch).toHaveBeenCalledWith("evt-209", {
        event_type: "other",
        reason: "source mismatch",
        reinvestigate: false,
      }),
    );
    await waitFor(() => expect(onRefresh).toHaveBeenCalled());
  });

  it("surfaces classification conflict errors", async () => {
    const user = userEvent.setup();
    mockPatch.mockRejectedValue(
      new ApiError({
        error_code: "classification_conflict_active_investigation",
        error_message: "classification cannot change while verifying",
      }),
    );
    renderCard(makeDetail());
    await user.click(screen.getByTestId("reclassify-open"));
    await user.type(screen.getByLabelText(/原因/), "blocked");
    await user.click(screen.getByRole("button", { name: "保 存" }));
    expect(
      await screen.findByText(/classification cannot change while verifying/),
    ).toBeInTheDocument();
  });
});
