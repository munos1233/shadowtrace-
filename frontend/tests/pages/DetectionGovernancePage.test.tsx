/** DetectionGovernancePage tests. */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter } from "react-router-dom";
import DetectionGovernancePage, {
  DEFAULT_ARTIFACT_PATH,
} from "../../src/pages/DetectionGovernancePage";
import { ApiError } from "../../src/services/apiClient";
import type {
  DetectionCandidate,
  DetectionEvaluationArtifact,
  DetectionGovernanceDecision,
  DetectionPromotionRecord,
} from "../../src/types/detectionGovernance";

const mockGetArtifact = vi.fn();
const mockListCandidates = vi.fn();
const mockAssessEligibility = vi.fn();
const mockRecordDecision = vi.fn();
const mockListDecisions = vi.fn();
const mockRevoke = vi.fn();
const mockEvaluateGate = vi.fn();
const mockListPromotions = vi.fn();
const mockCreatePromotion = vi.fn();
const mockCanDecide = vi.fn(() => true);

vi.mock("../../src/services/detectionGovernanceApi", () => ({
  getEvaluationArtifactByPath: (...args: unknown[]) => mockGetArtifact(...args),
  listDetectionCandidates: (...args: unknown[]) => mockListCandidates(...args),
  assessEligibility: (...args: unknown[]) => mockAssessEligibility(...args),
  recordDecisionFromPath: (...args: unknown[]) => mockRecordDecision(...args),
  listGovernanceDecisions: (...args: unknown[]) => mockListDecisions(...args),
  revokeGovernanceDecision: (...args: unknown[]) => mockRevoke(...args),
  evaluatePromotionGate: (...args: unknown[]) => mockEvaluateGate(...args),
  listPromotions: (...args: unknown[]) => mockListPromotions(...args),
  createPromotion: (...args: unknown[]) => mockCreatePromotion(...args),
}));

vi.mock("../../src/config/auth", () => ({
  canDecideDetectionGovernance: () => mockCanDecide(),
}));

vi.mock("../../src/services/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../../src/services/apiClient")>(
    "../../src/services/apiClient",
  );
  return {
    ...actual,
    showApiErrorToast: () => {},
    setApiErrorToastHandler: () => {},
  };
});

function makeArtifact(
  overrides: Partial<DetectionEvaluationArtifact> = {},
): DetectionEvaluationArtifact {
  return {
    evaluation_id: "deval-demo",
    tenant_id: "tenant-detection-eval",
    dataset_id: "detection_shadow_v1",
    dataset_version: "2026.08.02",
    status: "completed",
    artifact_hash: "a".repeat(64),
    aggregates: {
      case_count: 5,
      pass_count: 4,
      fail_count: 0,
      pass_rate: 1,
    },
    gate: { verdict: "pass", reason_codes: [] },
    config: {
      candidate_refs: { package_id: "drpkg-det-dup-v1", package_version: 1 },
    },
    ...overrides,
  };
}

function makeCandidate(overrides: Partial<DetectionCandidate> = {}): DetectionCandidate {
  return {
    candidate_detection_id: "cdet-1",
    source_tenant_id: "tenant-detection-eval",
    detection_scope_id: "dscope-1",
    package_id: "drpkg-det-dup-v1",
    package_version: 1,
    rule_id: "rule-dup-count",
    rule_version: 1,
    operator: "event_count",
    severity: "medium",
    shadow_only: true,
    cutoff_at: "2026-08-01T15:30:00Z",
    matched_value: 3,
    ...overrides,
  };
}

function makeDecision(
  overrides: Partial<DetectionGovernanceDecision> = {},
): DetectionGovernanceDecision {
  return {
    decision_id: "dgov-1",
    schema_version: "1.0",
    tenant_id: "tenant-detection-eval",
    decision: "approve",
    candidate_binding: {},
    evaluation_binding: {},
    threshold_binding: {},
    binding_hash: "b".repeat(64),
    decision_hash: "c".repeat(64),
    policy_version: "issue125_v1",
    reviewer_subject: "approver",
    reviewer_roles: ["approver"],
    reason_codes: [],
    reason_note: "",
    decided_at: "2026-08-05T10:00:00Z",
    ...overrides,
  };
}

function makePromotion(
  overrides: Partial<DetectionPromotionRecord> = {},
): DetectionPromotionRecord {
  return {
    promotion_id: "dprom-1",
    tenant_id: "tenant-detection-eval",
    promotion_key: "pk-1",
    status: "completed",
    decision_id: "dgov-1",
    candidate_detection_id: "cdet-1",
    candidate_content_hash: "d".repeat(64),
    package_id: "drpkg-det-dup-v1",
    package_version: 1,
    package_content_hash: "e".repeat(64),
    detection_scope_id: "dscope-1",
    event_id: "evt-promoted",
    reason_codes: [],
    reason_message: "",
    ...overrides,
  };
}

function renderPage() {
  return render(
    <AntApp>
      <MemoryRouter>
        <DetectionGovernancePage />
      </MemoryRouter>
    </AntApp>,
  );
}

describe("DetectionGovernancePage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockCanDecide.mockReturnValue(true);
    mockGetArtifact.mockResolvedValue({
      data: { path: DEFAULT_ARTIFACT_PATH, artifact: makeArtifact() },
    });
    mockListCandidates.mockResolvedValue({ data: { total: 0, page: 1, page_size: 50, items: [] } });
    mockListDecisions.mockResolvedValue({ data: { total: 0, page: 1, page_size: 20, items: [] } });
    mockListPromotions.mockResolvedValue({ data: { total: 0, page: 1, page_size: 20, items: [] } });
    mockAssessEligibility.mockResolvedValue({
      data: { eligible: true, reason_codes: [], messages: [] },
    });
    mockEvaluateGate.mockResolvedValue({
      data: { allowed: false, reason_codes: ["no_active_approval"], messages: [] },
    });
    mockRecordDecision.mockResolvedValue({ data: makeDecision() });
    mockCreatePromotion.mockResolvedValue({
      data: {
        promotion_id: "dprom-1",
        status: "completed",
        record: makePromotion(),
      },
    });
  });

  it("loads the default artifact and shows aggregates", async () => {
    renderPage();
    expect(screen.getByText("影子治理")).toBeInTheDocument();
    expect(await screen.findByTestId("artifact-summary")).toBeInTheDocument();
    expect(mockGetArtifact).toHaveBeenCalledWith(DEFAULT_ARTIFACT_PATH);
    expect(screen.getByText("deval-demo")).toBeInTheDocument();
    expect(screen.getByText("tenant-detection-eval")).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
  });

  it("keeps the artifact when decision list is tenant-denied", async () => {
    mockListDecisions.mockRejectedValue(
      new ApiError({
        error_code: "not_found",
        error_message: "detection governance decision not found",
        details: { tenant_id: "tenant-detection-eval", reason: "tenant_scope_denied" },
      }),
    );
    renderPage();
    expect(await screen.findByTestId("artifact-summary")).toBeInTheDocument();
    expect(screen.getByTestId("related-load-error")).toHaveTextContent(
      "当前账号租户无权访问制品租户 tenant-detection-eval",
    );
    expect(screen.queryByText("制品加载失败")).not.toBeInTheDocument();
  });

  it("assesses eligibility", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId("artifact-summary");
    await user.click(screen.getByTestId("assess-eligibility"));
    expect(await screen.findByTestId("eligibility-result")).toHaveTextContent("具备治理资格");
    expect(screen.getByTestId("promotion-gate-result")).toHaveTextContent("升进门禁关闭");
  });

  it("blocks approve without threshold_manifest_path", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByTestId("artifact-summary");
    await user.clear(screen.getByLabelText("threshold_manifest_path"));
    await user.click(screen.getByTestId("approve-decision"));
    expect(mockRecordDecision).not.toHaveBeenCalled();
    expect(await screen.findByText("批准必须填写 threshold_manifest_path")).toBeInTheDocument();
  });

  it("hides write actions for analyst-only role", async () => {
    mockCanDecide.mockReturnValue(false);
    mockListCandidates.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 50, items: [makeCandidate()] },
    });
    renderPage();
    await screen.findByTestId("artifact-summary");
    expect(screen.queryByTestId("approve-decision")).not.toBeInTheDocument();
    expect(screen.queryByTestId("promote-cdet-1")).not.toBeInTheDocument();
    expect(screen.getByText(/仅可查看制品与决策/)).toBeInTheDocument();
  });

  it("hides write actions after 403", async () => {
    const user = userEvent.setup();
    mockListCandidates.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 50, items: [makeCandidate()] },
    });
    mockCreatePromotion.mockRejectedValue(
      new ApiError({
        error_code: "forbidden",
        error_message: "requires one of roles: approver",
      }),
    );
    renderPage();
    await user.click(await screen.findByTestId("promote-cdet-1"));
    await user.click(await screen.findByRole("button", { name: "升 进" }));
    await waitFor(() =>
      expect(screen.queryByTestId("promote-cdet-1")).not.toBeInTheDocument(),
    );
    expect(screen.getByText(/仅可查看制品与决策/)).toBeInTheDocument();
  });

  it("promotes a candidate and links the resulting event", async () => {
    const user = userEvent.setup();
    mockListCandidates.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 50, items: [makeCandidate()] },
    });
    mockListPromotions
      .mockResolvedValueOnce({ data: { total: 0, page: 1, page_size: 20, items: [] } })
      .mockResolvedValueOnce({
        data: { total: 1, page: 1, page_size: 20, items: [makePromotion()] },
      });
    renderPage();
    await user.click(await screen.findByTestId("promote-cdet-1"));
    await user.click(await screen.findByRole("button", { name: "升 进" }));
    await waitFor(() =>
      expect(mockCreatePromotion).toHaveBeenCalledWith({
        tenant_id: "tenant-detection-eval",
        candidate_detection_id: "cdet-1",
        artifact_path: DEFAULT_ARTIFACT_PATH,
      }),
    );
    expect(await screen.findByTestId("promotion-status-dprom-1")).toHaveTextContent("completed");
    const eventLink = await screen.findByTestId("promotion-event-dprom-1");
    expect(eventLink).toHaveAttribute("href", "/events/evt-promoted");
  });

  it("shows gate-closed error on promote", async () => {
    const user = userEvent.setup();
    mockListCandidates.mockResolvedValue({
      data: { total: 1, page: 1, page_size: 50, items: [makeCandidate()] },
    });
    mockCreatePromotion.mockRejectedValue(
      new ApiError({
        error_code: "validation_error",
        error_message: "promotion blocked: governance gate closed",
        details: { reason_codes: ["no_active_approval"] },
      }),
    );
    renderPage();
    await user.click(await screen.findByTestId("promote-cdet-1"));
    await user.click(await screen.findByRole("button", { name: "升 进" }));
    await waitFor(() => expect(mockCreatePromotion).toHaveBeenCalled());
    expect(
      await screen.findByText(/promotion blocked: governance gate closed/),
    ).toBeInTheDocument();
    expect(screen.getByTestId("promote-cdet-1")).toBeInTheDocument();
  });
});
