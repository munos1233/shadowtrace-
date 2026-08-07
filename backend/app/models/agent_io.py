"""Agent stage input/output schemas (ISSUE-005).

These models lock the data-passing contract between the 12 Agents named in
intro §4.4. Later Agent implementation Issues must not add or rename fields.
Nested structures reuse ISSUE-002 models (``Evidence``, ``Action``,
``EntitySet``, writeback enums) where applicable.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.action import Action
from app.models.entities import EntitySet
from app.models.enums import (
    EventStatus,
    EventType,
    FinalVerdict,
    QualityVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.evidence import Evidence, EvidenceConflict, EvidenceGap
from app.models.playbook_release import PlaybookRef

# --------------------------------------------------------------------------- #
# Agent-IO-local enumerations (not part of intro §4.6 DECLARED_ENUMS)
# --------------------------------------------------------------------------- #


class CollectionStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL_DONE = "partial_done"
    DEGRADED = "degraded"
    FAILED = "failed"


class StorylineGeneratedBy(StrEnum):
    LLM = "llm"
    RULE = "rule"


class StorylinePhaseName(StrEnum):
    INITIAL_ACCESS = "initial_access"
    COLLECTION = "collection"
    STAGING = "staging"
    EXFILTRATION = "exfiltration"
    POST_ACTION = "post_action"


class ScoringMode(StrEnum):
    LLM_AND_RULE = "llm_and_rule"
    RULE_ONLY = "rule_only"


class LlmAdmissibility(StrEnum):
    """Whether RiskAgent may merge LLM dimension scores (ISSUE-102 Phase B / #675)."""

    NOT_USED = "not_used"
    VALID = "valid"
    DEGRADED = "degraded"
    INVALID = "invalid"


class ResponsePlanGeneratedBy(StrEnum):
    LLM = "llm"
    TEMPLATE = "template"
    # ISSUE-205: plan re-derived from persisted Action rows by the report
    # input builder after the original plan payload was lost. Statuses are
    # carried over verbatim from the Action table — never re-interpreted.
    RECOVERED = "recovered"


class ReportPhaseStatus(StrEnum):
    """Execution state of the response/verification phases feeding ReportAgent.

    ISSUE-205: report chapters must distinguish "phase never ran in this
    investigation" (「本调查未执行…」) from "phase ran but no data is
    quotable" (incomplete) and "backing data exists but could not be read"
    (degraded/unavailable). Fail-closed default is NOT_EXECUTED; only the
    unified builder (``app/services/report_input_builder.py``) may promote
    the status based on evidence of execution.
    """

    NOT_EXECUTED = "not_executed"
    EXECUTED = "executed"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class EffectStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNVERIFIABLE = "unverifiable"


class VerificationOverallStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    WAITING = "waiting"
    MANUAL_RESOLUTION = "manual_resolution"


class VerificationPhase(StrEnum):
    EFFECT = "effect"
    DISPOSITION = "disposition"


class GraphRelationType(StrEnum):
    LOGGED_IN_FROM = "logged_in_from"
    LOGGED_IN_TO = "logged_in_to"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    CONNECTED_TO = "connected_to"
    RESOLVED = "resolved"
    REQUESTED = "requested"
    UPLOADED_TO = "uploaded_to"


AgentName = Literal[
    "super_agent",
    "planner_agent",
    "triage_agent",
    "evidence_agent",
    "graph_agent",
    "rag_agent",
    "risk_agent",
    "response_agent",
    "verify_agent",
    "report_agent",
    "memory_agent",
    "tool_agent",
]


# --------------------------------------------------------------------------- #
# Triage
# --------------------------------------------------------------------------- #


class EntityProvenanceRecord(BaseModel):
    """Structured source enrichment provenance (ISSUE-099, no raw payload)."""

    model_config = ConfigDict(extra="forbid")

    source_kind: str
    source_object_id: str
    connector_id: str | None = None
    entity_category: str | None = None


class EntityConflictRecord(BaseModel):
    """Source-priority entity merge conflict (ISSUE-099)."""

    model_config = ConfigDict(extra="forbid")

    entity_type: str
    semantic_key: str
    kept_source: str
    discarded_source: str
    reason: str = "source_priority"


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: EventType
    severity: Severity
    need_investigation: bool
    entities: EntitySet = Field(default_factory=EntitySet)
    ioc_list: list[str] = Field(default_factory=list)
    decision_summary: str = Field(default="", max_length=512)
    reasoning: str = Field(default="", deprecated=True)
    degraded: bool = False
    degradation_reasons: list[str] = Field(default_factory=list)
    entity_provenance_summary: list[EntityProvenanceRecord] = Field(default_factory=list)
    entity_conflicts: list[EntityConflictRecord] = Field(default_factory=list)
    entity_rejection_summary: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


class EvidenceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_list: list[Evidence] = Field(default_factory=list)
    conflicts: list[EvidenceConflict] = Field(default_factory=list)
    gaps: list[EvidenceGap] = Field(default_factory=list)
    success_sources: list[str] = Field(default_factory=list)
    failed_sources: list[str] = Field(default_factory=list)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    collection_status: CollectionStatus


# --------------------------------------------------------------------------- #
# Attack storyline
# --------------------------------------------------------------------------- #


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    description: str
    evidence_id: str
    technique_id: str | None = None
    severity_hint: Severity | None = None


class StorylineClaimRef(BaseModel):
    """Stable navigation id for an evidence-grounded storyline proposition (ISSUE-116)."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(..., min_length=1, max_length=128)
    proposition_kind: Literal["timeline_entry", "phase_summary"] = "timeline_entry"
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    schema_version: str = Field(default="1.0", min_length=1, max_length=16)
    ordinal: int = Field(default=0, ge=0)


class StorylineGroundingStatus(StrEnum):
    """How storyline claims are grounded to evidence (ISSUE-116 Phase B / ISSUE-244)."""

    EVIDENCE_GROUNDED = "evidence_grounded"
    LEGACY_EVIDENCE_GROUNDED = "legacy_evidence_grounded"
    CLAIM_REFS_UNAVAILABLE = "claim_refs_unavailable"
    # Empty phases / no bindable evidence_ids — must not claim evidence_grounded.
    UNGROUNDED = "ungrounded"


class StorylinePhase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase_order: int
    phase_name: StorylinePhaseName
    tactic: str | None = None
    narrative: str = ""
    entries: list[TimelineEntry] = Field(default_factory=list)


class AttackStoryline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storyline_id: str
    event_id: str
    narrative_summary: str
    phases: list[StorylinePhase] = Field(default_factory=list)
    generated_by: StorylineGeneratedBy
    schema_version: str = Field(default="1.0", min_length=1, max_length=16)
    claim_refs: list[StorylineClaimRef] = Field(default_factory=list)
    grounding_status: StorylineGroundingStatus = StorylineGroundingStatus.LEGACY_EVIDENCE_GROUNDED


# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    event_id: str
    entity_type: str
    entity_value: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str
    event_id: str
    source_node_id: str
    target_node_id: str
    relation_type: GraphRelationType
    evidence_id: str
    occurred_at: datetime | None = None


class CrossEventPath(BaseModel):
    """Cross-event association path discovered via Neo4j (ISSUE-083)."""

    model_config = ConfigDict(extra="forbid")

    path_id: str
    related_event_ids: list[str] = Field(default_factory=list)
    shared_entities: list[str] = Field(default_factory=list)
    path_nodes: list[str] = Field(default_factory=list)
    risk_hint: str = ""


class GraphSummaryFeature(BaseModel):
    """Evidence-bound structured graph feature for pre-risk scoring (ISSUE-116)."""

    model_config = ConfigDict(extra="forbid")

    feature_id: str = Field(..., min_length=1, max_length=128)
    feature_kind: Literal[
        "attack_path",
        "central_entity",
        "lateral_movement",
        "attack_stage",
    ]
    score_hint: float = Field(..., ge=0.0, le=100.0)
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    provenance: Literal["graph_edge", "graph_path", "graph_centrality"] = "graph_edge"


class GraphSummary(BaseModel):
    """Deterministic graph-derived features consumed by RiskAgent (ISSUE-116)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0", min_length=1, max_length=16)
    features: list[GraphSummaryFeature] = Field(default_factory=list)
    degraded: bool = False
    degraded_reason: str | None = Field(default=None, max_length=256)


class GraphOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    central_entities: list[str] = Field(default_factory=list)
    # Each candidate is a time-ordered chain of node_id values.
    attack_path_candidates: list[list[str]] = Field(default_factory=list)
    # Filled by AttackPathService when NEO4J_ENABLED; otherwise always [].
    cross_event_paths: list[CrossEventPath] = Field(default_factory=list)
    summary: GraphSummary | None = None
    degraded: bool = False
    degraded_reason: str | None = Field(default=None, max_length=256)


# --------------------------------------------------------------------------- #
# RAG
# --------------------------------------------------------------------------- #


class AttackTechniqueMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    match_confidence: float = Field(ge=0.0, le=1.0)
    citation_id: str


class FpSimilarity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_case_id: str | None = None
    matched_pattern: str | None = None


class SimilarCaseSummary(BaseModel):
    """Compact HistoryCase digest for RAG similar_cases (full model lands later)."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    event_type: EventType | None = None
    summary: str = ""
    final_verdict: FinalVerdict | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    score: float | None = Field(default=None, ge=0.0, le=1.0)


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    citation_id: str
    chunk_id: str
    kb_name: str
    quoted_text: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    corpus_id: str | None = None
    release_id: str | None = None
    object_id: str | None = None


class RAGOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_techniques: list[AttackTechniqueMatch] = Field(default_factory=list)
    fp_similarity: FpSimilarity = Field(default_factory=FpSimilarity)
    similar_cases: list[SimilarCaseSummary] = Field(default_factory=list)
    playbook_refs: list[PlaybookRef] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    knowledge_query_plan: dict[str, Any] | None = Field(
        default=None,
        description="Release-pinned query plans keyed by kb_name (attack_kb, playbook_kb)",
    )
    degraded: bool = False


# --------------------------------------------------------------------------- #
# Risk
# --------------------------------------------------------------------------- #


class RiskFactor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    factor_name: str
    weight: float = Field(ge=0.0, le=1.0)
    raw_score: float
    weighted_score: float
    reasoning: str = ""


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    possible_false_positive: bool = False
    scoring_mode: ScoringMode
    evidence_limited: bool = False
    severity_floor_applied: bool = False
    source_risk_baseline: int | None = Field(default=None, ge=0, le=100)
    source_scale_unnormalized: bool = False
    high_source_evidence_limited: bool = False
    llm_admissibility: LlmAdmissibility | None = None
    confidence_cap_version: str | None = None


# --------------------------------------------------------------------------- #
# Response
# --------------------------------------------------------------------------- #


class ResponsePlan(BaseModel):
    """Generated disposition plan.

    ``actions`` is a generation-time snapshot only. Approval / execution /
    verification stages must re-load each Action by ``action_id``; they must
    not rely on the embedded ``status`` field here.
    """

    model_config = ConfigDict(extra="forbid")

    plan_id: str
    actions: list[Action] = Field(default_factory=list)
    strategy_summary: str = ""
    generated_by: ResponsePlanGeneratedBy


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


class VerificationActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    effect_status: EffectStatus
    writeback_required: bool
    writeback_readiness: WritebackReadiness
    # Only the eight WritebackStatus values; null when no command exists or
    # writeback is not required. Never use not_required/unsupported as status.
    writeback_status: WritebackStatus | None = None
    writeback_ids: list[str] = Field(default_factory=list)
    verification_action_id: str | None = None
    detail: str | None = None
    # True when _finalize_verification_action() itself failed during
    # exception handling, leaving the verification Action in an unknown
    # state (potentially stuck as EXECUTING zombie).  Downstream consumers
    # should check this flag instead of parsing the detail string.
    # (ISSUE-060 review Nit-2)
    verification_action_dirty: bool = False
    # Which verification phase produced this result.  Phase 1 (effect)
    # verifies the entity-level effect of an IMMEDIATE action; phase 2
    # (disposition) evaluates writeback receipts after disposition
    # activation.  Consumers that route on effect_status alone should
    # also check this field to avoid misinterpreting a phase‑2
    # "effect_status=VERIFIED" (writeback receipt confirmed) as an
    # entity-effect verification.
    verification_phase: VerificationPhase | None = None
    # Confirmation evidence tier from the latest DispositionReceipt when
    # available (readback_verified, manual_confirmed, adapter_acknowledged, …).
    confirmation_evidence: str | None = None

    @model_validator(mode="after")
    def _writeback_fields_are_consistent(self) -> VerificationActionResult:
        if not self.writeback_required:
            if self.writeback_readiness != WritebackReadiness.NOT_REQUIRED:
                raise ValueError(
                    "writeback_required=false requires writeback_readiness=NOT_REQUIRED"
                )
            if self.writeback_status is not None:
                raise ValueError("writeback_required=false requires writeback_status=null")
        elif self.writeback_readiness == WritebackReadiness.NOT_REQUIRED:
            # UNVERIFIABLE means the verification tool was unavailable — the
            # business obligation (writeback_required) stays intact but we
            # cannot observe writeback readiness/status.  The rule in 方案
            # §4.5 item 6: "writeback_required 只表达业务义务，禁止由技术能力
            # 反向改写".
            #
            # SKIPPED deferred_pending_activation means the writeback
            # obligation exists at the event level but hasn't been activated
            # yet — phase 2 will discharge it.  The obligation must not be
            # dropped from the Phase 1 result.
            if self.effect_status not in (
                EffectStatus.UNVERIFIABLE,
                EffectStatus.SKIPPED,
            ):
                raise ValueError("writeback_required=true forbids writeback_readiness=NOT_REQUIRED")
        return self


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[VerificationActionResult] = Field(default_factory=list)
    overall_status: VerificationOverallStatus
    failed_actions: list[str] = Field(default_factory=list)
    failed_writebacks: list[str] = Field(default_factory=list)
    blocked_writebacks: list[str] = Field(default_factory=list)
    need_action_replan: bool = False
    need_writeback_recovery: bool = False
    need_manual_resolution: bool = False
    verification_phase: VerificationPhase
    # True when the VerificationResult was successfully persisted to
    # WorkingMemory; False when the write failed or working_memory was
    # unavailable.  Default is False — only VerifyAgent._write_verification_result
    # sets this to True after a successful write.  Callers can inspect this
    # to decide whether downstream consumers (e.g. the report generator) can
    # read verification_result from EventContext.
    wm_persisted: bool = False
    # action_ids whose action_verified SocketEvent publish failed.
    # Publish failures are non-fatal — the event bus is best-effort —
    # but callers may retry or alert on repeated failures.
    publish_failures: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _deferred_skipped_not_in_failed_actions(self) -> VerificationResult:
        # Unactivated POST_VERIFY deferred Actions are skipped with a fixed detail
        # and must never be treated as effect failures.
        deferred = {
            item.action_id
            for item in self.results
            if item.effect_status == EffectStatus.SKIPPED
            and item.detail == "deferred_pending_activation"
        }
        leaked = deferred.intersection(self.failed_actions)
        if leaked:
            raise ValueError(
                "deferred skipped actions must not appear in failed_actions: "
                + ", ".join(sorted(leaked))
            )
        return self


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #


class CaseRecordSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    event_id: str | None = None
    summary: str = ""
    archived: bool = False
    pending_review: bool = False
    review_id: str | None = None


class FpRuleCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_summary: str
    alert_signature: str
    confidence: float = Field(ge=0.0, le=1.0)
    source_event_id: str
    pending_review: bool = True
    review_id: str | None = None


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    entity_value: str
    event_id: str
    risk_score: int | None = Field(default=None, ge=0, le=100)
    behavior_tags: list[str] = Field(default_factory=list)
    pending_review: bool = False
    review_id: str | None = None


class MemoryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_records: list[CaseRecordSummary] = Field(default_factory=list)
    fp_rules: list[FpRuleCandidate] = Field(default_factory=list)
    profile_updates: list[ProfileUpdate] = Field(default_factory=list)
    sigma_drafts: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Planner
# --------------------------------------------------------------------------- #


class PlanBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tool_calls: int = 30
    max_llm_calls: int = 20
    max_duration_s: int = 300


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_order: int
    step_goal: str
    assigned_agent: AgentName
    required_tools: list[str] = Field(default_factory=list)
    success_criteria: str = ""


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    event_id: str
    steps: list[PlanStep] = Field(default_factory=list)
    budget: PlanBudget = Field(default_factory=PlanBudget)
    revision: int = 0
    revise_reason: str | None = None
    degraded: bool = False


# --------------------------------------------------------------------------- #
# SuperAgent investigation aggregate
# --------------------------------------------------------------------------- #


class InvestigationResult(BaseModel):
    """Final investigation summary produced by SuperAgent.

    ``final_status=CLOSED`` is a *local* EventStatus only — it must never be
    interpreted as proof that an external XDR disposition completed. Use the
    writeback_* fields (and ``external_unsynced``) for external sync state.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str
    final_status: EventStatus
    final_verdict: FinalVerdict = FinalVerdict.NONE
    escalated: bool = False
    external_unsynced: bool = False
    report_id: str | None = None
    writeback_required: bool = False
    writeback_readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED
    writeback_overall_status: WritebackStatus | None = None
    pending_writeback_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _writeback_null_when_not_required(self) -> InvestigationResult:
        if not self.writeback_required:
            if self.writeback_readiness != WritebackReadiness.NOT_REQUIRED:
                raise ValueError(
                    "writeback_required=false requires writeback_readiness=NOT_REQUIRED"
                )
            if self.writeback_overall_status is not None:
                raise ValueError("writeback_required=false requires writeback_overall_status=null")
        elif self.writeback_readiness == WritebackReadiness.NOT_REQUIRED:
            raise ValueError("writeback_required=true forbids writeback_readiness=NOT_REQUIRED")
        return self


# --------------------------------------------------------------------------- #
# Agent inputs (ISSUE-094 §1)
#
# Each of the 12 Agents (intro §4.4) gets a dedicated, strictly-validated
# input model instead of the generic ``AgentInput(event_id, data: dict)``
# envelope. Fields carry the *typed* upstream stage output(s) that Agent
# consumes; ``extra="forbid"`` rejects unknown/typo'd fields so a caller can
# never smuggle an untyped payload through the inter-agent boundary.
# The base ``AgentInput`` contains only ``event_id``; BaseAgent rejects that
# base type at runtime and accepts only the dedicated class bound to its name.
# --------------------------------------------------------------------------- #


class AgentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str


class SuperAgentInput(AgentInput):
    """Top-level investigation kickoff — the only Agent that starts from a bare event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    triggered_by: str = "ingestion"


class PlannerAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    triage_result: TriageResult | None = None
    previous_plan: ExecutionPlan | None = None
    revise_reason: str | None = None


class TriageAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    raw_event_summary: str = ""
    hint_entities: EntitySet = Field(default_factory=EntitySet)


class EvidenceAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    triage_result: TriageResult
    alert_text: str = ""
    plan_step_goal: str = ""
    required_tools: list[str] = Field(default_factory=list)
    execution_plan: dict[str, Any] | None = None


class GraphAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    evidence_output: EvidenceOutput


class RAGAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    triage_result: TriageResult
    evidence_output: EvidenceOutput | None = None
    tenant_id: str | None = None
    principal: str | None = None
    trace_id: str | None = None


class RiskAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    triage_result: TriageResult
    evidence_output: EvidenceOutput
    graph_output: GraphOutput | None = None
    rag_output: RAGOutput | None = None


class ResponseAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    risk_assessment: RiskAssessment
    evidence_output: EvidenceOutput | None = None


class VerifyAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    response_plan: ResponsePlan
    verification_phase: VerificationPhase


class ReportAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    evidence_output: EvidenceOutput
    risk_assessment: RiskAssessment
    response_plan: ResponsePlan | None = None
    verification_result: VerificationResult | None = None
    # ISSUE-062: when replan_count is exhausted the graph sets escalated=true;
    # ReportAgent must surface a mandatory human-escalation note in the report.
    escalated: bool = False
    replan_count: int = 0
    # ISSUE-205: phase-execution signals set by the unified report input
    # builder. Chapters must not silently render 「暂无…」 when a phase never
    # ran, and must not claim data when the backfill read failed — both are
    # explicit, distinguishable states (see ReportPhaseStatus).
    response_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED
    verification_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED
    # ISSUE-212: POST quality gate builds the report without writing until the
    # gate accepts (or force=true). Graph / agent paths keep the default True.
    persist_report: bool = True


class MemoryAgentInput(AgentInput):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    investigation_result: InvestigationResult


class ToolAgentInput(AgentInput):
    """ToolExecutor dispatch (ISSUE-006 owns actual execution).

    ``tool_params`` stays a dict because tool argument shapes are defined by
    the per-tool Pydantic schemas in ``app.tools.inputs``, not by this
    envelope — ToolAgent must validate ``tool_params`` against the named
    tool's own input model before dispatch.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str
    tool_name: str
    tool_params: dict[str, Any] = Field(default_factory=dict)
    action_id: str | None = None


# Mapping of the 12 Agents (intro §4.4) to their locked input model — mirrors
# the output-side mapping tests build against ``agent_io`` classes.
AGENT_INPUT_MODELS: dict[AgentName, type[AgentInput]] = {
    "super_agent": SuperAgentInput,
    "planner_agent": PlannerAgentInput,
    "triage_agent": TriageAgentInput,
    "evidence_agent": EvidenceAgentInput,
    "graph_agent": GraphAgentInput,
    "rag_agent": RAGAgentInput,
    "risk_agent": RiskAgentInput,
    "response_agent": ResponseAgentInput,
    "verify_agent": VerifyAgentInput,
    "report_agent": ReportAgentInput,
    "memory_agent": MemoryAgentInput,
    "tool_agent": ToolAgentInput,
}

AGENT_INPUT_BY_NAME = AGENT_INPUT_MODELS


# --------------------------------------------------------------------------- #
# Output quality evaluation (ISSUE-065)
# --------------------------------------------------------------------------- #


class OutputQualityScore(BaseModel):
    """Per-agent output quality score computed by OutputQualityEvaluator.

    Fields match intro §4.13 ``OutputQualityScore`` and §4.6 ``QualityVerdict``.
    """

    model_config = ConfigDict(extra="forbid")

    agent_name: str
    score: float = Field(ge=0.0, le=1.0)
    verdict: QualityVerdict
    metrics: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    evaluated_by: Literal["rule", "llm"]
