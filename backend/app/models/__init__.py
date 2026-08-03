"""Core data models package (ISSUE-002).

``MODEL_REGISTRY`` maps model name -> Pydantic model class for every model whose
JSON Schema is exported to ``contracts/schemas/``. The schema-export test compares
the registry key set against the exported file set (no brittle fixed count).
"""

from __future__ import annotations

from pydantic import BaseModel

from app.models.action import Action, ImpactAssessment
from app.models.agent_io import (
    AgentInput,
    AttackStoryline,
    AttackTechniqueMatch,
    CaseRecordSummary,
    Citation,
    CrossEventPath,
    EvidenceAgentInput,
    EvidenceOutput,
    ExecutionPlan,
    FpRuleCandidate,
    FpSimilarity,
    GraphAgentInput,
    GraphEdge,
    GraphNode,
    GraphOutput,
    InvestigationResult,
    MemoryAgentInput,
    MemoryOutput,
    PlanBudget,
    PlannerAgentInput,
    PlanStep,
    ProfileUpdate,
    RAGAgentInput,
    RAGOutput,
    ReportAgentInput,
    ResponseAgentInput,
    ResponsePlan,
    RiskAgentInput,
    RiskAssessment,
    RiskFactor,
    SimilarCaseSummary,
    StorylinePhase,
    SuperAgentInput,
    TimelineEntry,
    ToolAgentInput,
    TriageAgentInput,
    TriageResult,
    VerificationActionResult,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationListResult,
    BehaviorObservationProjectionFailureListResult,
    BehaviorObservationProjectionFailureQuery,
    BehaviorObservationProjectionFailureRecord,
    BehaviorObservationProvenance,
    BehaviorObservationQuery,
    BehaviorObservationSourceRef,
)
from app.models.context import EventContext
from app.models.decision_record import DecisionRecord, DecisionRecordCandidate
from app.models.decision_trace import DecisionTrace, DecisionTraceEntry, DecisionTraceSummary
from app.models.detection_scope import (
    DerivedDetectionConnectorBinding,
    DetectionScopeConnectorSet,
    DetectionScopeIdentity,
    DetectionScopeListResult,
    DetectionScopeQuery,
    DetectionScopeRevision,
    UpstreamConnectorMember,
)
from app.models.feature_snapshot import (
    DetectionFeatureBaseline,
    DetectionFeatureBaselineListResult,
    DetectionFeatureBaselineQuery,
    FeatureSnapshot,
    FeatureSnapshotListResult,
    FeatureSnapshotProvenance,
    FeatureSnapshotQuery,
    SeasonalityProfile,
)
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionCaseObservation,
    DetectionCaseResult,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionResourceMetrics,
    DetectionResourceSummary,
    DetectionTenantSafetyProbe,
    DetectionTenantSafetySummary,
)
from app.models.detection_governance import (
    DetectionGovernanceCandidateBinding,
    DetectionGovernanceDecision,
    DetectionGovernanceDecisionRequest,
    DetectionGovernanceEligibilityAssessment,
    DetectionGovernanceEvaluationBinding,
    DetectionGovernancePromotionGateResult,
    DetectionGovernanceRevokeRequest,
    DetectionGovernanceThresholdBinding,
)
from app.models.detection_rule import (
    CandidateDetection,
    CandidateDetectionListResult,
    CandidateDetectionProvenance,
    CandidateDetectionQuery,
    DetectionRuleDefinition,
    DetectionRulePackage,
    DetectionRulePackageListResult,
    DetectionRulePackageProvenance,
    DetectionRulePackageQuery,
    DetectionRuleRuntimeError,
    DetectionRuleRuntimeResult,
)
from app.models.evaluation_truth import (
    BenignSliceExpectation,
    EvaluationCaseTruth,
    EvaluationDatasetManifest,
    EvaluationTruthListResult,
    EvaluationTruthQuery,
    LabelProvenance,
    OperationalTruthMapping,
    ThreatSliceExpectation,
    TruthObservationRef,
    UnevaluableSliceExpectation,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationCaseResult,
    EvaluationGateResult,
    EvaluationQuarantinePolicy,
    EvaluationRunArtifact,
    EvaluationRunConfig,
    EvaluationThresholdManifest,
)
from app.models.evaluation_quality import (
    ConfidenceInterval,
    EvaluationQualityReport,
    GroupingScorerSummary,
    MetricDenominator,
    QualityMetricValue,
)
from app.models.embedding import (
    EmbeddingProviderHealth,
    EmbeddingRelease,
    VectorImportUpsert,
    VectorIndexSchema,
    VectorQueryContext,
    VectorQueryFilter,
    VectorRecordIdentity,
)
from app.models.knowledge_release import (
    KnowledgeQueryBudget,
    KnowledgeQueryPlan,
    KnowledgeQueryPlanHints,
    KnowledgeQueryPlanValidationOutcome,
    KnowledgeRelease,
    KnowledgeTypedFilter,
)
from app.models.shadow_run import (
    ShadowQueryArtifact,
    ShadowQueryPivotRequest,
    ShadowQueryPivotResult,
    ShadowRun,
    ShadowRunProvenance,
)
from app.models.playbook_release import (
    PlaybookActionTemplateSnapshot,
    PlaybookRef,
    ResolvedPlaybook,
)
from app.models.tool_call_grant import (
    BoundExecutionPrincipal,
    SafeToolProjection,
    ToolCallAttemptRecord,
    ToolCallGrant,
    ToolCallGrantScope,
)
from app.models.llm_provider import (
    LLMCallLogAggregate,
    LLMProbeStatus,
    LLMProviderHealth,
)
from app.models.disposition import (
    DispositionCommand,
    DispositionOutboxRecord,
    DispositionReceipt,
    RecordCompensationParams,
    RecordExecutionResultParams,
    SetEventDispositionParams,
    SourceObjectLocator,
    SubmitEntityActionParams,
    TargetDispositionResult,
    TargetWritebackResult,
    WritebackSummary,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.evidence import Evidence, EvidenceConflict, EvidenceGap
from app.models.execution import (
    ActionExecutionJob,
    ExecutionActionView,
    ExecutionSummary,
    TargetExecutionResult,
)
from app.models.report import InvestigationReport, ReportSection
from app.models.security_event import SecurityEvent
from app.models.source import (
    SourceAlert,
    SourceAsset,
    SourceConnector,
    SourceIncident,
    SourceLog,
    SourceObjectState,
    SourceReference,
)
from app.models.tool_meta import (
    CapabilityBindingEntry,
    CapabilityManifest,
    ProviderToolBinding,
    ToolMeta,
    ToolResult,
)

MODEL_REGISTRY: dict[str, type[BaseModel]] = {
    # entities
    "AccountEntity": AccountEntity,
    "HostEntity": HostEntity,
    "IPEntity": IPEntity,
    "DomainEntity": DomainEntity,
    "ProcessEntity": ProcessEntity,
    "FileEntity": FileEntity,
    "EntitySet": EntitySet,
    # source
    "SourceReference": SourceReference,
    "SourceObjectState": SourceObjectState,
    "SourceIncident": SourceIncident,
    "SourceAlert": SourceAlert,
    "SourceAsset": SourceAsset,
    "SourceLog": SourceLog,
    "SourceConnector": SourceConnector,
    # evidence
    "Evidence": Evidence,
    "EvidenceConflict": EvidenceConflict,
    "EvidenceGap": EvidenceGap,
    # execution
    "TargetExecutionResult": TargetExecutionResult,
    "ActionExecutionJob": ActionExecutionJob,
    "ExecutionActionView": ExecutionActionView,
    "ExecutionSummary": ExecutionSummary,
    # disposition
    "SourceObjectLocator": SourceObjectLocator,
    "SetEventDispositionParams": SetEventDispositionParams,
    "SubmitEntityActionParams": SubmitEntityActionParams,
    "RecordExecutionResultParams": RecordExecutionResultParams,
    "RecordCompensationParams": RecordCompensationParams,
    "TargetDispositionResult": TargetDispositionResult,
    "DispositionCommand": DispositionCommand,
    "TargetWritebackResult": TargetWritebackResult,
    "DispositionReceipt": DispositionReceipt,
    "DispositionOutboxRecord": DispositionOutboxRecord,
    "WritebackSummary": WritebackSummary,
    # action
    "ImpactAssessment": ImpactAssessment,
    "Action": Action,
    # report
    "ReportSection": ReportSection,
    "InvestigationReport": InvestigationReport,
    # security event + context
    "SecurityEvent": SecurityEvent,
    "EventContext": EventContext,
    # agent stage I/O (ISSUE-005)
    "AgentInput": AgentInput,
    "SuperAgentInput": SuperAgentInput,
    "PlannerAgentInput": PlannerAgentInput,
    "TriageAgentInput": TriageAgentInput,
    "EvidenceAgentInput": EvidenceAgentInput,
    "GraphAgentInput": GraphAgentInput,
    "RAGAgentInput": RAGAgentInput,
    "RiskAgentInput": RiskAgentInput,
    "ResponseAgentInput": ResponseAgentInput,
    "VerifyAgentInput": VerifyAgentInput,
    "ReportAgentInput": ReportAgentInput,
    "MemoryAgentInput": MemoryAgentInput,
    "ToolAgentInput": ToolAgentInput,
    "TriageResult": TriageResult,
    "EvidenceOutput": EvidenceOutput,
    "TimelineEntry": TimelineEntry,
    "StorylinePhase": StorylinePhase,
    "AttackStoryline": AttackStoryline,
    "GraphNode": GraphNode,
    "GraphEdge": GraphEdge,
    "GraphOutput": GraphOutput,
    "CrossEventPath": CrossEventPath,
    "AttackTechniqueMatch": AttackTechniqueMatch,
    "FpSimilarity": FpSimilarity,
    "SimilarCaseSummary": SimilarCaseSummary,
    "Citation": Citation,
    "RAGOutput": RAGOutput,
    "RiskFactor": RiskFactor,
    "RiskAssessment": RiskAssessment,
    "ResponsePlan": ResponsePlan,
    "VerificationActionResult": VerificationActionResult,
    "VerificationResult": VerificationResult,
    "CaseRecordSummary": CaseRecordSummary,
    "FpRuleCandidate": FpRuleCandidate,
    "ProfileUpdate": ProfileUpdate,
    "MemoryOutput": MemoryOutput,
    "PlanBudget": PlanBudget,
    "PlanStep": PlanStep,
    "ExecutionPlan": ExecutionPlan,
    "InvestigationResult": InvestigationResult,
    # tool contracts (ISSUE-006)
    "ToolMeta": ToolMeta,
    "ToolResult": ToolResult,
    "ProviderToolBinding": ProviderToolBinding,
    "CapabilityBindingEntry": CapabilityBindingEntry,
    "CapabilityManifest": CapabilityManifest,
    # decision trace (ISSUE-063)
    "DecisionTraceEntry": DecisionTraceEntry,
    "DecisionTraceSummary": DecisionTraceSummary,
    "DecisionTrace": DecisionTrace,
    # decision record (ISSUE-131)
    "DecisionRecord": DecisionRecord,
    "DecisionRecordCandidate": DecisionRecordCandidate,
    # detection scope (ISSUE-120 Phase 0)
    "DetectionScopeRevision": DetectionScopeRevision,
    "DetectionScopeIdentity": DetectionScopeIdentity,
    "DetectionScopeConnectorSet": DetectionScopeConnectorSet,
    "DetectionScopeQuery": DetectionScopeQuery,
    "DetectionScopeListResult": DetectionScopeListResult,
    "UpstreamConnectorMember": UpstreamConnectorMember,
    "DerivedDetectionConnectorBinding": DerivedDetectionConnectorBinding,
    # behavior observation (ISSUE-119 / #624)
    "BehaviorObservation": BehaviorObservation,
    "BehaviorObservationSourceRef": BehaviorObservationSourceRef,
    "BehaviorEntityRef": BehaviorEntityRef,
    "BehaviorObservationProvenance": BehaviorObservationProvenance,
    "BehaviorObservationQuery": BehaviorObservationQuery,
    "BehaviorObservationListResult": BehaviorObservationListResult,
    "BehaviorObservationProjectionFailureRecord": BehaviorObservationProjectionFailureRecord,
    "BehaviorObservationProjectionFailureQuery": BehaviorObservationProjectionFailureQuery,
    "BehaviorObservationProjectionFailureListResult": (
        BehaviorObservationProjectionFailureListResult
    ),
    # feature snapshot (ISSUE-120 Phase A/B)
    "FeatureSnapshot": FeatureSnapshot,
    "FeatureSnapshotProvenance": FeatureSnapshotProvenance,
    "FeatureSnapshotQuery": FeatureSnapshotQuery,
    "FeatureSnapshotListResult": FeatureSnapshotListResult,
    "DetectionFeatureBaseline": DetectionFeatureBaseline,
    "DetectionFeatureBaselineQuery": DetectionFeatureBaselineQuery,
    "DetectionFeatureBaselineListResult": DetectionFeatureBaselineListResult,
    "SeasonalityProfile": SeasonalityProfile,
    # detection rule runtime (ISSUE-121 / #626)
    "DetectionRulePackage": DetectionRulePackage,
    "DetectionRuleDefinition": DetectionRuleDefinition,
    "DetectionRulePackageProvenance": DetectionRulePackageProvenance,
    "DetectionRulePackageQuery": DetectionRulePackageQuery,
    "DetectionRulePackageListResult": DetectionRulePackageListResult,
    "CandidateDetection": CandidateDetection,
    "CandidateDetectionProvenance": CandidateDetectionProvenance,
    "CandidateDetectionQuery": CandidateDetectionQuery,
    "CandidateDetectionListResult": CandidateDetectionListResult,
    "DetectionRuleRuntimeError": DetectionRuleRuntimeError,
    "DetectionRuleRuntimeResult": DetectionRuleRuntimeResult,
    # detection evaluation artifact (ISSUE-126 / #631 Phase A)
    "DetectionEvaluationArtifact": DetectionEvaluationArtifact,
    "DetectionEvaluationConfig": DetectionEvaluationConfig,
    "DetectionCandidateRefs": DetectionCandidateRefs,
    "DetectionCaseObservation": DetectionCaseObservation,
    "DetectionCaseResult": DetectionCaseResult,
    "DetectionResourceMetrics": DetectionResourceMetrics,
    "DetectionResourceSummary": DetectionResourceSummary,
    "DetectionTenantSafetyProbe": DetectionTenantSafetyProbe,
    "DetectionTenantSafetySummary": DetectionTenantSafetySummary,
    # detection governance (ISSUE-125 / #630 Phase A)
    "DetectionGovernanceCandidateBinding": DetectionGovernanceCandidateBinding,
    "DetectionGovernanceDecision": DetectionGovernanceDecision,
    "DetectionGovernanceDecisionRequest": DetectionGovernanceDecisionRequest,
    "DetectionGovernanceEligibilityAssessment": DetectionGovernanceEligibilityAssessment,
    "DetectionGovernanceEvaluationBinding": DetectionGovernanceEvaluationBinding,
    "DetectionGovernancePromotionGateResult": DetectionGovernancePromotionGateResult,
    "DetectionGovernanceRevokeRequest": DetectionGovernanceRevokeRequest,
    "DetectionGovernanceThresholdBinding": DetectionGovernanceThresholdBinding,
    # evaluation truth (ISSUE-113)
    "EvaluationCaseTruth": EvaluationCaseTruth,
    "EvaluationDatasetManifest": EvaluationDatasetManifest,
    "EvaluationTruthListResult": EvaluationTruthListResult,
    "EvaluationTruthQuery": EvaluationTruthQuery,
    "LabelProvenance": LabelProvenance,
    "OperationalTruthMapping": OperationalTruthMapping,
    "ThreatSliceExpectation": ThreatSliceExpectation,
    "BenignSliceExpectation": BenignSliceExpectation,
    "UnevaluableSliceExpectation": UnevaluableSliceExpectation,
    "TruthObservationRef": TruthObservationRef,
    # evaluation quality report (ISSUE-113 Phase B)
    "EvaluationQualityReport": EvaluationQualityReport,
    "QualityMetricValue": QualityMetricValue,
    "MetricDenominator": MetricDenominator,
    "ConfidenceInterval": ConfidenceInterval,
    "GroupingScorerSummary": GroupingScorerSummary,
    # evaluation run artifact (ISSUE-105)
    "EvaluationRunArtifact": EvaluationRunArtifact,
    "EvaluationRunConfig": EvaluationRunConfig,
    "EvaluationCaseResult": EvaluationCaseResult,
    "EvaluationAggregateMetrics": EvaluationAggregateMetrics,
    "EvaluationGateResult": EvaluationGateResult,
    "EvaluationQuarantinePolicy": EvaluationQuarantinePolicy,
    "EvaluationThresholdManifest": EvaluationThresholdManifest,
    # embedding / vector contract (ISSUE-140)
    "EmbeddingRelease": EmbeddingRelease,
    "VectorRecordIdentity": VectorRecordIdentity,
    "VectorIndexSchema": VectorIndexSchema,
    "VectorQueryFilter": VectorQueryFilter,
    "VectorQueryContext": VectorQueryContext,
    "EmbeddingProviderHealth": EmbeddingProviderHealth,
    "VectorImportUpsert": VectorImportUpsert,
    # tool call grant (ISSUE-134)
    "ToolCallGrant": ToolCallGrant,
    "ToolCallGrantScope": ToolCallGrantScope,
    "BoundExecutionPrincipal": BoundExecutionPrincipal,
    "ToolCallAttemptRecord": ToolCallAttemptRecord,
    "SafeToolProjection": SafeToolProjection,
    # knowledge release registry (ISSUE-128, ISSUE-130 / #636)
    "KnowledgeRelease": KnowledgeRelease,
    "KnowledgeQueryPlan": KnowledgeQueryPlan,
    "KnowledgeQueryBudget": KnowledgeQueryBudget,
    "KnowledgeQueryPlanHints": KnowledgeQueryPlanHints,
    "KnowledgeQueryPlanValidationOutcome": KnowledgeQueryPlanValidationOutcome,
    "KnowledgeTypedFilter": KnowledgeTypedFilter,
    # playbook release registry (ISSUE-139 / #645)
    "PlaybookRef": PlaybookRef,
    "PlaybookActionTemplateSnapshot": PlaybookActionTemplateSnapshot,
    "ResolvedPlaybook": ResolvedPlaybook,
    # shadow query pivot (ISSUE-135 / #641)
    "ShadowRun": ShadowRun,
    "ShadowRunProvenance": ShadowRunProvenance,
    "ShadowQueryArtifact": ShadowQueryArtifact,
    "ShadowQueryPivotRequest": ShadowQueryPivotRequest,
    "ShadowQueryPivotResult": ShadowQueryPivotResult,
    # llm provider health (ISSUE-106 / #609)
    "LLMProviderHealth": LLMProviderHealth,
    "LLMProbeStatus": LLMProbeStatus,
    "LLMCallLogAggregate": LLMCallLogAggregate,
}

__all__ = ["MODEL_REGISTRY", *sorted(MODEL_REGISTRY.keys())]
