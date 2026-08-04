"""Mock-only deterministic case replayer (ISSUE-105 / #608).

Never reads production Event/Detection/Disposition tables. Produces deterministic
observations derived from canonical truth + seed for scorer consumption.

Threat/benign slices still echo expectations. Security/knowledge slices route
through ``slice_replay`` adapters that simulate grant/retrieval decision paths.
"""

from __future__ import annotations

import hashlib

from app.evaluation.slice_replay import (
    replay_agentic_slice,
    replay_coordination_slice,
    replay_knowledge_slice,
    replay_security_slice,
)
from app.models.evaluation_run import CaseObservation
from app.models.evaluation_truth import (
    AgenticSliceExpectation,
    BenignSliceExpectation,
    CoordinationSliceExpectation,
    EvaluationCaseTruth,
    KnowledgeSliceExpectation,
    SecuritySliceExpectation,
    SliceType,
    ThreatSliceExpectation,
    UnevaluableSliceExpectation,
)


def _derive_case_nonce(case_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()
    return int(digest[:8], 16)


_ECHO_SLICES = frozenset(
    {
        SliceType.THREAT,
        SliceType.BENIGN,
        SliceType.UNEVALUABLE,
    }
)
_ADAPTER_SLICES = frozenset(
    {
        SliceType.SECURITY,
        SliceType.KNOWLEDGE,
        SliceType.AGENTIC,
        SliceType.COORDINATION,
    }
)


def resolve_replay_fidelity(truths: list[EvaluationCaseTruth]) -> str:
    """Label replay fidelity for a dataset run based on slice mix."""
    slice_types = {_slice_type(truth) for truth in truths}
    uses_echo = bool(slice_types & _ECHO_SLICES)
    uses_adapter = bool(slice_types & _ADAPTER_SLICES)
    if uses_echo and uses_adapter:
        return "mixed_echo_and_slice_adapter"
    if uses_adapter:
        return "slice_adapter_stub"
    return "echo_truth_stub"


def _slice_type(truth: EvaluationCaseTruth) -> SliceType:
    return SliceType(truth.slice_expectation.slice_type)


class MockDeterministicReplayer:
    """Deterministic mock replay for evaluation cases."""

    replay_mode = "mock_deterministic"

    def replay(self, truth: EvaluationCaseTruth, *, seed: int) -> CaseObservation:
        slice_type = SliceType(truth.slice_expectation.slice_type)
        nonce = _derive_case_nonce(truth.case_id, seed)

        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=False,
                replay_notes=f"unevaluable:{truth.slice_expectation.reason_code};seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, ThreatSliceExpectation):
            expectation = truth.slice_expectation
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=expectation.expected_case_label.value,
                observed_final_verdict=expectation.expected_final_verdict.value,
                observed_risk_score=expectation.expected_risk_score,
                observed_attack_techniques=list(expectation.expected_attack_techniques),
                observed_incident_group_id=expectation.expected_incident_group_id,
                observation_available=True,
                replay_notes=f"mock_deterministic:threat;seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, BenignSliceExpectation):
            benign_expectation = truth.slice_expectation
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observed_case_label=benign_expectation.expected_case_label.value,
                observed_final_verdict=benign_expectation.expected_final_verdict.value,
                observed_risk_score=benign_expectation.expected_risk_score,
                observed_attack_techniques=list(benign_expectation.expected_attack_techniques),
                observed_incident_group_id=benign_expectation.expected_incident_group_id,
                observation_available=True,
                replay_notes=f"mock_deterministic:benign;seed={seed};n={nonce:x}",
            )

        if isinstance(truth.slice_expectation, SecuritySliceExpectation):
            security_expectation = truth.slice_expectation
            fail = security_expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                security=replay_security_slice(security_expectation, fail=fail),
                replay_notes=(
                    f"slice_adapter:security:{security_expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        if isinstance(truth.slice_expectation, KnowledgeSliceExpectation):
            knowledge_expectation = truth.slice_expectation
            fail = knowledge_expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                knowledge=replay_knowledge_slice(
                    knowledge_expectation,
                    case_id=truth.case_id,
                    seed=seed,
                    fail=fail,
                ),
                replay_notes=(
                    f"slice_adapter:knowledge:{knowledge_expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        if isinstance(truth.slice_expectation, AgenticSliceExpectation):
            agentic_expectation = truth.slice_expectation
            fail = agentic_expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                agentic=replay_agentic_slice(agentic_expectation, fail=fail),
                replay_notes=(
                    f"slice_adapter:agentic:{agentic_expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        if isinstance(truth.slice_expectation, CoordinationSliceExpectation):
            coordination_expectation = truth.slice_expectation
            fail = coordination_expectation.replay_variant == "fail"
            return CaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=True,
                coordination=replay_coordination_slice(coordination_expectation, fail=fail),
                replay_notes=(
                    f"slice_adapter:coordination:{coordination_expectation.replay_variant};"
                    f"seed={seed};n={nonce:x}"
                ),
            )

        return CaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            observation_available=False,
            replay_notes=f"unsupported_slice_expectation;seed={seed};n={nonce:x}",
        )


__all__ = ["MockDeterministicReplayer", "resolve_replay_fidelity"]
