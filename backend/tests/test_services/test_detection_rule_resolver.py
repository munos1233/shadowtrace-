"""Unit tests for detection rule resolver and operators (ISSUE-121 / #626)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.errors import ValidationError
from app.detection.operators import default_operator_registry
from app.detection.operators.base import OperatorExecutionContext
from app.detection.operators.event_count import EventCountOperator
from app.detection.operators.event_match import EventMatchOperator
from app.detection.operators.value_count import ValueCountOperator
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_rule import (
    CandidateDetectionProvenance,
    DetectionRuleDefinition,
    DetectionRulePackageProvenance,
    DetectionRuleRuntimeState,
    MissingDataPolicy,
    RuleOperatorKind,
)
from app.models.feature_snapshot import (
    FEATURE_CONTRACT_VERSION,
    FeatureSnapshot,
    FeatureSnapshotProvenance,
    FeatureSnapshotStatus,
    FeatureWindowKind,
)
from app.services.detection_rule_resolver import (
    allowed_runtime_transition,
    build_candidate_detection,
    compile_rule_package,
)


def _observation(
    *,
    obs_id: str,
    observed_at: datetime,
    action: str = "create_process",
    category: str = "process_create",
    entity_id: str = "10.0.0.10",
) -> BehaviorObservation:
    return BehaviorObservation(
        observation_id=obs_id,
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        source_ref=BehaviorObservationSourceRef(
            source_product="mock_xdr",
            connector_id="conn-a",
            source_kind="log",
            source_object_id=f"src-{obs_id}",
            source_object_type="edr",
            source_revision=1,
        ),
        observed_at=observed_at,
        ingested_at=observed_at,
        entity_refs=[BehaviorEntityRef(entity_type="ip", entity_id=entity_id, role="src")],
        action=action,
        category=category,
        detection_score=55.0,
        content_hash="a" * 64,
        observation_hash="b" * 64,
        idempotency_key=f"idem-{obs_id}",
        provenance=BehaviorObservationProvenance(source_record_id=f"rec-{obs_id}"),
    )


def _rule(
    *,
    operator: RuleOperatorKind,
    threshold: float = 1.0,
    match_criteria: dict | None = None,
    value_field: str | None = None,
) -> DetectionRuleDefinition:
    return DetectionRuleDefinition(
        rule_id="rule-test",
        rule_version=1,
        operator=operator,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id="dscope-test",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=threshold,
        severity="medium",
        required_fields=["action"],
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria=match_criteria or {"action": "create_process"},
        value_field=value_field,
        max_observation_scan=100,
    )


def test_default_operator_registry_contains_phase_a_operators() -> None:
    registry = default_operator_registry()
    assert registry.get(RuleOperatorKind.EVENT_MATCH.value).operator_kind == "event_match"
    assert registry.get(RuleOperatorKind.EVENT_COUNT.value).operator_kind == "event_count"
    assert registry.get(RuleOperatorKind.VALUE_COUNT.value).operator_kind == "value_count"


def test_compile_rule_package_rejects_unknown_operator() -> None:
    broken = DetectionRuleDefinition.model_construct(
        rule_id="rule-test",
        rule_version=1,
        operator="unknown_op",
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id="dscope-test",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    with pytest.raises(ValidationError, match="unsupported operator"):
        compile_rule_package(
            source_tenant_id="tenant-a",
            package_version=1,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=[broken],
            provenance=DetectionRulePackageProvenance(author="tester"),
        )


def test_compile_rejects_unknown_match_criteria_key() -> None:
    rule = _rule(operator=RuleOperatorKind.EVENT_MATCH).model_copy(
        update={"match_criteria": {"action": "create_process", "foo": "bar"}}
    )
    with pytest.raises(ValidationError, match="unsupported match_criteria key"):
        compile_rule_package(
            source_tenant_id="tenant-a",
            package_version=1,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=[rule],
            provenance=DetectionRulePackageProvenance(author="tester"),
        )


def test_compile_rule_package_is_deterministic() -> None:
    rule = _rule(operator=RuleOperatorKind.EVENT_COUNT, threshold=3)
    provenance = DetectionRulePackageProvenance(author="tester")
    first = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.DRAFT,
        rules=[rule],
        provenance=provenance,
    )
    second = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.DRAFT,
        rules=[rule],
        provenance=provenance,
    )
    assert first.content_hash == second.content_hash
    assert first.package_id == second.package_id


def test_candidate_detection_shadow_only_rejects_false() -> None:
    from app.models.detection_rule import CandidateDetection

    with pytest.raises(ValueError):
        CandidateDetection.model_validate(
            {
                "candidate_detection_id": "dcand-test",
                "source_tenant_id": "tenant-a",
                "detection_scope_id": "dscope-test",
                "package_id": "drpkg-test",
                "package_version": 1,
                "rule_id": "rule-test",
                "rule_version": 1,
                "operator": "event_match",
                "group_key": {"entity_type": "ip", "entity_id": "10.0.0.10"},
                "cutoff_at": datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC).isoformat(),
                "window_kind": "1h",
                "matched_value": 1.0,
                "severity": "medium",
                "shadow_only": False,
                "provenance": {"observation_ids": ["o1"]},
                "content_hash": "a" * 64,
                "idempotency_key": "idem-test",
            }
        )


def test_runtime_transitions_fail_closed() -> None:
    assert allowed_runtime_transition(
        DetectionRuleRuntimeState.DRAFT,
        DetectionRuleRuntimeState.VALIDATED,
    )
    assert not allowed_runtime_transition(
        DetectionRuleRuntimeState.DRAFT,
        DetectionRuleRuntimeState.SHADOW_ACTIVE,
    )
    assert allowed_runtime_transition(
        DetectionRuleRuntimeState.VALIDATED,
        DetectionRuleRuntimeState.SHADOW_ACTIVE,
    )


def test_event_match_operator_golden() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=30), action="other"),
    ]
    rule = _rule(operator=RuleOperatorKind.EVENT_MATCH, threshold=1)
    matches = EventMatchOperator().evaluate(
        rule,
        OperatorExecutionContext(
            source_tenant_id="tenant-a",
            cutoff_at=base,
            observations=observations,
            snapshots=[],
        ),
    )
    assert len(matches) == 1
    assert matches[0].matched_value == 1.0
    assert matches[0].observation_ids == ["o1"]


def test_event_count_operator_golden() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
    ]
    rule = _rule(operator=RuleOperatorKind.EVENT_COUNT, threshold=3, match_criteria={})
    matches = EventCountOperator().evaluate(
        rule,
        OperatorExecutionContext(
            source_tenant_id="tenant-a",
            cutoff_at=base,
            observations=observations,
            snapshots=[],
        ),
    )
    assert len(matches) == 1
    assert matches[0].matched_value == 3.0


def test_value_count_operator_skips_non_ready_snapshot() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    snapshot = FeatureSnapshot(
        snapshot_id="fsnap-test",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        window_start=base - timedelta(hours=1),
        window_end=base,
        cutoff_at=base,
        source_watermark=base,
        status=FeatureSnapshotStatus.INSUFFICIENT_HISTORY,
        features={},
        provenance=FeatureSnapshotProvenance(observation_count=0),
        content_hash="c" * 64,
        cache_key="c" * 64,
        idempotency_key="idem-snap",
    )
    rule = _rule(
        operator=RuleOperatorKind.VALUE_COUNT,
        threshold=5,
        value_field="observation_count",
        match_criteria={},
    )
    matches = ValueCountOperator().evaluate(
        rule,
        OperatorExecutionContext(
            source_tenant_id="tenant-a",
            cutoff_at=base,
            observations=[],
            snapshots=[snapshot],
        ),
    )
    assert matches == []


def test_candidate_detection_identity_is_deterministic() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    package = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.SHADOW_ACTIVE,
        rules=[_rule(operator=RuleOperatorKind.EVENT_MATCH)],
        provenance=DetectionRulePackageProvenance(author="tester"),
    )
    first = build_candidate_detection(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        package=package,
        rule=package.rules[0],
        cutoff_at=base,
        group_key={"entity_type": "ip", "entity_id": "10.0.0.10"},
        matched_value=1.0,
        provenance=CandidateDetectionProvenance(observation_ids=["o1"]),
    )
    second = build_candidate_detection(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        package=package,
        rule=package.rules[0],
        cutoff_at=base,
        group_key={"entity_type": "ip", "entity_id": "10.0.0.10"},
        matched_value=1.0,
        provenance=CandidateDetectionProvenance(observation_ids=["o1"]),
    )
    assert first.candidate_detection_id == second.candidate_detection_id
    assert first.content_hash == second.content_hash
    assert first.shadow_only is True


def test_candidate_identity_stable_when_evidence_differs() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    package = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.SHADOW_ACTIVE,
        rules=[_rule(operator=RuleOperatorKind.EVENT_MATCH)],
        provenance=DetectionRulePackageProvenance(author="tester"),
    )
    group_key = {"entity_type": "ip", "entity_id": "10.0.0.10"}
    first = build_candidate_detection(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        package=package,
        rule=package.rules[0],
        cutoff_at=base,
        group_key=group_key,
        matched_value=1.0,
        provenance=CandidateDetectionProvenance(observation_ids=["o1"]),
    )
    second = build_candidate_detection(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        package=package,
        rule=package.rules[0],
        cutoff_at=base,
        group_key=group_key,
        matched_value=2.0,
        provenance=CandidateDetectionProvenance(observation_ids=["o1", "o2"]),
    )
    assert first.candidate_detection_id == second.candidate_detection_id
    assert first.content_hash != second.content_hash


def test_dedupe_latest_snapshots_by_entity_keeps_highest_revision() -> None:
    from app.services.feature_snapshot_resolver import dedupe_latest_snapshots_by_entity

    base = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    rev1 = FeatureSnapshot(
        snapshot_id="fsnap-rev1",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        window_start=base - timedelta(hours=1),
        window_end=base,
        cutoff_at=base,
        source_watermark=base,
        status=FeatureSnapshotStatus.READY,
        features={"observation_count": 2},
        provenance=FeatureSnapshotProvenance(observation_count=2),
        content_hash="a" * 64,
        cache_key="a" * 64,
        idempotency_key="idem-rev1",
        revision=1,
    )
    rev2 = rev1.model_copy(
        update={
            "snapshot_id": "fsnap-rev2",
            "revision": 2,
            "features": {"observation_count": 4},
            "provenance": FeatureSnapshotProvenance(observation_count=4),
            "content_hash": "b" * 64,
            "cache_key": "b" * 64,
            "idempotency_key": "idem-rev2",
        }
    )
    deduped = dedupe_latest_snapshots_by_entity([rev1, rev2])
    assert len(deduped) == 1
    assert deduped[0].snapshot_id == "fsnap-rev2"
    assert deduped[0].features["observation_count"] == 4


def test_compile_rule_package_excludes_runtime_state_from_hash() -> None:
    rule = _rule(operator=RuleOperatorKind.EVENT_COUNT, threshold=3)
    provenance = DetectionRulePackageProvenance(author="tester")
    draft = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.DRAFT,
        rules=[rule],
        provenance=provenance,
    )
    validated = compile_rule_package(
        source_tenant_id="tenant-a",
        package_version=1,
        runtime_state=DetectionRuleRuntimeState.VALIDATED,
        rules=[rule],
        provenance=provenance,
    )
    assert draft.content_hash == validated.content_hash


def test_event_count_fail_on_missing_required_field() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observation = _observation(obs_id="o1", observed_at=base - timedelta(minutes=30))
    observation = observation.model_copy(update={"action": None})
    rule = _rule(
        operator=RuleOperatorKind.EVENT_COUNT,
        threshold=1,
        match_criteria={},
    )
    rule = rule.model_copy(update={"missing_data_policy": MissingDataPolicy.FAIL})
    with pytest.raises(ValidationError, match="missing required field action"):
        EventCountOperator().evaluate(
            rule,
            OperatorExecutionContext(
                source_tenant_id="tenant-a",
                cutoff_at=base,
                observations=[observation],
                snapshots=[],
            ),
        )


def test_compile_rejects_treat_as_zero_for_observation_operators() -> None:
    rule = _rule(operator=RuleOperatorKind.EVENT_COUNT, threshold=1, match_criteria={})
    rule = rule.model_copy(update={"missing_data_policy": MissingDataPolicy.TREAT_AS_ZERO})
    with pytest.raises(ValidationError, match="treat_as_zero"):
        compile_rule_package(
            source_tenant_id="tenant-a",
            package_version=1,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=[rule],
            provenance=DetectionRulePackageProvenance(author="tester"),
        )


def test_compile_rejects_observation_count_required_field_on_event_match() -> None:
    rule = _rule(operator=RuleOperatorKind.EVENT_MATCH).model_copy(
        update={"required_fields": ["observation_count"]},
    )
    with pytest.raises(ValidationError, match="observation_count required_field"):
        compile_rule_package(
            source_tenant_id="tenant-a",
            package_version=1,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=[rule],
            provenance=DetectionRulePackageProvenance(author="tester"),
        )


def test_event_count_cost_limit_fail_closed() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id=f"o{i}", observed_at=base - timedelta(minutes=i + 1)) for i in range(5)
    ]
    rule = _rule(operator=RuleOperatorKind.EVENT_COUNT, threshold=1, match_criteria={})
    rule = rule.model_copy(update={"max_observation_scan": 3})
    with pytest.raises(ValidationError, match="cost limit exceeded"):
        EventCountOperator().evaluate(
            rule,
            OperatorExecutionContext(
                source_tenant_id="tenant-a",
                cutoff_at=base,
                observations=observations,
                snapshots=[],
            ),
        )
