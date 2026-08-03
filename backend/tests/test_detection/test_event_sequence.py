"""Unit tests for event_sequence operator (ISSUE-123 / #628)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.errors import ValidationError
from app.detection.operators.base import OperatorExecutionContext
from app.detection.operators.event_sequence import (
    EventSequenceOperator,
    find_ordered_sequence_match,
)
from app.detection.sequences.releases import (
    GEO_SENSITIVE_SEQUENCE_V1,
    IDENTITY_EXFIL_SEQUENCE_V1,
    sequence_match_threshold,
)
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_rule import DetectionRuleDefinition, RuleOperatorKind
from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION, FeatureWindowKind


def _observation(
    *,
    obs_id: str,
    observed_at: datetime,
    action: str,
    category: str,
    entity_id: str = "account-1",
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
        entity_refs=[BehaviorEntityRef(entity_type="user", entity_id=entity_id, role="subject")],
        action=action,
        category=category,
        detection_score=55.0,
        content_hash="a" * 64,
        observation_hash="b" * 64,
        idempotency_key=f"idem-{obs_id}",
        provenance=BehaviorObservationProvenance(source_record_id=f"rec-{obs_id}"),
    )


def _identity_exfil_rule(**criteria_overrides: object) -> DetectionRuleDefinition:
    criteria = IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria()
    criteria.update(criteria_overrides)
    return DetectionRuleDefinition(
        rule_id="rule-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id="dscope-test",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=criteria,
    )


def test_find_ordered_sequence_match_positive() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    steps = [dict(step) for step in IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps]
    observations = [
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=50),
            action="login",
            category="identity",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=40),
            action="privilege_change",
            category="identity",
        ),
        _observation(
            obs_id="o3",
            observed_at=base - timedelta(minutes=30),
            action="bulk_read",
            category="data_access",
        ),
        _observation(
            obs_id="o4",
            observed_at=base - timedelta(minutes=20),
            action="egress",
            category="data_exfiltration",
        ),
    ]
    matched = find_ordered_sequence_match(observations, steps, max_step_gap_seconds=86_400)
    assert matched is not None
    assert [obs.observation_id for obs in matched] == ["o1", "o2", "o3", "o4"]


def test_find_ordered_sequence_match_out_of_order_input() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    steps = [dict(step) for step in IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps]
    observations = [
        _observation(
            obs_id="o4",
            observed_at=base - timedelta(minutes=20),
            action="egress",
            category="data_exfiltration",
        ),
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=50),
            action="login",
            category="identity",
        ),
        _observation(
            obs_id="o3",
            observed_at=base - timedelta(minutes=30),
            action="bulk_read",
            category="data_access",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=40),
            action="privilege_change",
            category="identity",
        ),
    ]
    matched = find_ordered_sequence_match(observations, steps, max_step_gap_seconds=86_400)
    assert matched is not None
    assert [obs.observation_id for obs in matched] == ["o1", "o2", "o3", "o4"]


def test_find_ordered_sequence_match_duplicate_ids_ignored() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    steps = [dict(step) for step in IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps[:2]]
    first = _observation(
        obs_id="dup",
        observed_at=base - timedelta(minutes=50),
        action="login",
        category="identity",
    )
    duplicate = _observation(
        obs_id="dup",
        observed_at=base - timedelta(minutes=45),
        action="login",
        category="identity",
    )
    second = _observation(
        obs_id="o2",
        observed_at=base - timedelta(minutes=40),
        action="privilege_change",
        category="identity",
    )
    matched = find_ordered_sequence_match(
        [duplicate, second, first],
        steps,
        max_step_gap_seconds=86_400,
    )
    assert matched is not None
    assert [obs.observation_id for obs in matched] == ["dup", "o2"]


def test_find_ordered_sequence_match_benign_partial_sequence_returns_none() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    steps = [dict(step) for step in IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps]
    observations = [
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=50),
            action="login",
            category="identity",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=40),
            action="privilege_change",
            category="identity",
        ),
        _observation(
            obs_id="o3",
            observed_at=base - timedelta(minutes=30),
            action="bulk_read",
            category="data_access",
        ),
    ]
    matched = find_ordered_sequence_match(observations, steps, max_step_gap_seconds=86_400)
    assert matched is None


def test_find_ordered_sequence_match_respects_max_step_gap() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    steps = [dict(step) for step in IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps[:2]]
    observations = [
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=50),
            action="login",
            category="identity",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=10),
            action="privilege_change",
            category="identity",
        ),
    ]
    assert find_ordered_sequence_match(observations, steps, max_step_gap_seconds=600) is None
    assert find_ordered_sequence_match(observations, steps, max_step_gap_seconds=3600) is not None


def test_event_sequence_operator_emits_typed_provenance() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=50),
            action="login",
            category="identity",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=40),
            action="privilege_change",
            category="identity",
        ),
        _observation(
            obs_id="o3",
            observed_at=base - timedelta(minutes=30),
            action="bulk_read",
            category="data_access",
        ),
        _observation(
            obs_id="o4",
            observed_at=base - timedelta(minutes=20),
            action="egress",
            category="data_exfiltration",
        ),
    ]
    rule = _identity_exfil_rule()
    matches = EventSequenceOperator().evaluate(
        rule,
        OperatorExecutionContext(
            source_tenant_id="tenant-a",
            cutoff_at=base,
            observations=observations,
            snapshots=[],
            window_start=base - timedelta(hours=1),
            window_end=base - timedelta(minutes=30),
        ),
    )
    assert len(matches) == 1
    match = matches[0]
    assert match.observation_ids == ["o1", "o2", "o3", "o4"]
    assert match.sequence_provenance["sequence_id"] == IDENTITY_EXFIL_SEQUENCE_V1.sequence_id
    assert match.sequence_provenance["sequence_hash"] == IDENTITY_EXFIL_SEQUENCE_V1.sequence_hash
    assert match.sequence_provenance["ordered_observation_ids"] == ["o1", "o2", "o3", "o4"]
    assert len(match.sequence_provenance["sequence_step_matches"]) == 4
    assert (
        "login→privilege_change→bulk_read→egress" in match.sequence_provenance["match_explanation"]
    )


def test_event_sequence_operator_hash_mismatch_fail_closed() -> None:
    rule = _identity_exfil_rule(sequence_hash="deadbeef" * 8)
    with pytest.raises(ValidationError, match="hash mismatch"):
        EventSequenceOperator().evaluate(
            rule,
            OperatorExecutionContext(
                source_tenant_id="tenant-a",
                cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
                observations=[],
                snapshots=[],
            ),
        )


def test_event_sequence_operator_step_matches_include_source_revision() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(
            obs_id="o1",
            observed_at=base - timedelta(minutes=40),
            action="anomalous_login",
            category="identity",
        ),
        _observation(
            obs_id="o2",
            observed_at=base - timedelta(minutes=30),
            action="sensitive_access",
            category="data_access",
        ),
    ]
    criteria = GEO_SENSITIVE_SEQUENCE_V1.as_match_criteria()
    rule = DetectionRuleDefinition(
        rule_id="rule-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id="dscope-test",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(GEO_SENSITIVE_SEQUENCE_V1),
        severity="high",
        match_criteria=criteria,
    )
    matches = EventSequenceOperator().evaluate(
        rule,
        OperatorExecutionContext(
            source_tenant_id="tenant-a",
            cutoff_at=base,
            observations=observations,
            snapshots=[],
        ),
    )
    assert len(matches) == 1
    for step_match in matches[0].sequence_provenance["sequence_step_matches"]:
        assert step_match["source_revision"] == 1
