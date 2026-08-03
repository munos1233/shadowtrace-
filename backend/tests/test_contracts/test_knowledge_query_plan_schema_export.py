"""KnowledgeQueryPlan contract schema export tests (ISSUE-130 / #636 Phase A)."""

from __future__ import annotations

import json

from app.models import MODEL_REGISTRY
from app.models.knowledge_release import (
    KnowledgeFilterKind,
    KnowledgeQueryBudget,
    KnowledgeQueryPlan,
    KnowledgeQueryPlanHints,
    KnowledgeTypedFilter,
)


def test_knowledge_query_plan_models_are_registered() -> None:
    expected = {
        "KnowledgeQueryPlan",
        "KnowledgeQueryBudget",
        "KnowledgeQueryPlanHints",
        "KnowledgeQueryPlanValidationOutcome",
        "KnowledgeTypedFilter",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_knowledge_query_plan_schema_exports_core_fields() -> None:
    schema = KnowledgeQueryPlan.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    for field in (
        "tenant_id",
        "principal",
        "allowed_corpora",
        "typed_filters",
        "budget",
        "plan_hash",
        "schema_version",
    ):
        assert field in props


def test_knowledge_query_plan_golden_json_roundtrip() -> None:
    from datetime import UTC, datetime

    plan = KnowledgeQueryPlan(
        tenant_id="tenant-a",
        principal="investigation:test",
        corpus_id="attack_enterprise",
        kb_name="attack_kb",
        allowed_corpora=("attack_enterprise",),
        active_release_id="krel-test",
        embedding_release_id="mock-v1",
        typed_filters=(
            KnowledgeTypedFilter(
                kind=KnowledgeFilterKind.SOURCE_ID,
                value="mitre_attack_stix",
            ),
        ),
        budget=KnowledgeQueryBudget(top_k=3, max_candidates=12),
        trace_id="trace-schema",
        plan_hash="abc123",
        pinned_at=datetime.now(UTC),
    )
    golden = json.dumps(plan.model_dump(mode="json"), sort_keys=True)
    restored = KnowledgeQueryPlan.model_validate_json(golden)
    assert restored.corpus_id == plan.corpus_id
    assert restored.budget.top_k == 3


def test_knowledge_query_plan_hints_extra_forbid() -> None:
    schema = KnowledgeQueryPlanHints.model_json_schema(mode="serialization")
    assert schema.get("additionalProperties") is False
