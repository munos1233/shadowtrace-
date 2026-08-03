"""Playbook release contract schema export tests (ISSUE-139 / #645)."""

from __future__ import annotations

import json

from app.models import MODEL_REGISTRY
from app.models.enums import ActionLevel
from app.models.knowledge_release import KnowledgeReleaseLifecycleState
from app.models.playbook_release import (
    PlaybookActionTemplateSnapshot,
    PlaybookRef,
    ResolvedPlaybook,
)


def test_playbook_contract_models_are_registered() -> None:
    expected = {
        "PlaybookRef",
        "PlaybookActionTemplateSnapshot",
        "ResolvedPlaybook",
    }
    assert expected <= set(MODEL_REGISTRY.keys())


def test_playbook_ref_schema_exports_immutable_fields() -> None:
    schema = PlaybookRef.model_json_schema(mode="serialization")
    props = schema.get("properties", {})
    for field in ("release_id", "content_hash", "bundle_content_hash", "playbook_id"):
        assert field in props


def test_playbook_ref_golden_json_roundtrip() -> None:
    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-test",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
        revision=1,
    )
    golden = json.dumps(ref.model_dump(mode="json"), sort_keys=True)
    restored = PlaybookRef.model_validate_json(golden)
    assert restored == ref


def test_resolved_playbook_schema_roundtrip() -> None:
    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-test",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    resolved = ResolvedPlaybook(
        ref=ref,
        release_version="v1",
        release_lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
        playbook_name="Test Playbook",
        step_count=2,
    )
    payload = resolved.model_dump(mode="json")
    restored = ResolvedPlaybook.model_validate(payload)
    assert restored.playbook_name == "Test Playbook"
    assert restored.step_count == 2


def test_action_template_snapshot_extra_forbid() -> None:
    schema = PlaybookActionTemplateSnapshot.model_json_schema(mode="serialization")
    assert schema.get("additionalProperties") is False
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    assert snapshot.tool_name == "block_ip"
