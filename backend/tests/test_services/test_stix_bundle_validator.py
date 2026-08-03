"""STIX bundle validation tests (ISSUE-128 / #634)."""

from __future__ import annotations

import copy

from app.services.stix_bundle_builder import build_attack_pattern, build_bundle_from_techniques_json
from app.services.stix_bundle_validator import validate_stix_bundle


def _minimal_pattern(technique_id: str = "T1078") -> dict:
    return build_attack_pattern(
        {
            "technique_id": technique_id,
            "technique_name": "Valid Accounts",
            "tactics": ["Initial Access"],
            "description": "desc",
            "detection": "detect",
        },
        attack_version="v15.1",
    )


def test_validate_accepts_minimal_bundle() -> None:
    pattern = _minimal_pattern()
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "x_shadowtrace_object_count": 1,
        "objects": [pattern],
    }
    result = validate_stix_bundle(bundle)
    assert result.ok
    assert result.attack_pattern_count == 1
    assert result.external_ids == ("T1078",)


def test_validate_rejects_bad_relationship_ref() -> None:
    pattern = _minimal_pattern()
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            pattern,
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--missing-ref",
                "relationship_type": "uses",
                "source_ref": pattern["id"],
                "target_ref": "attack-pattern--does-not-exist",
            },
        ],
    }
    result = validate_stix_bundle(bundle)
    assert not result.ok
    assert any("target_ref" in err for err in result.errors)


def test_validate_rejects_duplicate_external_id() -> None:
    first = _minimal_pattern("T1078")
    second = copy.deepcopy(first)
    second["id"] = "attack-pattern--duplicate"
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [first, second],
    }
    result = validate_stix_bundle(bundle)
    assert not result.ok
    assert any("duplicate external_id" in err for err in result.errors)


def test_builder_bundle_from_repo_json() -> None:
    from pathlib import Path

    data_file = (
        Path(__file__).resolve().parents[2].parent / "data" / "knowledge" / "attack_techniques.json"
    )
    bundle = build_bundle_from_techniques_json(data_file)
    result = validate_stix_bundle(bundle)
    assert result.ok
    assert result.attack_pattern_count >= 60
