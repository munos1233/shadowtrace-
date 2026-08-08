"""Detection context snapshot contract schema export tests (ISSUE-127 / #633)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.api.v1 import schemas as api_schemas
from app.models.context import EventContext

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "contracts" / "schemas"
OPENAPI_PATH = REPO_ROOT / "contracts" / "openapi" / "openapi.json"

_STALE_STANDALONE_SCHEMAS = (
    "DetectionContextSnapshot.json",
    "DetectionContextSnapshotRef.json",
    "DetectionContextSnapshotSummary.json",
    "DetectionContextProjectionErrorSummary.json",
)


def _openapi_component_schema(name: str) -> dict:
    doc = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    components = doc.get("components", {}).get("schemas", {})
    assert name in components, f"missing OpenAPI component schema: {name}"
    return components[name]


@pytest.mark.parametrize("schema_file", _STALE_STANDALONE_SCHEMAS)
def test_detection_context_schemas_are_not_standalone_committed(schema_file: str) -> None:
    """Domain/API summary types export via OpenAPI only, not MODEL_REGISTRY schemas/."""
    assert not (SCHEMA_DIR / schema_file).is_file(), (
        f"stale standalone schema should not be committed: {schema_file}"
    )


def test_event_context_schema_includes_detection_context_snapshot_field() -> None:
    path = SCHEMA_DIR / "EventContext.json"
    assert path.is_file(), f"missing committed schema: {path}"
    committed = json.loads(path.read_text(encoding="utf-8"))
    current = EventContext.model_json_schema()
    assert committed == current


@pytest.mark.parametrize(
    ("model_cls", "component_name"),
    [
        (api_schemas.DetectionContextSnapshotSummary, "DetectionContextSnapshotSummary"),
        (
            api_schemas.DetectionContextProjectionErrorSummary,
            "DetectionContextProjectionErrorSummary",
        ),
    ],
)
def test_detection_context_api_summary_schemas_in_openapi_match_models(
    model_cls: type,
    component_name: str,
) -> None:
    committed = _openapi_component_schema(component_name)
    current = model_cls.model_json_schema(mode="serialization")
    assert committed["title"] == current["title"]
    assert set(committed.get("properties", {})) == set(current.get("properties", {}))
    assert committed.get("required") == current.get("required")
