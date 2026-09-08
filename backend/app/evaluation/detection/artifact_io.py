"""Confined evaluation artifact listing/loading for detection governance UI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.errors import ResourceNotFoundError, ValidationError
from app.evaluation.paths import repo_relative_manifest_path
from app.evaluation.threshold import EVALUATION_MANIFEST_ROOT, confine_threshold_manifest_path
from app.models.detection_evaluation import DetectionEvaluationArtifact

_SKIP_FILENAMES = frozenset({"threshold_manifest.json", "manifest.json", "case_bindings.json"})


def confine_evaluation_artifact_path(raw: str) -> Path:
    stripped = (raw or "").strip()
    if not stripped:
        raise ValidationError("evaluation artifact path is required")
    return confine_threshold_manifest_path(Path(stripped))


def load_evaluation_artifact(raw_path: str) -> tuple[DetectionEvaluationArtifact, str]:
    path = confine_evaluation_artifact_path(raw_path)
    if not path.is_file():
        raise ResourceNotFoundError(
            "evaluation artifact not found",
            details={"path": path.name},
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError("evaluation artifact is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValidationError("evaluation artifact must be a JSON object")
    artifact = DetectionEvaluationArtifact.model_validate(payload)
    relative = repo_relative_manifest_path(path)
    if relative.startswith("data/evaluation/"):
        relative = relative.removeprefix("data/evaluation/")
    return artifact, relative


def list_evaluation_artifact_summaries(root: str) -> list[dict[str, Any]]:
    directory = confine_evaluation_artifact_path(root)
    if not directory.is_dir():
        raise ResourceNotFoundError(
            "evaluation artifact root not found",
            details={"path": directory.name},
        )
    items: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.name in _SKIP_FILENAMES:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or "evaluation_id" not in payload:
                continue
            artifact = DetectionEvaluationArtifact.model_validate(payload)
        except Exception:
            continue
        relative = path.relative_to(EVALUATION_MANIFEST_ROOT).as_posix()
        gate = artifact.gate
        items.append(
            {
                "path": relative,
                "evaluation_id": artifact.evaluation_id,
                "tenant_id": artifact.tenant_id,
                "dataset_id": artifact.dataset_id,
                "dataset_version": artifact.dataset_version,
                "status": (
                    artifact.status.value
                    if hasattr(artifact.status, "value")
                    else str(artifact.status)
                ),
                "artifact_hash": artifact.artifact_hash,
                "gate_verdict": (
                    gate.verdict.value
                    if gate is not None and hasattr(gate.verdict, "value")
                    else None
                ),
                "case_count": artifact.aggregates.case_count,
                "pass_rate": artifact.aggregates.pass_rate,
            }
        )
    return items


__all__ = [
    "confine_evaluation_artifact_path",
    "list_evaluation_artifact_summaries",
    "load_evaluation_artifact",
]
