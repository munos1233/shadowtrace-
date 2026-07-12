"""Baseline tool catalog (ISSUE-006).

``BASELINE_TOOL_METAS`` is the open set of intro §4.5 tools. Providers may append
additional tools at startup but must not overwrite a same-named tool that has a
different input Schema. Tests assert the *required* baseline set is present and
never lock the total count.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models.execution import ActionExecutionJob
from app.models.tool_meta import ToolMeta, ToolResult
from app.tools.inputs import TOOL_INPUT_MODELS
from app.tools.specs.query import QUERY_TOOL_METAS
from app.tools.specs.response import RESPONSE_ROLLBACK_MAP, RESPONSE_TOOL_METAS
from app.tools.specs.rollback import ROLLBACK_SOURCE_MAP, ROLLBACK_TOOL_METAS
from app.tools.specs.verification import VERIFICATION_TOOL_METAS

BASELINE_TOOL_METAS: list[ToolMeta] = [
    *QUERY_TOOL_METAS,
    *RESPONSE_TOOL_METAS,
    *VERIFICATION_TOOL_METAS,
    *ROLLBACK_TOOL_METAS,
]

BASELINE_TOOL_NAMES: frozenset[str] = frozenset(m.tool_name for m in BASELINE_TOOL_METAS)


def baseline_tool_index() -> dict[str, ToolMeta]:
    """Return tool_name -> ToolMeta for the baseline catalog."""
    return {m.tool_name: m for m in BASELINE_TOOL_METAS}


def merge_provider_tools(
    existing: dict[str, ToolMeta], additions: list[ToolMeta]
) -> dict[str, ToolMeta]:
    """Append Provider tools; refuse same-name overwrite with a different Schema."""
    merged = dict(existing)
    for meta in additions:
        prior = merged.get(meta.tool_name)
        if prior is not None and prior.input_schema != meta.input_schema:
            raise ValueError(
                f"refusing to overwrite tool {meta.tool_name!r} with a different input Schema"
            )
        if prior is None:
            merged[meta.tool_name] = meta
    return merged


def export_baseline_tool_schemas(out_dir: Path) -> list[Path]:
    """Write one JSON Schema per baseline tool into ``out_dir``.

    Each file contains the tool's input schema plus metadata pointers. Async
    response/rollback tools reference ``ActionExecutionJob`` as the job-shaped
    async output contract; the immediate call envelope is always ``ToolResult``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    job_schema = ActionExecutionJob.model_json_schema()
    result_schema = ToolResult.model_json_schema()

    for meta in BASELINE_TOOL_METAS:
        input_model = TOOL_INPUT_MODELS[meta.tool_name]
        doc = {
            "tool_name": meta.tool_name,
            "tool_category": meta.tool_category.value,
            "action_category": (meta.action_category.value if meta.action_category else None),
            "routing_kind": meta.routing_kind.value,
            "async_mode": meta.async_mode,
            "executable": meta.executable,
            "input_schema": input_model.model_json_schema(),
            "tool_result_schema": result_schema,
        }
        if meta.async_mode:
            doc["async_job_schema"] = job_schema
            doc["async_job_schema_ref"] = "ActionExecutionJob"
        path = out_dir / f"{meta.tool_name}.json"
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    return written


__all__ = [
    "BASELINE_TOOL_METAS",
    "BASELINE_TOOL_NAMES",
    "QUERY_TOOL_METAS",
    "RESPONSE_TOOL_METAS",
    "RESPONSE_ROLLBACK_MAP",
    "ROLLBACK_TOOL_METAS",
    "ROLLBACK_SOURCE_MAP",
    "VERIFICATION_TOOL_METAS",
    "baseline_tool_index",
    "export_baseline_tool_schemas",
    "merge_provider_tools",
]
