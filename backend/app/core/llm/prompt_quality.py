"""Per-prompt_key LLM structured-output quality metrics (ISSUE-251).

Measures ``llm_invalid_json`` rate by ``prompt_key`` and compares against
demo thresholds. Does **not** add retries — prompt/schema hardening owns
the invalid-rate reduction; this module is observability + gate helpers.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm

# Structured JSON keys that remain high-invalid after ISSUE-239 empty-content
# recovery. Demo thresholds are deliberately above the hardened query_rewrite
# bar but below the round-2 baseline (~37% overall invalid among structured
# calls) so a regression is visible without false-failing noisy keys.
STRUCTURED_PROMPT_KEYS: frozenset[str] = frozenset(
    {
        "triage_extract",
        "plan_generate",
        "plan_revise",
        "risk_score",
        "storyline_generate",
        "response_plan",
        "query_rewrite",
    }
)

# Short demo/eval timeout for structured JSON keys (fast fail vs LLM_TIMEOUT=30).
STRUCTURED_PROMPT_TIMEOUT_SECONDS: float = 15.0

# Round-2 dynamic-eval baseline (ID-R2-005): overall success 27 / invalid 16.
# Per-key rates were not published; use conservative demo ceilings below that
# overall invalid share so post-hardening runs can assert improvement.
PROMPT_INVALID_RATE_DEMO_THRESHOLDS: dict[str, float] = {
    "query_rewrite": 0.10,
    "triage_extract": 0.30,
    "plan_generate": 0.30,
    "plan_revise": 0.30,
    "risk_score": 0.30,
    "storyline_generate": 0.30,
    "response_plan": 0.30,
}

# Error classes that count toward invalid JSON quality (ISSUE-240 taxonomy).
_INVALID_JSON_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "empty_content",
        "invalid_json",
        "schema_validation",
    }
)


class PromptKeyInvalidRate(BaseModel):
    """One prompt_key rollup for demo gates / eval comparison."""

    model_config = ConfigDict(extra="forbid")

    prompt_key: str
    total_calls: int = Field(ge=0)
    invalid_calls: int = Field(ge=0)
    invalid_rate: float = Field(ge=0.0, le=1.0)
    by_error_class: dict[str, int] = Field(default_factory=dict)
    demo_threshold: float | None = None
    within_demo_threshold: bool | None = None


class PromptKeyInvalidRateReport(BaseModel):
    """Multi-key report used by the eval comparison script."""

    model_config = ConfigDict(extra="forbid")

    window_minutes: int | None = None
    keys: list[PromptKeyInvalidRate] = Field(default_factory=list)
    all_within_demo_threshold: bool = True


@dataclass(frozen=True)
class _CallRow:
    prompt_key: str
    status: str
    error_class: str | None


def _as_call_row(row: Mapping[str, Any] | object) -> _CallRow:
    if isinstance(row, Mapping):
        prompt_key = str(row.get("prompt_key") or "").strip()
        status = str(row.get("status") or "").strip()
        raw_class = row.get("error_class")
        error_class = str(raw_class).strip() if isinstance(raw_class, str) and raw_class else None
        return _CallRow(prompt_key=prompt_key, status=status, error_class=error_class)
    prompt_key = str(getattr(row, "prompt_key", "") or "").strip()
    status = str(getattr(row, "status", "") or "").strip()
    raw_class = getattr(row, "error_class", None)
    error_class = str(raw_class).strip() if isinstance(raw_class, str) and raw_class else None
    return _CallRow(prompt_key=prompt_key, status=status, error_class=error_class)


def is_invalid_json_failure(*, status: str, error_class: str | None) -> bool:
    """True when a call should count toward prompt_key invalid rate.

    Prefers ISSUE-240 ``error_class`` when present so empty_content vs
    invalid_json vs schema_validation stay distinguishable; falls back to
    status == llm_invalid_json for legacy rows.
    """

    if error_class and error_class in _INVALID_JSON_ERROR_CLASSES:
        return True
    return status == "llm_invalid_json"


def compute_prompt_key_invalid_rates(
    rows: Iterable[Mapping[str, Any] | object],
    *,
    prompt_keys: Sequence[str] | None = None,
    thresholds: Mapping[str, float] | None = None,
) -> PromptKeyInvalidRateReport:
    """Compute invalid rates from in-memory audit rows (eval / unit tests)."""

    wanted = set(prompt_keys) if prompt_keys is not None else set(STRUCTURED_PROMPT_KEYS)
    threshold_map = dict(thresholds or PROMPT_INVALID_RATE_DEMO_THRESHOLDS)

    totals: Counter[str] = Counter()
    invalids: Counter[str] = Counter()
    class_counts: dict[str, Counter[str]] = {}

    for raw in rows:
        row = _as_call_row(raw)
        if not row.prompt_key or row.prompt_key not in wanted:
            continue
        totals[row.prompt_key] += 1
        if is_invalid_json_failure(status=row.status, error_class=row.error_class):
            invalids[row.prompt_key] += 1
            bucket = class_counts.setdefault(row.prompt_key, Counter())
            label = row.error_class or "invalid_json"
            bucket[label] += 1

    keys: list[PromptKeyInvalidRate] = []
    all_ok = True
    for prompt_key in sorted(wanted):
        total = int(totals.get(prompt_key, 0))
        invalid = int(invalids.get(prompt_key, 0))
        rate = (invalid / total) if total else 0.0
        threshold = threshold_map.get(prompt_key)
        within: bool | None
        if threshold is None or total == 0:
            within = None
        else:
            within = rate <= threshold
            if within is False:
                all_ok = False
        keys.append(
            PromptKeyInvalidRate(
                prompt_key=prompt_key,
                total_calls=total,
                invalid_calls=invalid,
                invalid_rate=rate,
                by_error_class=dict(class_counts.get(prompt_key, {})),
                demo_threshold=threshold,
                within_demo_threshold=within,
            )
        )

    return PromptKeyInvalidRateReport(
        keys=keys,
        all_within_demo_threshold=all_ok,
    )


async def aggregate_prompt_key_invalid_rates(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    window_minutes: int,
    prompt_keys: Sequence[str] | None = None,
    thresholds: Mapping[str, float] | None = None,
) -> PromptKeyInvalidRateReport:
    """SQL rollup of recent ``llm_call_log`` rows by prompt_key."""

    cutoff = datetime.now(UTC) - timedelta(minutes=max(int(window_minutes), 1))
    wanted = list(prompt_keys) if prompt_keys is not None else sorted(STRUCTURED_PROMPT_KEYS)
    async with session_factory() as session:
        result = await session.execute(
            select(
                orm.LLMCallLog.prompt_key,
                orm.LLMCallLog.status,
                orm.LLMCallLog.error_class,
            ).where(
                orm.LLMCallLog.created_at >= cutoff,
                orm.LLMCallLog.prompt_key.in_(wanted),
            )
        )
        rows = [
            {
                "prompt_key": prompt_key,
                "status": status,
                "error_class": error_class,
            }
            for prompt_key, status, error_class in result.all()
        ]
    report = compute_prompt_key_invalid_rates(
        rows,
        prompt_keys=wanted,
        thresholds=thresholds,
    )
    return report.model_copy(update={"window_minutes": int(window_minutes)})


__all__ = [
    "PROMPT_INVALID_RATE_DEMO_THRESHOLDS",
    "STRUCTURED_PROMPT_KEYS",
    "STRUCTURED_PROMPT_TIMEOUT_SECONDS",
    "PromptKeyInvalidRate",
    "PromptKeyInvalidRateReport",
    "aggregate_prompt_key_invalid_rates",
    "compute_prompt_key_invalid_rates",
    "is_invalid_json_failure",
]
