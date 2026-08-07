"""LLM configuration diagnostics, probe cache, and audit aggregation (ISSUE-106)."""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import LLMError
from app.core.llm.base import (
    LLMAuthError,
    LLMInvalidJSONError,
    LLMProviderError,
    LLMRateLimitedError,
    LLMTimeoutError,
)
from app.core.llm.url_utils import normalize_llm_base_url, redact_base_url
from app.db import models as orm
from app.models.llm_provider import (
    LLMCallLogAggregate,
    LLMProbeStatus,
    LLMProviderHealth,
    LLMProviderMode,
)

logger = logging.getLogger(__name__)

# cache_key -> (expires_at_monotonic, probe_status)
_PROBE_CACHE: dict[str, tuple[float, LLMProbeStatus]] = {}


def _api_key_fingerprint(api_key: str) -> str:
    raw = (api_key or "").strip()
    if not raw:
        return "none"
    return hashlib.sha256(raw.encode()).hexdigest()[:8]


def _probe_cache_key(settings: Settings) -> str:
    method = (settings.llm_probe_method or "chat").strip().lower()
    return "|".join(
        [
            settings.llm_mode.strip().lower(),
            normalize_llm_base_url(settings.llm_api_base_url),
            (settings.llm_primary_model or "").strip(),
            method,
            _api_key_fingerprint(settings.llm_api_key),
        ]
    )


def classify_llm_error(
    *,
    error_code: str | None = None,
    exc: Exception | None = None,
) -> tuple[str, str | None]:
    """Map provider failures to stable error classes for #607 / ISSUE-240."""
    if exc is not None:
        if isinstance(exc, LLMInvalidJSONError):
            return exc.error_class, exc.error_code
        if isinstance(exc, LLMAuthError):
            return "auth", exc.error_code
        if isinstance(exc, LLMRateLimitedError):
            return "rate_limit", exc.error_code
        if isinstance(exc, LLMTimeoutError):
            return "timeout", exc.error_code
        if isinstance(exc, LLMProviderError):
            return "provider", exc.error_code
        if isinstance(exc, LLMError):
            code = (exc.error_code or "").strip().lower()
            if code == "llm_invalid_json":
                return "invalid_json", exc.error_code
            if code == "llm_timeout":
                return "timeout", exc.error_code
            if code == "llm_auth_error":
                return "auth", exc.error_code
            if code == "llm_rate_limited":
                return "rate_limit", exc.error_code
            if code == "llm_config_error":
                return "config", exc.error_code
            return "provider", exc.error_code
        return "provider", getattr(exc, "error_code", None)

    code = (error_code or "").strip().lower()
    if code in {"llm_auth_error"}:
        return "auth", error_code
    if code in {"llm_rate_limited"}:
        return "rate_limit", error_code
    if code in {"llm_timeout"}:
        return "timeout", error_code
    if code in {"llm_config_error"}:
        return "config", error_code
    if code in {"llm_invalid_json"}:
        return "invalid_json", error_code
    if code in {"empty_content", "invalid_json", "schema_validation"}:
        return code, error_code
    if code:
        return "provider", error_code
    return "provider", None


def validate_openai_compatible_config(settings: Settings) -> str | None:
    """Return error_code when openai_compatible config is unusable."""
    if not normalize_llm_base_url(settings.llm_api_base_url):
        return "llm_config_error"
    if not (settings.llm_primary_model or "").strip():
        return "llm_config_error"
    return None


async def _aggregate_llm_call_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    window_minutes: int,
) -> LLMCallLogAggregate:
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    async with session_factory() as session:
        total = await session.scalar(
            select(func.count())
            .select_from(orm.LLMCallLog)
            .where(orm.LLMCallLog.created_at >= cutoff)
        )
        success = await session.scalar(
            select(func.count())
            .select_from(orm.LLMCallLog)
            .where(
                orm.LLMCallLog.created_at >= cutoff,
                orm.LLMCallLog.status == "success",
            )
        )
        last_row = await session.scalar(
            select(orm.LLMCallLog)
            .where(orm.LLMCallLog.created_at >= cutoff)
            .order_by(orm.LLMCallLog.created_at.desc(), orm.LLMCallLog.id.desc())
            .limit(1)
        )
    total_calls = int(total or 0)
    success_calls = int(success or 0)
    success_rate = (success_calls / total_calls) if total_calls else None
    last_status = last_row.status if last_row is not None else None
    last_error_class = None
    if last_row is not None and last_row.status != "success":
        # Prefer durable per-row taxonomy (ISSUE-240); fall back for legacy rows.
        persisted = getattr(last_row, "error_class", None)
        if isinstance(persisted, str) and persisted.strip():
            last_error_class = persisted.strip()
        else:
            last_error_class, _ = classify_llm_error(error_code=last_row.status)
    return LLMCallLogAggregate(
        window_minutes=window_minutes,
        total_calls=total_calls,
        success_calls=success_calls,
        success_rate=success_rate,
        last_status=last_status,
        last_error_class=last_error_class,
    )


async def _safe_aggregate_llm_call_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    window_minutes: int,
) -> LLMCallLogAggregate | None:
    """Best-effort audit rollup; failures must not break LLM health in mock mode."""
    try:
        return await _aggregate_llm_call_log(
            session_factory,
            window_minutes=window_minutes,
        )
    except Exception:
        logger.warning("llm_call_log aggregate unavailable", exc_info=True)
        return None


async def _run_openai_probe(settings: Settings) -> LLMProbeStatus:
    from app.providers.llm.openai_compatible import OpenAICompatibleLLMClient

    started = time.perf_counter()
    method = (settings.llm_probe_method or "chat").strip().lower()
    client = OpenAICompatibleLLMClient(
        base_url=settings.llm_api_base_url,
        api_key=settings.llm_api_key,
        primary_model=settings.llm_primary_model,
        timeout_seconds=settings.llm_timeout_seconds,
        audit_recorder=_NoopAuditRecorder(),
    )
    try:
        if method == "models":
            await client.probe_models()
        else:
            await client.probe_chat(model_name=settings.llm_primary_model)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return LLMProbeStatus(
            status="ok",
            probe_method=method,
            latency_ms=latency_ms,
        )
    except Exception as exc:  # noqa: BLE001 — probe must classify
        error_class, error_code = classify_llm_error(exc=exc)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.warning(
            "llm probe failed method=%s error_class=%s error_code=%s",
            method,
            error_class,
            error_code,
        )
        return LLMProbeStatus(
            status="error",
            probe_method=method,
            error_class=error_class,
            error_code=error_code,
            latency_ms=latency_ms,
        )
    finally:
        await client.aclose()


class _NoopAuditRecorder:
    async def record(self, _entry: object) -> None:
        return None


async def probe_llm_provider(
    settings: Settings,
    *,
    force: bool = False,
) -> LLMProbeStatus:
    """Optional live probe with TTL cache; mock mode never calls outbound."""
    mode = settings.llm_mode.strip().lower()
    if mode == LLMProviderMode.MOCK.value:
        return LLMProbeStatus(status="skipped", probe_method=None)
    if mode != LLMProviderMode.OPENAI_COMPATIBLE.value:
        return LLMProbeStatus(
            status="skipped",
            probe_method=None,
            error_class="config",
            error_code="llm_config_error",
        )
    config_error = validate_openai_compatible_config(settings)
    if config_error:
        error_class, _ = classify_llm_error(error_code=config_error)
        return LLMProbeStatus(
            status="error",
            probe_method=None,
            error_class=error_class,
            error_code=config_error,
        )
    if not settings.llm_probe_enabled and not force:
        return LLMProbeStatus(status="skipped", probe_method=None)

    cache_key = _probe_cache_key(settings)
    now = time.monotonic()
    if not force:
        cached_entry = _PROBE_CACHE.get(cache_key)
        if cached_entry is not None:
            expires_at, cached = cached_entry
            if now < expires_at:
                return cached

    probe_status = await _run_openai_probe(settings)
    _PROBE_CACHE[cache_key] = (
        now + max(int(settings.llm_probe_ttl_seconds), 1),
        probe_status,
    )
    return probe_status


async def build_llm_provider_health(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    *,
    force_probe: bool = False,
) -> LLMProviderHealth:
    """Assemble sanitized LLM health including optional probe + audit aggregate."""
    mode = settings.llm_mode.strip().lower()
    base_url_redacted = redact_base_url(settings.llm_api_base_url)
    probe_status = await probe_llm_provider(settings, force=force_probe)
    audit = await _safe_aggregate_llm_call_log(
        session_factory,
        window_minutes=int(settings.llm_audit_window_minutes),
    )

    status = "ok"
    if mode == LLMProviderMode.MOCK.value:
        pass
    elif mode == LLMProviderMode.OPENAI_COMPATIBLE.value:
        config_error = validate_openai_compatible_config(settings)
        if config_error or probe_status.status == "error":
            status = "degraded"
        elif probe_status.status not in {"ok", "skipped"}:
            status = "degraded"
    elif mode == LLMProviderMode.CUSTOM.value:
        status = "degraded"
        if probe_status.status == "skipped":
            probe_status = LLMProbeStatus(
                status="skipped",
                error_class="config",
                error_code="llm_custom_not_probed",
            )
    else:
        status = "error"
        probe_status = LLMProbeStatus(
            status="error",
            error_class="config",
            error_code="llm_config_error",
        )

    return LLMProviderHealth(
        status=status,
        mode=mode,
        base_url_redacted=base_url_redacted,
        primary_model=settings.llm_primary_model,
        probe_enabled=bool(settings.llm_probe_enabled),
        last_probe_status=probe_status,
        audit=audit,
    )


async def check_llm_provider(
    settings: Settings | None = None,
    *,
    force_probe: bool = False,
) -> dict[str, object]:
    """Health helper: never raises; returns JSON-safe payload."""
    cfg = settings or get_settings()
    try:
        from app.db.session import get_session_factory

        health = await build_llm_provider_health(
            cfg,
            get_session_factory(),
            force_probe=force_probe,
        )
        return health.model_dump(mode="json")
    except Exception:  # noqa: BLE001 — health must never raise
        logger.exception("llm health probe failed")
        mode = cfg.llm_mode.strip().lower()
        return {
            "status": "error",
            "mode": mode,
            "base_url_redacted": redact_base_url(cfg.llm_api_base_url),
            "primary_model": cfg.llm_primary_model,
            "probe_enabled": bool(cfg.llm_probe_enabled),
            "last_probe_status": {
                "status": "error",
                "error_class": "provider",
                "error_code": "llm_provider_error",
            },
            "audit": None,
        }


def reset_llm_probe_cache() -> None:
    """Clear cached probe status (tests)."""
    _PROBE_CACHE.clear()


__all__ = [
    "build_llm_provider_health",
    "check_llm_provider",
    "classify_llm_error",
    "normalize_llm_base_url",
    "probe_llm_provider",
    "redact_base_url",
    "reset_llm_probe_cache",
    "validate_openai_compatible_config",
]
