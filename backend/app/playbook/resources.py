"""PlaybookKB DI, lifecycle, and readiness probes (ISSUE-139 / #645 Phase A)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ConfigurationError
from app.db.session_provider import peek_session_provider
from app.services.playbook_kb_service import PlaybookKBService
from app.services.playbook_release_service import PlaybookReleaseService

logger = logging.getLogger(__name__)

LoadedStatus = Literal["ready", "degraded", "unavailable"]


@dataclass(frozen=True, slots=True)
class LoadedPlaybookResources:
    status: LoadedStatus
    mode: str
    playbook_kb_service: PlaybookKBService | None
    playbook_release_service: PlaybookReleaseService | None
    active_release_id: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)
    session_pool: str = "unknown"


_resources: LoadedPlaybookResources | None = None
_resources_key: str | None = None


def _resources_cache_key(
    settings: Settings,
    *,
    session_factory: async_sessionmaker[AsyncSession] | None,
    embed_service: EmbeddingService | None,
) -> str:
    provider = peek_session_provider()
    pool = provider.pool_policy if provider is not None else "unknown"
    embed = embed_service or None
    release_id = embed.release.release_id if embed is not None else ""
    return "|".join(
        [
            settings.database_url,
            settings.embedding_mode,
            settings.app_env,
            str(settings.playbook_fixture_fallback),
            str(settings.playbook_release_require_active),
            pool,
            release_id,
            str(id(session_factory)),
            str(id(embed_service)),
        ]
    )


def _assert_fixture_policy(settings: Settings) -> None:
    if settings.app_env.strip().lower() == "production" and settings.playbook_fixture_fallback:
        raise ConfigurationError(
            "app_env=production forbids PLAYBOOK_FIXTURE_FALLBACK=true",
            error_code="configuration_error",
            details={"violations": ["playbook_fixture_fallback=true"]},
        )


def build_playbook_services(
    *,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> tuple[PlaybookKBService, PlaybookReleaseService]:
    tenant_isolation_strict = settings.app_env.strip().lower() == "production"
    from app.services.knowledge_store import KnowledgeStore

    store = KnowledgeStore(
        session_factory,
        embed_service,
        tenant_isolation_strict=tenant_isolation_strict,
    )
    playbook_kb = PlaybookKBService(store, session_factory)
    release_service = PlaybookReleaseService(
        session_factory,
        playbook_kb=playbook_kb,
        settings=settings,
    )
    return playbook_kb, release_service


async def _probe_active_release(
    release_service: PlaybookReleaseService,
) -> tuple[str | None, tuple[str, ...]]:
    active = await release_service.get_active_release()
    if active is None:
        return None, ("no_active_playbook_release",)
    return active.release_id, ()


def get_loaded_playbook_resources(
    *,
    settings: Settings | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    embed_service: EmbeddingService | None = None,
) -> LoadedPlaybookResources:
    """Return process-local PlaybookKB resources, rebuilding when inputs change."""
    global _resources, _resources_key

    cfg = settings or get_settings()
    _assert_fixture_policy(cfg)

    if cfg.playbook_fixture_fallback:
        provider = peek_session_provider()
        if session_factory is None or embed_service is None:
            return LoadedPlaybookResources(
                status="degraded",
                mode="fixture",
                playbook_kb_service=None,
                playbook_release_service=None,
                reasons=("playbook_fixture_fallback_enabled",),
                session_pool=provider.pool_policy if provider is not None else "unknown",
            )

    if session_factory is None or embed_service is None:
        provider = peek_session_provider()
        return LoadedPlaybookResources(
            status="unavailable",
            mode="unconfigured",
            playbook_kb_service=None,
            playbook_release_service=None,
            reasons=("session_factory_or_embed_service_missing",),
            session_pool=provider.pool_policy if provider is not None else "unknown",
        )

    cache_key = _resources_cache_key(
        cfg, session_factory=session_factory, embed_service=embed_service
    )
    if _resources is not None and _resources_key == cache_key:
        return _resources

    if cfg.playbook_fixture_fallback:
        provider = peek_session_provider()
        playbook_kb, release_service = build_playbook_services(
            settings=cfg,
            session_factory=session_factory,
            embed_service=embed_service,
        )
        loaded = LoadedPlaybookResources(
            status="degraded",
            mode="fixture",
            playbook_kb_service=playbook_kb,
            playbook_release_service=release_service,
            reasons=("playbook_fixture_fallback_enabled",),
            session_pool=peek_session_provider().pool_policy
            if peek_session_provider()
            else "unknown",
        )
        _resources = loaded
        _resources_key = cache_key
        return loaded

    playbook_kb, release_service = build_playbook_services(
        settings=cfg,
        session_factory=session_factory,
        embed_service=embed_service,
    )
    loaded = LoadedPlaybookResources(
        status="ready",
        mode="production",
        playbook_kb_service=playbook_kb,
        playbook_release_service=release_service,
        session_pool=peek_session_provider().pool_policy if peek_session_provider() else "unknown",
    )
    _resources = loaded
    _resources_key = cache_key
    return loaded


async def probe_playbook_resources(
    loaded: LoadedPlaybookResources,
    *,
    settings: Settings | None = None,
) -> LoadedPlaybookResources:
    """Refresh readiness based on active release presence."""
    cfg = settings or get_settings()
    if loaded.playbook_release_service is None:
        return loaded

    release_id, reasons = await _probe_active_release(loaded.playbook_release_service)
    require_active = (
        cfg.app_env.strip().lower() == "production" or cfg.playbook_release_require_active
    )
    if require_active and release_id is None:
        return LoadedPlaybookResources(
            status="unavailable",
            mode=loaded.mode,
            playbook_kb_service=loaded.playbook_kb_service,
            playbook_release_service=loaded.playbook_release_service,
            active_release_id="",
            reasons=loaded.reasons + reasons,
            session_pool=loaded.session_pool,
        )
    if release_id is None:
        return LoadedPlaybookResources(
            status="degraded",
            mode=loaded.mode,
            playbook_kb_service=loaded.playbook_kb_service,
            playbook_release_service=loaded.playbook_release_service,
            active_release_id="",
            reasons=loaded.reasons + reasons,
            session_pool=loaded.session_pool,
        )
    return LoadedPlaybookResources(
        status="ready" if loaded.status != "degraded" else "degraded",
        mode=loaded.mode,
        playbook_kb_service=loaded.playbook_kb_service,
        playbook_release_service=loaded.playbook_release_service,
        active_release_id=release_id,
        reasons=loaded.reasons,
        session_pool=loaded.session_pool,
    )


async def check_playbook_resources(settings: Settings | None = None) -> dict[str, object]:
    """Sanitized readiness for /health playbook_resources block."""
    cfg = settings or get_settings()
    provider = peek_session_provider()
    postgres = "error"
    session_pool = "unknown"
    if provider is not None:
        session_pool = provider.pool_policy
        try:
            postgres = "ok" if await provider.ping_postgres() else "error"
        except Exception:  # noqa: BLE001 — health must never raise
            postgres = "error"

    if cfg.app_env.strip().lower() == "production" and cfg.playbook_fixture_fallback:
        return {
            "status": "unavailable",
            "mode": "production",
            "active_release_id": "",
            "postgres": postgres,
            "session_pool": session_pool,
            "fixture_fallback_enabled": True,
            "reasons": ["playbook_fixture_fallback_forbidden_in_production"],
        }

    if postgres != "ok" or provider is None:
        reasons: list[str] = []
        if provider is None:
            reasons.append("session_provider_missing")
        if postgres != "ok":
            reasons.append("postgres_unavailable")
        return {
            "status": "unavailable",
            "mode": "unconfigured",
            "active_release_id": "",
            "postgres": postgres,
            "session_pool": session_pool,
            "fixture_fallback_enabled": cfg.playbook_fixture_fallback,
            "reasons": reasons or ["playbook_unavailable"],
        }

    try:
        from app.core.embedding.factory import get_embedding_client

        embed_service = get_embedding_client(settings=cfg)
        session_factory = provider.session_factory()
        loaded = get_loaded_playbook_resources(
            settings=cfg,
            session_factory=session_factory,
            embed_service=embed_service,
        )
        probed = await probe_playbook_resources(loaded, settings=cfg)
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("playbook health probe failed", exc_info=True)
        return {
            "status": "unavailable",
            "mode": "error",
            "active_release_id": "",
            "postgres": postgres,
            "session_pool": session_pool,
            "fixture_fallback_enabled": cfg.playbook_fixture_fallback,
            "reasons": ["playbook_probe_failed"],
        }

    return {
        "status": probed.status,
        "mode": probed.mode,
        "active_release_id": probed.active_release_id,
        "postgres": postgres,
        "session_pool": session_pool,
        "fixture_fallback_enabled": cfg.playbook_fixture_fallback,
        "reasons": list(probed.reasons),
    }


def reset_playbook_resources_cache() -> None:
    global _resources, _resources_key
    _resources = None
    _resources_key = None


__all__ = [
    "LoadedPlaybookResources",
    "build_playbook_services",
    "check_playbook_resources",
    "get_loaded_playbook_resources",
    "probe_playbook_resources",
    "reset_playbook_resources_cache",
]
