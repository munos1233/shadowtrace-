"""RetrievalPipeline DI, lifecycle, and readiness probes (ISSUE-138)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ConfigurationError
from app.core.llm.base import BaseLLMClient
from app.db.session_provider import peek_session_provider
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.pipeline import RetrievalPipeline
from app.rag.query_rewriter import QueryRewriter
from app.rag.reranker import Reranker
from app.services.knowledge_store import KnowledgeStore

logger = logging.getLogger(__name__)

LoadedStatus = Literal["ready", "degraded", "unavailable"]


@dataclass(frozen=True, slots=True)
class LoadedRetrievalResources:
    status: LoadedStatus
    mode: str
    pipeline: RetrievalPipeline | None
    reasons: tuple[str, ...] = field(default_factory=tuple)
    session_pool: str = "unknown"
    embedding_mode: str = "unknown"
    embedding_release_id: str = ""


_resources: LoadedRetrievalResources | None = None
_resources_key: str | None = None


def _resources_cache_key(
    settings: Settings,
    *,
    session_factory: async_sessionmaker[AsyncSession] | None,
    llm_client: BaseLLMClient | None,
    embed_service: EmbeddingService | None,
) -> str:
    provider = peek_session_provider()
    pool = provider.pool_policy if provider is not None else "unknown"
    embed = embed_service or None
    release_id = embed.release.release_id if embed is not None else ""
    llm_mode = settings.llm_mode
    return "|".join(
        [
            settings.database_url,
            settings.embedding_mode,
            settings.embedding_release_id,
            settings.rerank_mode,
            str(settings.retrieval_fixture_fallback),
            pool,
            release_id,
            llm_mode,
            str(id(session_factory)),
            str(id(llm_client)),
            str(id(embed_service)),
        ]
    )


def _assert_fixture_policy(settings: Settings) -> None:
    if settings.app_env.strip().lower() == "production" and settings.retrieval_fixture_fallback:
        raise ConfigurationError(
            "app_env=production forbids RETRIEVAL_FIXTURE_FALLBACK=true",
            error_code="configuration_error",
            details={"violations": ["retrieval_fixture_fallback=true"]},
        )


def build_retrieval_pipeline(
    *,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    llm_client: BaseLLMClient,
    embed_service: EmbeddingService,
) -> RetrievalPipeline:
    tenant_isolation_strict = settings.app_env.strip().lower() == "production"
    store = KnowledgeStore(
        session_factory,
        embed_service,
        tenant_isolation_strict=tenant_isolation_strict,
    )
    return RetrievalPipeline(
        rewriter=QueryRewriter(llm_client, agent_name="RAGAgent"),
        retriever=HybridRetriever(store, embed_service),
        reranker=Reranker(settings),
    )


def get_loaded_retrieval_resources(
    *,
    settings: Settings | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    llm_client: BaseLLMClient | None = None,
    embed_service: EmbeddingService | None = None,
) -> LoadedRetrievalResources:
    """Return process-local retrieval resources, rebuilding when inputs change."""
    global _resources, _resources_key

    cfg = settings or get_settings()
    _assert_fixture_policy(cfg)

    if cfg.retrieval_fixture_fallback:
        provider = peek_session_provider()
        return LoadedRetrievalResources(
            status="degraded",
            mode="fixture",
            pipeline=None,
            reasons=("retrieval_fixture_fallback_enabled",),
            session_pool=provider.pool_policy if provider is not None else "unknown",
            embedding_mode=cfg.embedding_mode,
        )

    cache_key = _resources_cache_key(
        cfg,
        session_factory=session_factory,
        llm_client=llm_client,
        embed_service=embed_service,
    )
    if _resources is not None and _resources_key == cache_key:
        return _resources

    reasons: list[str] = []
    status: LoadedStatus = "ready"
    pipeline: RetrievalPipeline | None = None
    provider = peek_session_provider()
    session_pool = provider.pool_policy if provider is not None else "unknown"

    if session_factory is None or llm_client is None or embed_service is None:
        status = "unavailable"
        reasons.append("retrieval_dependencies_not_provided")
    else:
        try:
            pipeline = build_retrieval_pipeline(
                settings=cfg,
                session_factory=session_factory,
                llm_client=llm_client,
                embed_service=embed_service,
            )
        except Exception as exc:  # noqa: BLE001 — surface as unavailable, never fixture
            logger.warning("RetrievalPipeline build failed: %s", exc, exc_info=True)
            status = "unavailable"
            reasons.append("pipeline_build_failed")

    embed_release_id = embed_service.release.release_id if embed_service is not None else ""

    loaded = LoadedRetrievalResources(
        status=status,
        mode=cfg.embedding_mode,
        pipeline=pipeline,
        reasons=tuple(reasons),
        session_pool=session_pool,
        embedding_mode=cfg.embedding_mode,
        embedding_release_id=embed_release_id,
    )
    # Cache only successful builds so transient failures can reconnect (ISSUE-138).
    if pipeline is not None:
        _resources = loaded
        _resources_key = cache_key
    return loaded


def peek_loaded_retrieval_resources() -> LoadedRetrievalResources | None:
    return _resources


def reset_loaded_retrieval_resources() -> None:
    """Clear cached retrieval resources (tests / Celery task teardown)."""
    global _resources, _resources_key
    _resources = None
    _resources_key = None


async def _probe_corpus_status() -> str:
    """Return corpus readiness: ok | empty | error | unknown."""
    provider = peek_session_provider()
    if provider is None:
        return "unknown"
    try:
        async with provider.session_factory()() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM knowledge_chunk"))
            count = int(result.scalar_one())
            return "ok" if count > 0 else "empty"
    except Exception:  # noqa: BLE001 — health must never raise
        return "error"


def warmup_retrieval_resources() -> None:
    """Eagerly build retrieval pipeline so /health reports pipeline_attached."""
    cfg = get_settings()
    try:
        _assert_fixture_policy(cfg)
    except ConfigurationError:
        raise

    if cfg.retrieval_fixture_fallback:
        get_loaded_retrieval_resources(settings=cfg)
        return

    provider = peek_session_provider()
    if provider is None:
        return

    from app.api.v1.deps import _get_redis, _get_session_factory
    from app.core.embedding.factory import get_embedding_client
    from app.core.llm.factory import get_llm_client
    from app.services.budget_service import BudgetService

    session_factory = _get_session_factory()
    budget_service = BudgetService(redis=_get_redis(), settings=cfg)
    llm_client = get_llm_client(settings=cfg, budget_service=budget_service)
    embed_service = get_embedding_client(settings=cfg)
    get_loaded_retrieval_resources(
        settings=cfg,
        session_factory=session_factory,
        llm_client=llm_client,
        embed_service=embed_service,
    )


def _ensure_pipeline_probed_for_health(cfg: Settings) -> None:
    """Best-effort lazy build when startup warmup did not attach a pipeline."""
    if cfg.retrieval_fixture_fallback:
        return
    loaded = peek_loaded_retrieval_resources()
    if loaded is not None and loaded.pipeline is not None:
        return
    try:
        warmup_retrieval_resources()
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("loaded_resources health probe warmup skipped", exc_info=True)


async def check_loaded_resources(settings: Settings | None = None) -> dict[str, Any]:
    """Sanitized readiness for /health loaded_resources block."""
    cfg = settings or get_settings()
    _ensure_pipeline_probed_for_health(cfg)
    provider = peek_session_provider()
    postgres = "error"
    session_pool = "unknown"
    if provider is not None:
        session_pool = provider.pool_policy
        try:
            postgres = "ok" if await provider.ping_postgres() else "error"
        except Exception:  # noqa: BLE001 — health must never raise
            postgres = "error"

    from app.core.embedding.factory import get_embedding_client

    try:
        embedding_provider = (await get_embedding_client(settings=cfg).health_probe()).model_dump(
            mode="json"
        )
    except Exception:  # noqa: BLE001 — health must never raise
        embedding_provider = {
            "status": "error",
            "mode": cfg.embedding_mode,
            "release_id": "",
            "error_code": "embedding_provider_error",
        }
    embedding_ok = embedding_provider.get("status") == "ok"
    configured_release = (cfg.embedding_release_id or "").strip()
    actual_release = str(embedding_provider.get("release_id") or "").strip()
    release_mismatch = (
        bool(configured_release) and bool(actual_release) and configured_release != actual_release
    )

    corpus_status = await _probe_corpus_status()

    loaded = peek_loaded_retrieval_resources()
    pipeline_attached = loaded is not None and loaded.pipeline is not None

    status: LoadedStatus = "ready"
    reasons: list[str] = []
    if postgres != "ok":
        status = "unavailable"
        reasons.append("postgres_unavailable")
    if not embedding_ok:
        if status == "ready":
            status = "degraded"
        reasons.append("embedding_degraded")
    if release_mismatch:
        if status == "ready":
            status = "degraded"
        reasons.append("embedding_release_mismatch")
    if corpus_status == "error":
        if status == "ready":
            status = "degraded"
        reasons.append("corpus_error")
    elif corpus_status == "empty":
        if status == "ready":
            status = "degraded"
        reasons.append("corpus_empty")
    if cfg.retrieval_fixture_fallback:
        if status == "ready":
            status = "degraded"
        reasons.append("retrieval_fixture_fallback_enabled")
    elif not pipeline_attached:
        if status == "ready":
            status = "degraded"
        reasons.append("pipeline_unavailable")

    return {
        "status": status,
        "postgres": postgres,
        "session_pool": session_pool,
        "embedding_provider": embedding_provider,
        "corpus_status": corpus_status,
        "embedding_release_id": configured_release,
        "embedding_release_mismatch": release_mismatch,
        "pipeline_attached": pipeline_attached,
        "fixture_fallback_enabled": cfg.retrieval_fixture_fallback,
        "mode": cfg.embedding_mode,
        "reasons": reasons,
    }


__all__ = [
    "LoadedRetrievalResources",
    "build_retrieval_pipeline",
    "check_loaded_resources",
    "get_loaded_retrieval_resources",
    "peek_loaded_retrieval_resources",
    "reset_loaded_retrieval_resources",
    "warmup_retrieval_resources",
]
