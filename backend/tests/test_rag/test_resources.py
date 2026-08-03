"""RetrievalPipeline DI and lifecycle tests (ISSUE-138)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ConfigurationError
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.models.knowledge import RetrievedChunk
from app.rag.context import RetrievalContext
from app.rag.hybrid_retriever import HybridRetriever
from app.rag.pipeline import RetrievalPipeline
from app.rag.resources import (
    build_retrieval_pipeline,
    check_loaded_resources,
    get_loaded_retrieval_resources,
    peek_loaded_retrieval_resources,
    reset_loaded_retrieval_resources,
    warmup_retrieval_resources,
)
from app.services.knowledge_store import KnowledgeStore


@pytest.fixture(autouse=True)
def _clear_resources() -> None:
    reset_loaded_retrieval_resources()
    yield
    reset_loaded_retrieval_resources()


def test_production_settings_reject_fixture_fallback() -> None:
    with pytest.raises(ConfigurationError, match="retrieval_fixture_fallback"):
        Settings(
            app_env="production",
            simulation_enabled=False,
            source_mode="live_xdr",
            tool_mode="live",
            disposition_mode="live_xdr",
            disposition_adapter_kind="live",
            llm_mode="openai_compatible",
            embedding_mode="remote",
            retrieval_fixture_fallback=True,
        )


def test_fixture_fallback_skips_pipeline_in_non_production() -> None:
    settings = Settings(app_env="development", retrieval_fixture_fallback=True)
    loaded = get_loaded_retrieval_resources(settings=settings)
    assert loaded.pipeline is None
    assert loaded.mode == "fixture"
    assert loaded.status == "degraded"
    assert "retrieval_fixture_fallback_enabled" in loaded.reasons


def test_builds_pipeline_when_dependencies_provided() -> None:
    settings = Settings()
    session_factory = MagicMock(spec=async_sessionmaker[AsyncSession])
    llm = MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())
    embed = EmbeddingService(settings)

    loaded = get_loaded_retrieval_resources(
        settings=settings,
        session_factory=session_factory,
        llm_client=llm,
        embed_service=embed,
    )
    assert loaded.pipeline is not None
    assert loaded.status == "ready"


def test_missing_dependencies_mark_unavailable_without_fixture() -> None:
    loaded = get_loaded_retrieval_resources(settings=Settings())
    assert loaded.pipeline is None
    assert loaded.status == "unavailable"
    assert "retrieval_dependencies_not_provided" in loaded.reasons
    assert peek_loaded_retrieval_resources() is None


def test_build_failure_is_not_cached_and_retries() -> None:
    settings = Settings()
    session_factory = MagicMock(spec=async_sessionmaker[AsyncSession])
    llm = MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())
    embed = EmbeddingService(settings)
    calls = {"count": 0}
    real_build = build_retrieval_pipeline

    def _flaky_build(**kwargs: object) -> RetrievalPipeline:
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("transient pipeline build failure")
        return real_build(**kwargs)  # type: ignore[arg-type]

    with patch("app.rag.resources.build_retrieval_pipeline", side_effect=_flaky_build):
        first = get_loaded_retrieval_resources(
            settings=settings,
            session_factory=session_factory,
            llm_client=llm,
            embed_service=embed,
        )
        assert first.pipeline is None
        assert peek_loaded_retrieval_resources() is None

        second = get_loaded_retrieval_resources(
            settings=settings,
            session_factory=session_factory,
            llm_client=llm,
            embed_service=embed,
        )
    assert second.pipeline is not None
    assert second.status == "ready"
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_loaded_resources_health_probes_warmup_when_pipeline_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_loaded_retrieval_resources()
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    warmup_calls: list[bool] = []

    def _warmup() -> None:
        warmup_calls.append(True)
        get_loaded_retrieval_resources(
            settings=Settings(),
            session_factory=MagicMock(spec=async_sessionmaker[AsyncSession]),
            llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
            embed_service=EmbeddingService(Settings()),
        )

    monkeypatch.setattr("app.rag.resources.warmup_retrieval_resources", _warmup)
    with (
        patch(
            "app.rag.resources.peek_session_provider",
            return_value=mock_provider,
        ),
        patch(
            "app.rag.resources._probe_corpus_status",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
    ):
        mock_embed.return_value.health_probe = AsyncMock(
            return_value=MagicMock(
                model_dump=lambda *, mode: {
                    "status": "ok",
                    "mode": "mock",
                    "release_id": "mock-v1",
                }
            )
        )
        payload = await check_loaded_resources(Settings())
    assert warmup_calls == [True]
    assert payload["pipeline_attached"] is True
    assert payload["status"] == "ready"


@pytest.mark.asyncio
async def test_loaded_resources_degraded_on_embedding_release_mismatch() -> None:
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)

    with (
        patch(
            "app.rag.resources.peek_loaded_retrieval_resources",
            return_value=None,
        ),
        patch(
            "app.rag.resources.peek_session_provider",
            return_value=mock_provider,
        ),
        patch(
            "app.rag.resources._probe_corpus_status",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
    ):
        mock_embed.return_value.health_probe = AsyncMock(
            return_value=MagicMock(
                model_dump=lambda *, mode: {
                    "status": "ok",
                    "mode": "mock",
                    "release_id": "other-release",
                }
            )
        )
        payload = await check_loaded_resources(Settings(embedding_release_id="configured-release"))
    assert payload["embedding_release_mismatch"] is True
    assert payload["status"] == "degraded"
    assert "embedding_release_mismatch" in payload["reasons"]


@pytest.mark.asyncio
async def test_loaded_resources_reports_corpus_status() -> None:
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)

    with (
        patch(
            "app.rag.resources.peek_loaded_retrieval_resources",
            return_value=None,
        ),
        patch(
            "app.rag.resources.peek_session_provider",
            return_value=mock_provider,
        ),
        patch(
            "app.rag.resources._probe_corpus_status",
            new_callable=AsyncMock,
            return_value="empty",
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
    ):
        mock_embed.return_value.health_probe = AsyncMock(
            return_value=MagicMock(
                model_dump=lambda *, mode: {
                    "status": "ok",
                    "mode": "mock",
                    "release_id": "mock-v1",
                }
            )
        )
        payload = await check_loaded_resources(Settings())
    assert payload["corpus_status"] == "empty"
    assert "corpus_empty" in payload["reasons"]


def test_warmup_retrieval_resources_builds_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    session_factory = MagicMock(spec=async_sessionmaker[AsyncSession])
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.session_factory = MagicMock(return_value=session_factory)
    monkeypatch.setattr("app.rag.resources.peek_session_provider", lambda: mock_provider)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)
    monkeypatch.setattr("app.api.v1.deps._get_redis", lambda: MagicMock())

    settings = Settings()
    llm = MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())
    embed = EmbeddingService(settings)
    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: llm,
    )
    monkeypatch.setattr(
        "app.core.embedding.factory.get_embedding_client",
        lambda **kwargs: embed,
    )
    monkeypatch.setattr("app.rag.resources.get_settings", lambda: settings)

    warmup_retrieval_resources()
    loaded = peek_loaded_retrieval_resources()
    assert loaded is not None
    assert loaded.pipeline is not None


def test_celery_task_releases_retrieval_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    stack_mock = MagicMock()
    reset_mock = MagicMock()
    embed_mock = MagicMock()
    monkeypatch.setattr("app.api.v1.deps.reset_investigation_stack_cache", stack_mock)
    monkeypatch.setattr("app.rag.resources.reset_loaded_retrieval_resources", reset_mock)
    monkeypatch.setattr("app.core.embedding.factory.reset_embedding_client", embed_mock)

    from app.tasks.investigation_tasks import _release_celery_task_loop_resources

    _release_celery_task_loop_resources()
    stack_mock.assert_called_once()
    reset_mock.assert_called_once()
    embed_mock.assert_called_once()


@pytest.mark.asyncio
async def test_hybrid_retriever_passes_tenant_to_store() -> None:
    store = MagicMock(spec=KnowledgeStore)
    store.vector_search = AsyncMock(return_value=[])
    store.keyword_search = AsyncMock(return_value=[])
    embed = MagicMock()
    embed.embed_query = AsyncMock(return_value=[0.1, 0.2])
    retriever = HybridRetriever(store, embed)
    context = RetrievalContext(
        tenant_id="tenant-beta",
        principal="investigation:rag_agent",
        event_id="evt-42",
        trace_id="trace-42",
    )

    await retriever.retrieve(["query"], ["attack_kb"], top_k=2, context=context)

    store.vector_search.assert_awaited()
    store.keyword_search.assert_awaited()
    for call in store.vector_search.await_args_list:
        assert call.kwargs.get("tenant_id") == "tenant-beta"
    for call in store.keyword_search.await_args_list:
        assert call.kwargs.get("tenant_id") == "tenant-beta"


@pytest.mark.asyncio
async def test_retrieval_pipeline_sets_trace_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from app.core.telemetry import traced_operation

    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    metric_reader = InMemoryMetricReader()
    MeterProvider(metric_readers=[metric_reader])

    monkeypatch.setattr("app.core.telemetry._ENABLED", True)
    monkeypatch.setattr(
        "app.core.telemetry.get_tracer",
        lambda name: tracer_provider.get_tracer(name),
    )

    rewriter = AsyncMock(return_value=["query"])
    chunk = RetrievedChunk(
        chunk_id="c1",
        kb_name="attack_kb",
        content="content",
        score=0.9,
        retrieval_method="vector",
    )
    retriever = AsyncMock(return_value=[[chunk]])
    reranker = AsyncMock(return_value=[chunk])
    pipeline = RetrievalPipeline(rewriter=rewriter, retriever=retriever, reranker=reranker)
    context = RetrievalContext(
        tenant_id="tenant-otel",
        principal="investigation:rag_agent",
        event_id="evt-otel",
        trace_id="trace-otel",
    )

    with traced_operation("test.parent"):
        await pipeline.retrieve("query", ["attack_kb"], top_k=1, context=context)

    finished = [
        span
        for span in span_exporter.get_finished_spans()
        if span.name == "retrieval_pipeline.retrieve"
    ]
    assert len(finished) == 1
    attrs = dict(finished[0].attributes or {})
    assert attrs.get("shadowtrace.tenant_id") == "tenant-otel"
    assert attrs.get("shadowtrace.event_id") == "evt-otel"
    assert attrs.get("shadowtrace.trace_id") == "trace-otel"
