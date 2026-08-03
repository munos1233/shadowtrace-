"""Knowledge release service persistence tests (ISSUE-128 / #634)."""

from __future__ import annotations

import asyncio
import copy
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ValidationError
from app.db import models as orm
from app.db.orm.knowledge import KnowledgeChunkORM
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    KnowledgeReleaseLifecycleState,
)
from app.services.knowledge_query_plan_service import resolve_knowledge_query_plan
from app.services.knowledge_release_resolver import default_attack_provenance
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.knowledge_store import KnowledgeStore
from app.services.stix_bundle_builder import build_bundle_from_techniques_json

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "attack_techniques.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_release_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.KnowledgeStixObjectORM))
            await session.execute(delete(orm.KnowledgeReleaseORM))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.KnowledgeStixObjectORM))
            await session.execute(delete(orm.KnowledgeReleaseORM))


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(EMBEDDING_MODE="mock", EMBEDDING_MAX_BATCH_SIZE=128))


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service)


@pytest_asyncio.fixture
def service(
    session_factory: async_sessionmaker[AsyncSession],
    store: KnowledgeStore,
) -> KnowledgeReleaseService:
    return KnowledgeReleaseService(
        session_factory,
        store=store,
        settings=Settings(EMBEDDING_MODE="mock", EMBEDDING_MAX_BATCH_SIZE=128),
    )


def _bundle() -> dict:
    return build_bundle_from_techniques_json(DATA_FILE)


@pytest.mark.asyncio
async def test_stage_import_is_idempotent(service: KnowledgeReleaseService) -> None:
    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    provenance = default_attack_provenance("fixture://attack")
    first = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=provenance,
    )
    second = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=provenance,
    )
    assert first.release_id == second.release_id
    assert first.content_hash == second.content_hash


@pytest.mark.asyncio
async def test_bad_bundle_cannot_activate(service: KnowledgeReleaseService) -> None:
    bundle = _bundle()
    bundle["objects"] = []
    with pytest.raises(ValidationError, match="invalid STIX bundle|attack-pattern"):
        await service.stage_stix_bundle(
            bundle,
            release_version="v15.1",
            provenance=default_attack_provenance("bad://bundle"),
        )


@pytest.mark.asyncio
async def test_activate_materializes_release_scoped_chunks(
    service: KnowledgeReleaseService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack"),
    )
    activated = await service.activate_release(staged.release_id)
    assert activated.lifecycle_state is KnowledgeReleaseLifecycleState.ACTIVE
    assert activated.vector_ready is False

    async with session_factory() as session:
        result = await session.execute(
            select(KnowledgeChunkORM).where(
                KnowledgeChunkORM.kb_name == "attack_kb",
                KnowledgeChunkORM.chunk_metadata["release_id"].as_string() == activated.release_id,
            )
        )
        rows = list(result.scalars())
        assert len(rows) >= 60


@pytest.mark.asyncio
async def test_embedding_mismatch_blocks_vector_ready_activation(
    service: KnowledgeReleaseService,
) -> None:
    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack"),
    )
    with pytest.raises(ValidationError, match="embedding release incompatible"):
        await service.activate_release(
            staged.release_id,
            vector_ready=True,
            embedding_release_id="wrong-release-id",
        )


@pytest.mark.asyncio
async def test_concurrent_activate_single_active_per_corpus(
    service: KnowledgeReleaseService,
) -> None:
    bundle_a = _bundle()
    bundle_b = copy.deepcopy(bundle_a)
    bundle_b["x_shadowtrace_attack_version"] = "v15.1-test"
    bundle_b["id"] = "bundle--variant-b"
    bundle_b["objects"] = copy.deepcopy(bundle_a["objects"])
    bundle_b["objects"][0] = copy.deepcopy(bundle_b["objects"][0])
    bundle_b["objects"][0]["description"] = "variant description for hash separation"
    bundle_b["x_shadowtrace_object_count"] = len(bundle_b["objects"])

    first = await service.stage_stix_bundle(
        bundle_a,
        release_version="v15.1",
        provenance=default_attack_provenance("fixture://a"),
    )
    second = await service.stage_stix_bundle(
        bundle_b,
        release_version="v15.1-test",
        provenance=default_attack_provenance("fixture://b"),
        revision=2,
        supersedes_release_id=first.release_id,
    )
    results = await asyncio.gather(
        service.activate_release(first.release_id),
        service.activate_release(second.release_id),
        return_exceptions=True,
    )
    assert not any(isinstance(item, Exception) for item in results)
    active = await service.get_active_release(ATTACK_CORPUS_ID)
    assert active is not None
    async with service._session_factory() as session:
        active_rows = await session.scalars(
            select(orm.KnowledgeReleaseORM).where(
                orm.KnowledgeReleaseORM.corpus_id == ATTACK_CORPUS_ID,
                orm.KnowledgeReleaseORM.lifecycle_state
                == KnowledgeReleaseLifecycleState.ACTIVE.value,
            )
        )
        assert len(list(active_rows)) == 1


@pytest.mark.asyncio
async def test_request_plan_pins_release_ids(service: KnowledgeReleaseService) -> None:
    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack"),
    )
    activated = await service.activate_release(staged.release_id)
    settings = Settings(EMBEDDING_MODE="mock")
    plan = resolve_knowledge_query_plan(
        corpus_id=ATTACK_CORPUS_ID,
        active_release_id=activated.release_id,
        embedding_release_id=settings.embedding_release_id,
        trace_id=f"trace-{uuid.uuid4().hex[:8]}",
    )
    assert plan.active_release_id == activated.release_id
    assert plan.kb_name == "attack_kb"


@pytest.mark.asyncio
async def test_mark_import_failed_is_idempotent(service: KnowledgeReleaseService) -> None:
    provenance = default_attack_provenance("fixture://failed")
    content_hash = "c" * 64
    first = await service.mark_import_failed(
        corpus_id=ATTACK_CORPUS_ID,
        content_hash=content_hash,
        provenance=provenance,
        release_version="v15.1-failed",
        reason="bad bundle",
    )
    second = await service.mark_import_failed(
        corpus_id=ATTACK_CORPUS_ID,
        content_hash=content_hash,
        provenance=provenance,
        release_version="v15.1-failed",
        reason="bad bundle",
    )
    assert first.release_id == second.release_id
    assert first.lifecycle_state is KnowledgeReleaseLifecycleState.FAILED


@pytest.mark.asyncio
async def test_retired_release_remains_auditable(
    service: KnowledgeReleaseService,
) -> None:
    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    first = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://first"),
    )
    await service.activate_release(first.release_id)

    bundle_b = copy.deepcopy(bundle)
    bundle_b["id"] = "bundle--replacement"
    bundle_b["x_shadowtrace_attack_version"] = "v15.1-replacement"
    bundle_b["objects"] = copy.deepcopy(bundle["objects"])
    bundle_b["objects"][0] = copy.deepcopy(bundle_b["objects"][0])
    bundle_b["objects"][0]["description"] = "replacement release description"
    bundle_b["x_shadowtrace_object_count"] = len(bundle_b["objects"])
    second = await service.stage_stix_bundle(
        bundle_b,
        release_version="v15.1-replacement",
        provenance=default_attack_provenance("fixture://second"),
        revision=2,
        supersedes_release_id=first.release_id,
    )
    await service.activate_release(second.release_id)

    retired = await service.get_release(first.release_id)
    assert retired is not None
    assert retired.lifecycle_state is KnowledgeReleaseLifecycleState.RETIRED
    assert retired.retired_at is not None


@pytest.mark.asyncio
async def test_cannot_activate_failed_release(service: KnowledgeReleaseService) -> None:
    failed = await service.mark_import_failed(
        corpus_id=ATTACK_CORPUS_ID,
        content_hash="d" * 64,
        provenance=default_attack_provenance("fixture://failed-activate"),
        release_version="v15.1-failed-activate",
        reason="bundle validation failed",
    )
    with pytest.raises(ValidationError, match="cannot activate a failed"):
        await service.activate_release(failed.release_id)


@pytest.mark.asyncio
async def test_vector_ready_activation_succeeds_with_matching_embedding_release(
    service: KnowledgeReleaseService,
) -> None:
    from app.core.embedding.release import build_embedding_release

    bundle = _bundle()
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack-vector"),
    )
    settings = Settings(EMBEDDING_MODE="mock", EMBEDDING_MAX_BATCH_SIZE=128)
    embedding_release_id = build_embedding_release(settings).release_id
    activated = await service.activate_release(
        staged.release_id,
        vector_ready=True,
        embedding_release_id=embedding_release_id,
    )
    assert activated.vector_ready is True
    assert activated.embedding_release_id == embedding_release_id
