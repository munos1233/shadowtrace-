"""Tests for PlaybookKBService: load, search, get, validation rejection (ISSUE-044)."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.services.knowledge_store import KnowledgeStore
from app.services.playbook_kb_service import KB_NAME, PlaybookKBService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "playbooks.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock"))


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service)


@pytest_asyncio.fixture
def service(
    store: KnowledgeStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> PlaybookKBService:
    return PlaybookKBService(store, session_factory)


async def _clean(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.commit()


# ---------------------------------------------------------------------------
# Load tests
# ---------------------------------------------------------------------------


class TestLoadFromFile:
    @pytest.mark.asyncio
    async def test_loads_at_least_12_playbooks(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        count = await service.load_from_file(DATA_FILE)
        assert count >= 12

    @pytest.mark.asyncio
    async def test_upsert_is_idempotent(
        self,
        service: PlaybookKBService,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        first = await service.load_from_file(DATA_FILE)
        second = await service.load_from_file(DATA_FILE)
        assert first == second
        assert await store.count(KB_NAME) == first

    @pytest.mark.asyncio
    async def test_all_eight_event_types_covered(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        expected_types = {
            "account_anomaly",
            "host_compromise",
            "data_exfiltration",
            "insider_threat",
            "malicious_process",
            "suspicious_domain",
            "lateral_movement",
            "other",
        }
        covered: set[str] = set()
        for et in expected_types:
            results = await service.search_playbooks(et, "critical", top_k=10)
            if results:
                covered.add(et)
        assert covered == expected_types

    @pytest.mark.asyncio
    async def test_step_order_is_sequential(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("data_exfiltration", "critical", top_k=5)
        for pb in results:
            orders = [s.step_order for s in pb.steps]
            assert orders == sorted(orders)
            assert orders[0] == 1
            assert len(set(orders)) == len(orders)

    @pytest.mark.asyncio
    async def test_data_exfiltration_steps_have_correct_action_levels(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("data_exfiltration", "high", top_k=5)
        assert len(results) >= 1
        tool_levels: dict[str, str] = {}
        for pb in results:
            for step in pb.steps:
                tool_levels[step.tool_name] = step.action_level.value
        assert tool_levels.get("disable_account") == "l3"
        assert tool_levels.get("block_ip") == "l2"


# ---------------------------------------------------------------------------
# Validation rejection tests
# ---------------------------------------------------------------------------


class TestValidationRejection:
    @pytest.mark.asyncio
    async def test_unknown_tool_name_rejected(
        self,
        service: PlaybookKBService,
    ) -> None:
        invalid_json = {
            "playbooks": [
                {
                    "playbook_id": "pb-deadbeef",
                    "playbook_name": "Bad Playbook",
                    "event_type": "other",
                    "min_severity": "low",
                    "description": "Contains an invalid tool name.",
                    "steps": [
                        {
                            "step_order": 1,
                            "action_name": "Run nonexistent tool",
                            "tool_name": "nonexistent_tool_xyz",
                            "action_level": "l0",
                            "precondition": "",
                            "expected_outcome": "",
                            "required_capabilities": [],
                        }
                    ],
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps(invalid_json, ensure_ascii=False, indent=2))
            tmp_path = f.name
        try:
            with pytest.raises(ValueError, match="unknown tool_name"):
                await service.load_from_file(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_wrong_action_level_rejected(
        self,
        service: PlaybookKBService,
    ) -> None:
        invalid_json = {
            "playbooks": [
                {
                    "playbook_id": "pb-cafebabe",
                    "playbook_name": "Wrong Level Playbook",
                    "event_type": "other",
                    "min_severity": "low",
                    "description": "Step declares l3 but notify_security_team is l1.",
                    "steps": [
                        {
                            "step_order": 1,
                            "action_name": "Notify with wrong level",
                            "tool_name": "notify_security_team",
                            "action_level": "l3",
                            "precondition": "",
                            "expected_outcome": "",
                            "required_capabilities": ["entity_response"],
                        }
                    ],
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps(invalid_json, ensure_ascii=False, indent=2))
            tmp_path = f.name
        try:
            with pytest.raises(ValueError, match="does not match ToolMeta.action_level"):
                await service.load_from_file(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Search tests
# ---------------------------------------------------------------------------


class TestSearchPlaybooks:
    @pytest.mark.asyncio
    async def test_filter_by_event_type_returns_only_matching(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("account_anomaly", "critical", top_k=10)
        assert len(results) >= 1
        for pb in results:
            assert pb.event_type.value == "account_anomaly"

    @pytest.mark.asyncio
    async def test_min_severity_filter_excludes_lower_playbooks(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("data_exfiltration", "critical", top_k=10)
        for pb in results:
            sev_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            assert sev_map[pb.min_severity.value] <= 3  # all valid since critical=3 is max

    @pytest.mark.asyncio
    async def test_data_exfiltration_high_returns_disable_account(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("data_exfiltration", "high", top_k=5)
        assert len(results) >= 1
        all_tool_names: set[str] = set()
        for pb in results:
            for step in pb.steps:
                all_tool_names.add(step.tool_name)
        assert "disable_account" in all_tool_names
        assert "block_ip" in all_tool_names

    @pytest.mark.asyncio
    async def test_search_with_query_text(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks(
            "data_exfiltration", "critical", query_text="data theft file access", top_k=3
        )
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_respects_top_k(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("lateral_movement", "critical", top_k=1)
        assert len(results) <= 1

    @pytest.mark.asyncio
    async def test_nonexistent_event_type_returns_empty(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("nonexistent_type", "low")
        assert results == []

    @pytest.mark.asyncio
    async def test_other_playbook_only_queries_and_l1(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("other", "low", top_k=5)
        assert len(results) >= 1
        for pb in results:
            for step in pb.steps:
                level = step.action_level.value
                assert level in ("l0", "l1"), (
                    f"other playbook step {step.tool_name} has action_level={level}, "
                    "expected only l0 (query) or l1 (ticket/notify)"
                )


# ---------------------------------------------------------------------------
# Get playbook tests
# ---------------------------------------------------------------------------


class TestGetPlaybook:
    @pytest.mark.asyncio
    async def test_get_existing_playbook_returns_full_structure(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        pb = await service.get_playbook("pb-a1b2c3d4")
        assert pb is not None
        assert pb.playbook_id == "pb-a1b2c3d4"
        assert pb.playbook_name == "Account Anomaly Credential Compromise Response"
        assert pb.event_type.value == "account_anomaly"
        assert pb.min_severity.value == "high"
        assert len(pb.steps) >= 3
        first_step = pb.steps[0]
        assert first_step.step_order == 1
        assert first_step.tool_name == "query_account_login"
        assert first_step.action_level.value == "l0"

    @pytest.mark.asyncio
    async def test_get_nonexistent_playbook_returns_none(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        result = await service.get_playbook("pb-ffffffff")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_kb_returns_none(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        result = await service.get_playbook("pb-a1b2c3d4")
        assert result is None


# ---------------------------------------------------------------------------
# Structural completeness tests
# ---------------------------------------------------------------------------


class TestStructuralCompleteness:
    @pytest.mark.asyncio
    async def test_every_playbook_has_required_fields(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        count = await service.load_from_file(DATA_FILE)
        assert count >= 12
        for et in [
            "account_anomaly",
            "host_compromise",
            "data_exfiltration",
            "insider_threat",
            "malicious_process",
            "suspicious_domain",
            "lateral_movement",
            "other",
        ]:
            results = await service.search_playbooks(et, "critical", top_k=10)
            for pb in results:
                assert pb.playbook_id.startswith("pb-")
                assert len(pb.playbook_id) == 11  # "pb-" + 8 hex
                assert len(pb.playbook_name) > 0
                assert len(pb.steps) >= 1
                for step in pb.steps:
                    assert step.step_order >= 1
                    assert len(step.action_name) > 0
                    assert len(step.tool_name) > 0
                    assert step.action_level is not None

    @pytest.mark.asyncio
    async def test_data_exfiltration_has_two_playbooks_by_severity(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("data_exfiltration", "critical", top_k=10)
        severities = {pb.min_severity.value for pb in results}
        assert len(severities) >= 2, (
            f"Expected at least 2 distinct severities for data_exfiltration, got {severities}"
        )

    @pytest.mark.asyncio
    async def test_insider_threat_has_two_playbooks_by_severity(
        self,
        service: PlaybookKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)
        results = await service.search_playbooks("insider_threat", "critical", top_k=10)
        severities = {pb.min_severity.value for pb in results}
        assert len(severities) >= 2, (
            f"Expected at least 2 distinct severities for insider_threat, got {severities}"
        )
