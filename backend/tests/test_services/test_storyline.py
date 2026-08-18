"""StorylineService tests (ISSUE-051).

Covers: rule-path 5-phase completeness, time-monotonic ordering, evidence_id
backlinks, LLM golden path, LLM-failure rule fallback, technique_id
backfill, WorkingMemory write, and degraded single-phase output for
evidence-scarce events.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from app.core.llm.base import (
    InMemoryLLMCallAuditRecorder,
    LLMMessage,
    LLMProviderError,
    LLMResponse,
)
from app.core.llm.mock_client import MockLLMClient
from app.models.agent_io import (
    StorylineGeneratedBy,
    StorylinePhaseName,
)
from app.models.ids import new_evidence_id
from app.services.storyline_service import (
    StorylineService,
    _bucket_evidence,
)

pytestmark = pytest.mark.asyncio


# ====================================================================== #
# Test helpers
# ====================================================================== #


def _new_sfx() -> str:
    return uuid4().hex[:8]


def _make_event_context(
    event_id: str = "evt-sl-001",
    evidence_list: list[dict[str, Any]] | None = None,
    techniques: list[dict[str, Any]] | None = None,
    graph_paths: list[list[str]] | None = None,
    central_entities: list[str] | None = None,
    scenario_id: str | None = None,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {"event": {"event_id": event_id}}
    if evidence_list is not None:
        ctx["evidence_output"] = {"evidence_list": evidence_list}
    if techniques is not None:
        ctx["rag_output"] = {"attack_techniques": techniques}
    if graph_paths is not None or central_entities is not None:
        ctx["graph_output"] = {
            "attack_path_candidates": graph_paths or [],
            "central_entities": central_entities or [],
        }
    if scenario_id:
        ctx["source_snapshot"] = {"normalized": {"scenario": scenario_id}}
    return ctx


def _make_evidence(
    *,
    evidence_id: str | None = None,
    source: str = "identity",
    evidence_type: str = "login",
    description: str = "test evidence",
    confidence: float = 0.8,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id or new_evidence_id(),
        "source": source,
        "evidence_type": evidence_type,
        "description": description,
        "confidence": confidence,
        "timestamp": (timestamp or datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)).isoformat(),
    }


def _main_scenario_evidence(event_id: str = "evt-sl-001") -> list[dict[str, Any]]:
    base = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    return [
        _make_evidence(
            source="identity",
            evidence_type="login",
            description="账号 zhangsan 从 10.20.30.23 登录",
            timestamp=base,
        ),
        _make_evidence(
            source="endpoint",
            evidence_type="process_create",
            description="主机 PC-FIN-023 上 rar.exe 进程启动",
            timestamp=base + timedelta(minutes=1),
        ),
        _make_evidence(
            source="data_security",
            evidence_type="file_access",
            description="账号 zhangsan 访问文件 financial_data.zip",
            timestamp=base + timedelta(minutes=2),
        ),
        _make_evidence(
            source="network_flow",
            evidence_type="outbound",
            description="PC-FIN-023 连接外部 IP 203.0.113.88",
            timestamp=base + timedelta(minutes=3),
        ),
        _make_evidence(
            source="dns",
            evidence_type="dns_query",
            description="DNS 解析 unknown-upload-example.com 到 203.0.113.88",
            timestamp=base + timedelta(minutes=4),
        ),
    ]


def _main_techniques() -> list[dict[str, Any]]:
    return [
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
            "match_confidence": 0.85,
            "citation_id": "cit-001",
        },
        {
            "technique_id": "T1560",
            "technique_name": "Archive Collected Data",
            "tactics": ["Collection"],
            "match_confidence": 0.78,
            "citation_id": "cit-002",
        },
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactics": ["Exfiltration"],
            "match_confidence": 0.82,
            "citation_id": "cit-003",
        },
    ]


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}
        self._for_writer_calls: list[str] = []

    def for_writer(self, writer: str) -> _FakeWorkingMemory:
        self._for_writer_calls.append(writer)
        return self

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass


class _FailingStorylineWorkingMemory(_FakeWorkingMemory):
    async def write(self, event_id: str, key: str, value: Any) -> None:
        if key == "storyline":
            raise RuntimeError("wm unavailable")
        await super().write(event_id, key, value)


def _production_mock_llm() -> MockLLMClient:
    return MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())


class _UnboundGoldenLLMClient:
    """Anti-cheat: emit the golden without production evidence_id binding."""

    async def chat(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
        del messages
        prompt_key = kwargs.get("prompt_key", "")
        if prompt_key != "storyline_generate":
            raise LLMProviderError("unknown prompt_key")
        with open(
            "app/core/llm/golden/storyline_generate/insider_data_exfiltration.json",
            encoding="utf-8",
        ) as fh:
            data = json.loads(fh.read())
        content = data["content"]
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        return LLMResponse(
            content=content_str,
            parsed=None,
            model_name="mock-model",
            prompt_tokens=data.get("prompt_tokens", 100),
            completion_tokens=data.get("completion_tokens", 100),
            total_tokens=data.get("total_tokens", 200),
            latency_ms=10,
            fallback_level=2,
        )


class _FailingLLMClient:
    async def chat(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
        raise LLMProviderError("simulated LLM failure")


# ====================================================================== #
# Rule-path tests
# ====================================================================== #


async def test_rule_path_five_phases_complete() -> None:
    """Rule path: main scenario produces >=4 phases with time-monotonic entries."""
    ctx = _make_event_context(
        evidence_list=_main_scenario_evidence(),
        techniques=_main_techniques(),
    )
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE
    assert len(storyline.phases) >= 4
    assert len(storyline.narrative_summary) > 0
    assert any("zhangsan" in phase.narrative for phase in storyline.phases)

    # Time monotonic: within each phase, entries sorted by timestamp
    for phase in storyline.phases:
        timestamps = [e.timestamp for e in phase.entries]
        assert timestamps == sorted(timestamps)


async def test_rule_path_evidence_backlinks() -> None:
    """Every TimelineEntry.evidence_id references a real evidence record."""
    evidence_list = _main_scenario_evidence()
    valid_ids = {e["evidence_id"] for e in evidence_list}

    ctx = _make_event_context(evidence_list=evidence_list)
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    for phase in storyline.phases:
        for entry in phase.entries:
            assert entry.evidence_id in valid_ids, f"evidence_id {entry.evidence_id} not in input"


async def test_rule_path_technique_backfill() -> None:
    """Technique IDs from RAG are backfilled into matching entries."""
    evidence_list = [
        _make_evidence(
            evidence_type="login",
            description="Valid Accounts login detected for zhangsan",
        ),
    ]
    ctx = _make_event_context(
        evidence_list=evidence_list,
        techniques=_main_techniques(),
    )
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    # "Valid Accounts" should match T1078
    technique_ids: set[str] = set()
    for phase in storyline.phases:
        for entry in phase.entries:
            if entry.technique_id:
                technique_ids.add(entry.technique_id)
    assert "T1078" in technique_ids, f"Expected T1078 backfill, got {technique_ids}"


async def test_rule_path_two_classified_evidence_single_phase() -> None:
    """< 3 evidence items always collapse to a single phase."""
    evidence_list = [
        _make_evidence(
            source="identity",
            evidence_type="login",
            description="账号 alice 登录",
            timestamp=datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC),
        ),
        _make_evidence(
            source="network_flow",
            evidence_type="outbound",
            description="向外连接 203.0.113.50",
            timestamp=datetime(2024, 6, 15, 9, 5, 0, tzinfo=UTC),
        ),
    ]
    ctx = _make_event_context(evidence_list=evidence_list)
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert len(storyline.phases) == 1
    assert len(storyline.phases[0].entries) == 2


async def test_rule_path_evidence_scarce_single_phase() -> None:
    """< 3 evidence items, all unclassified → single POST_ACTION phase."""
    from app.models.agent_io import StorylineGroundingStatus

    evidence_list = [
        _make_evidence(
            source="asset",
            evidence_type="agent_status",
            description="Agent 状态检查",
            timestamp=datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC),
        ),
        _make_evidence(
            source="threat_intel",
            evidence_type="indicator_check",
            description="威胁情报查询",
            timestamp=datetime(2024, 6, 15, 9, 5, 0, tzinfo=UTC),
        ),
    ]
    ctx = _make_event_context(evidence_list=evidence_list)
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert len(storyline.phases) == 1
    assert storyline.phases[0].phase_name == StorylinePhaseName.POST_ACTION
    assert len(storyline.narrative_summary) > 0
    assert storyline.grounding_status is StorylineGroundingStatus.EVIDENCE_GROUNDED
    assert len(storyline.claim_refs) >= 1


async def test_rule_path_empty_evidence() -> None:
    """No evidence → empty storyline with rule fallback (ISSUE-244: not grounded)."""
    from app.models.agent_io import StorylineGroundingStatus

    ctx = _make_event_context(evidence_list=[])
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE
    assert storyline.phases == []
    assert len(storyline.narrative_summary) > 0
    assert storyline.grounding_status is StorylineGroundingStatus.UNGROUNDED
    assert storyline.grounding_status is not StorylineGroundingStatus.EVIDENCE_GROUNDED
    assert storyline.claim_refs == []


async def test_rule_path_wm_write() -> None:
    """Storyline is written to WorkingMemory under 'storyline' key."""
    wm = _FakeWorkingMemory()
    ctx = _make_event_context(
        event_id="evt-wm-001",
        evidence_list=_main_scenario_evidence(),
    )
    svc = StorylineService(working_memory=wm)
    await svc.generate(ctx)

    assert wm._for_writer_calls == ["StorylineService"]
    stored = await wm.read("evt-wm-001", "storyline")
    assert stored is not None
    assert stored["event_id"] == "evt-wm-001"
    assert stored["generated_by"] == StorylineGeneratedBy.RULE.value


async def test_wm_write_failure_sets_storyline_degraded() -> None:
    """WM storyline write failure records storyline_degraded."""
    wm = _FailingStorylineWorkingMemory()
    ctx = _make_event_context(
        event_id="evt-wm-fail-001",
        evidence_list=_main_scenario_evidence(),
    )
    svc = StorylineService(working_memory=wm)
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE
    assert svc.last_degraded_reason is not None
    assert svc.last_degraded_reason.startswith("storyline_write_failed:")
    degraded = await wm.read("evt-wm-fail-001", "storyline_degraded")
    assert degraded is not None
    assert degraded["degraded"] is True


async def test_storyline_id_format() -> None:
    ctx = _make_event_context(evidence_list=_main_scenario_evidence())
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)
    assert re.fullmatch(r"sty-[0-9a-f]{8}", storyline.storyline_id)


# ====================================================================== #
# LLM-path tests
# ====================================================================== #


async def test_llm_path_golden_response() -> None:
    """Production MockLLM binds catalog ids and adopts the insider golden."""
    evidence_list = _main_scenario_evidence()
    ctx = _make_event_context(
        evidence_list=evidence_list,
        techniques=_main_techniques(),
        graph_paths=[["node-a", "node-b", "node-c"]],
        central_entities=["zhangsan", "PC-FIN-023"],
        scenario_id="insider_data_exfiltration",
    )

    svc = StorylineService(
        llm_client=_production_mock_llm(),
        working_memory=_FakeWorkingMemory(),
    )
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.LLM
    assert len(storyline.phases) >= 4
    assert len(storyline.narrative_summary) > 0
    assert "zhangsan" in storyline.narrative_summary.lower()


async def test_llm_path_evidence_backlinks() -> None:
    """Production MockLLM path: every TimelineEntry.evidence_id is from input."""
    evidence_list = _main_scenario_evidence()
    valid_ids = {e["evidence_id"] for e in evidence_list}
    ctx = _make_event_context(
        evidence_list=evidence_list,
        techniques=_main_techniques(),
        graph_paths=[["node-a", "node-b", "node-c"]],
        central_entities=["zhangsan", "PC-FIN-023"],
        scenario_id="insider_data_exfiltration",
    )

    svc = StorylineService(
        llm_client=_production_mock_llm(),
        working_memory=_FakeWorkingMemory(),
    )
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.LLM
    for phase in storyline.phases:
        for entry in phase.entries:
            assert entry.evidence_id in valid_ids, f"evidence_id {entry.evidence_id} not in input"


async def test_unbound_golden_is_not_adopted_as_llm() -> None:
    """Anti-cheat: goldens without bound evidence_id must not stamp generated_by=llm."""
    evidence_list = _main_scenario_evidence()
    ctx = _make_event_context(
        evidence_list=evidence_list,
        techniques=_main_techniques(),
        scenario_id="insider_data_exfiltration",
    )
    wm = _FakeWorkingMemory()
    svc = StorylineService(llm_client=_UnboundGoldenLLMClient(), working_memory=wm)
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE
    assert svc.last_degraded_reason == "storyline_unbound_evidence"
    degraded = await wm.read("evt-sl-001", "storyline_degraded")
    assert degraded is not None
    assert degraded["reason"] == "storyline_unbound_evidence"


async def test_llm_path_falls_back_to_rule() -> None:
    """LLM failure → rule fallback with generated_by=rule."""
    evidence_list = _main_scenario_evidence()
    ctx = _make_event_context(evidence_list=evidence_list)

    svc = StorylineService(llm_client=_FailingLLMClient(), working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE
    assert len(storyline.phases) >= 4


async def test_llm_path_soft_time_limit_does_not_fall_back_to_rule() -> None:
    """ISSUE-314: SoftTimeLimitExceeded must not become rule-storyline success."""
    from celery.exceptions import SoftTimeLimitExceeded

    class _SoftLimitLLMClient:
        async def chat(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
            raise SoftTimeLimitExceeded()

    evidence_list = _main_scenario_evidence()
    ctx = _make_event_context(evidence_list=evidence_list)
    svc = StorylineService(
        llm_client=_SoftLimitLLMClient(),
        working_memory=_FakeWorkingMemory(),
    )
    with pytest.raises(SoftTimeLimitExceeded):
        await svc.generate(ctx)


async def test_llm_path_no_llm_client_uses_rule() -> None:
    """Without llm_client, service goes directly to rule path."""
    ctx = _make_event_context(evidence_list=_main_scenario_evidence())
    svc = StorylineService(llm_client=None, working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert storyline.generated_by == StorylineGeneratedBy.RULE


# ====================================================================== #
# Bucket helper tests
# ====================================================================== #


async def test_bucket_login_to_initial_access() -> None:
    ev = _make_evidence(source="identity", evidence_type="login", description="用户登录")
    assert _bucket_evidence(ev) == StorylinePhaseName.INITIAL_ACCESS


async def test_bucket_file_access_to_collection() -> None:
    ev = _make_evidence(
        source="data_security", evidence_type="file_access", description="文件访问操作"
    )
    assert _bucket_evidence(ev) == StorylinePhaseName.COLLECTION


async def test_bucket_rar_to_staging() -> None:
    ev = _make_evidence(
        source="endpoint", evidence_type="process_create", description="rar.exe 压缩文件"
    )
    assert _bucket_evidence(ev) == StorylinePhaseName.STAGING


async def test_bucket_outbound_to_exfiltration() -> None:
    ev = _make_evidence(source="network_flow", evidence_type="outbound", description="向外连接")
    assert _bucket_evidence(ev) == StorylinePhaseName.EXFILTRATION


async def test_bucket_unknown_to_post_action() -> None:
    ev = _make_evidence(source="asset", evidence_type="agent_status", description="Agent 状态检查")
    assert _bucket_evidence(ev) == StorylinePhaseName.POST_ACTION


# ====================================================================== #
# Technique backfill unit tests
# ====================================================================== #


async def test_backfill_technique_ids_matches_description() -> None:
    entry = _make_evidence(description="Valid Accounts login detected")
    ev_list = [entry]
    ctx = _make_event_context(evidence_list=ev_list, techniques=_main_techniques())
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    found = False
    for phase in storyline.phases:
        for e in phase.entries:
            if e.technique_id == "T1078":
                found = True
    assert found, "T1078 should be backfilled for 'Valid Accounts' evidence"


async def test_backfill_no_techniques_no_error() -> None:
    """Empty technique list → no crash, no backfill."""
    entry = _make_evidence(description="some activity")
    ctx = _make_event_context(evidence_list=[entry], techniques=[])
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    for phase in storyline.phases:
        for e in phase.entries:
            assert e.technique_id is None


async def test_generate_attaches_claim_refs_v2() -> None:
    """ISSUE-116 Phase B: storyline emits evidence-grounded claim refs."""
    from app.models.agent_io import StorylineGroundingStatus

    entries = [
        _make_evidence(evidence_type="login", description="login"),
        _make_evidence(evidence_type="file_access", description="read file"),
        _make_evidence(evidence_type="upload", description="upload"),
    ]
    ctx = _make_event_context(evidence_list=entries)
    svc = StorylineService(working_memory=_FakeWorkingMemory())
    storyline = await svc.generate(ctx)

    assert storyline.schema_version == "2.0"
    assert storyline.grounding_status is StorylineGroundingStatus.EVIDENCE_GROUNDED
    assert len(storyline.claim_refs) >= 1
    assert all(ref.evidence_ids for ref in storyline.claim_refs)
