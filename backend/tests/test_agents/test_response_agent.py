"""ResponseAgent disposition plan tests (ISSUE-057)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.agents.response_agent import (
    ActionCandidate,
    ResponseAgent,
    ResponsePolicyFilter,
    _cap_low_severity_candidates,
    _enforce_execution_owner_consistency,
    approval_confidence_for_disposition_only,
    build_mock_capability_manifest,
    compute_action_fingerprint,
    derive_stable_action_id,
    generate_response_plan_id,
)
from app.agents.rules.default_response_rules import DEFAULT_RESPONSE_RULES, get_rule_actions
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.models.action import TERMINAL_DISPOSITION_TOOL
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponseAgentInput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
    TriageResult,
)
from app.models.evidence import Evidence
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    CapabilityState,
    DispositionPolicy,
    EventType,
    EvidenceSource,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceDisposition,
    SourceObjectKind,
)
from app.models.playbook import Playbook, PlaybookStep
from app.models.playbook_release import PlaybookRef
from app.models.source import SourceReference
from app.models.workflow import FP_HIGH_THRESHOLD


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        return None


class _FakeEventService:
    def __init__(
        self,
        *,
        disposition_policy: DispositionPolicy = DispositionPolicy.REQUIRED,
        final_verdict: FinalVerdict = FinalVerdict.NONE,
    ) -> None:
        self.disposition_policy = disposition_policy
        self.final_verdict = final_verdict
        self.actions_by_fp: dict[str, dict[str, Any]] = {}
        self.supersede_calls: list[dict[str, Any]] = []

    async def get_event(self, event_id: str) -> Any:
        return SimpleNamespace(
            event_id=event_id,
            disposition_policy=self.disposition_policy,
            final_verdict=self.final_verdict,
            creation_source_ref=SourceReference(
                source_kind=SourceObjectKind.INCIDENT,
                source_product="mock_xdr",
                source_tenant_id="tenant-1",
                connector_id="conn-mock",
                source_object_id="INC-001",
            ),
        )

    async def upsert_response_plan_actions(
        self,
        event_id: str,
        *,
        plan_revision: int,
        actions: list[Any],
        response_plan: Any | None = None,
    ) -> list[Any]:
        stored: list[Any] = []
        for action in actions:
            fp = action.action_fingerprint
            if fp in self.actions_by_fp:
                stored.append(self._dict_to_action(self.actions_by_fp[fp]))
                continue
            payload = action.model_dump(mode="json")
            self.actions_by_fp[fp] = payload
            stored.append(action)
        return stored

    async def supersede_undeployed_deferred(
        self,
        event_id: str,
        *,
        old_revision: int,
        new_revision: int,
    ) -> int:
        self.supersede_calls.append(
            {"event_id": event_id, "old_revision": old_revision, "new_revision": new_revision}
        )
        count = 0
        for _fp, row in list(self.actions_by_fp.items()):
            if (
                row.get("event_id") == event_id
                and row.get("plan_revision") == old_revision
                and row.get("tool_name") == TERMINAL_DISPOSITION_TOOL
                and row.get("execution_job_id") is None
                and row.get("status")
                in {
                    ActionStatus.PENDING.value,
                    ActionStatus.WAITING_APPROVAL.value,
                    ActionStatus.APPROVED.value,
                }
            ):
                row["status"] = ActionStatus.SUPERSEDED.value
                row["writeback_applicable"] = False
                row["superseded_by_revision"] = new_revision
                count += 1
        return count

    def list_actions(self, event_id: str) -> list[dict[str, Any]]:
        return [row for row in self.actions_by_fp.values() if row.get("event_id") == event_id]

    @staticmethod
    def _dict_to_action(payload: dict[str, Any]) -> Any:
        from app.models.action import Action

        return Action.model_validate(payload)


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("llm unavailable")


class _UngroundedOnlyLLM:
    """LLM proposes targets absent from EntitySet — PolicyFilter drops containment."""

    async def chat(self, *args: Any, **kwargs: Any) -> Any:
        import json

        from app.core.llm.base import LLMResponse

        payload = {
            "actions": [
                {
                    "tool_name": "reset_password",
                    "target_type": "account",
                    "target": "zhangsan",
                    "parameters": {},
                    "reason": "ungrounded insider account",
                },
                {
                    "tool_name": "block_ip",
                    "target_type": "ip",
                    "target": "198.51.100.44",
                    "parameters": {},
                    "reason": "ungrounded external IOC",
                },
                {
                    "tool_name": "create_ticket",
                    "target_type": "ticket",
                    "target": "ticket",
                    "parameters": {"title": "track", "description": "track"},
                    "reason": "ticket only after filter",
                },
            ],
            "strategy_summary": "LLM-only ungrounded plan",
        }
        return LLMResponse(
            content=json.dumps(payload),
            model_name="mock",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
        )


def _playbook_ref(playbook_id: str) -> dict[str, str | int]:
    return {
        "playbook_id": playbook_id,
        "release_id": "krel-test00000001",
        "release_version": "v1-test",
        "content_hash": "a" * 64,
        "bundle_content_hash": "b" * 64,
        "revision": 1,
    }


class _FakePlaybookKB:
    def __init__(self, playbook: Playbook | None) -> None:
        self.playbook = playbook

    async def get_playbook(self, playbook_id: str) -> Playbook | None:
        if self.playbook is not None and self.playbook.playbook_id == playbook_id:
            return self.playbook
        return None


def _ref() -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id="INC-001",
        ingested_at=datetime.now(UTC),
    )


def _entities() -> EntitySet:
    return EntitySet(
        accounts=[
            AccountEntity(entity_id="acct-1", username="svc-backup", source_refs=[_ref()]),
        ],
        ips=[
            IPEntity(
                entity_id="ip-ext",
                address="203.0.113.50",
                scope="external",
                source_refs=[_ref()],
            ),
            IPEntity(
                entity_id="ip-int",
                address="10.0.0.5",
                scope="internal",
                source_refs=[_ref()],
            ),
        ],
        hosts=[HostEntity(entity_id="host-1", hostname="PC-FIN-023", source_refs=[_ref()])],
        domains=[DomainEntity(entity_id="dom-1", fqdn="evil.example", source_refs=[_ref()])],
    )


def _risk(
    severity: Severity = Severity.HIGH,
    *,
    score: int = 85,
    evidence_limited: bool = False,
) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=severity,
        confidence=0.88,
        risk_factors=[
            RiskFactor(
                factor_name="asset_impact",
                weight=0.2,
                raw_score=float(score),
                weighted_score=float(score) * 0.2,
                reasoning="test",
            )
        ],
        scoring_mode=ScoringMode.LLM_AND_RULE,
        evidence_limited=evidence_limited,
    )


def _sample_evidence(event_id: str = "evt-20260723-test") -> Evidence:
    return Evidence(
        evidence_id="ev-usable-1",
        event_id=event_id,
        source=EvidenceSource.ENDPOINT,
        evidence_type="process",
        description="suspicious process tree",
        confidence=0.91,
    )


def _triage(
    *,
    event_type: EventType = EventType.DATA_EXFILTRATION,
    severity: Severity = Severity.HIGH,
    entities: EntitySet | None = None,
) -> TriageResult:
    return TriageResult(
        event_type=event_type,
        severity=severity,
        need_investigation=True,
        entities=entities or _entities(),
        reasoning="test triage",
    )


def _agent_input(event_id: str = "evt-20260723-test") -> ResponseAgentInput:
    return ResponseAgentInput(
        event_id=event_id,
        risk_assessment=_risk(),
        evidence_output=EvidenceOutput(
            evidence_list=[],
            collection_status=CollectionStatus.COMPLETED,
            overall_confidence=0.9,
        ),
    )


def _seed_wm(
    wm: _FakeWorkingMemory,
    event_id: str,
    *,
    triage: TriageResult,
    disposition_policy: DispositionPolicy = DispositionPolicy.REQUIRED,
    disposition_only: bool = False,
    plan_revision: int = 1,
) -> None:
    wm.values[(event_id, "triage_result")] = triage.model_dump(mode="json")
    wm.values[(event_id, "execution_plan")] = {
        "plan_id": "pln-test",
        "event_id": event_id,
        "revision": plan_revision - 1,
        "steps": [],
    }
    wm.values[(event_id, "event")] = {
        "event_id": event_id,
        "disposition_policy": disposition_policy.value,
        "creation_source_ref": _ref().model_dump(mode="json"),
    }
    wm.values[(event_id, "disposition_only_intent")] = disposition_only


@pytest.mark.asyncio
async def test_main_scenario_has_disable_account_and_block_ip() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    event_service = _FakeEventService()
    llm = MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())
    agent = ResponseAgent(
        llm_client=llm,
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
        scenario_id="insider_data_exfiltration",
    )

    plan = await agent.execute(_agent_input(event_id))

    tool_names = {action.tool_name for action in plan.actions}
    assert "isolate_host" in tool_names
    assert "create_ticket" in tool_names
    isolate = next(a for a in plan.actions if a.tool_name == "isolate_host")
    assert isolate.action_level is ActionLevel.L3
    assert plan.generated_by is ResponsePlanGeneratedBy.LLM


@pytest.mark.asyncio
async def test_low_not_required_single_ticket() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(event_type=EventType.OTHER, severity=Severity.LOW),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(disposition_policy=DispositionPolicy.NOT_REQUIRED),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.LOW, score=15),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.4,
            ),
        )
    )

    immediate = [a for a in plan.actions if a.tool_name != TERMINAL_DISPOSITION_TOOL]
    assert len(immediate) == 1
    assert immediate[0].tool_name == "create_ticket"
    assert all(a.tool_name != TERMINAL_DISPOSITION_TOOL for a in plan.actions)


@pytest.mark.asyncio
async def test_required_plan_has_single_post_verify_action() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))

    deferred = [a for a in plan.actions if a.tool_name == TERMINAL_DISPOSITION_TOOL]
    assert len(deferred) == 1
    assert deferred[0].execution_phase is ActionExecutionPhase.POST_VERIFY
    assert deferred[0].activation_condition == "after_effect_resolution"
    assert deferred[0].action_level is ActionLevel.L2


@pytest.mark.asyncio
async def test_disposition_only_plan_only_deferred_action() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(event_type=EventType.OTHER, severity=Severity.LOW),
        disposition_only=True,
    )
    agent = ResponseAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))

    assert len(plan.actions) == 1
    assert plan.actions[0].tool_name == TERMINAL_DISPOSITION_TOOL


@pytest.mark.asyncio
async def test_deferred_approved_terminal_subset_only() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(),
        disposition_only=True,
    )
    agent = ResponseAgent(
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    deferred = plan.actions[0]
    assert set(deferred.approved_terminal_dispositions) <= {
        SourceDisposition.CONTAINED,
        SourceDisposition.COMPLETED,
        SourceDisposition.SUSPENDED,
        SourceDisposition.IGNORED,
    }
    assert deferred.approved_terminal_dispositions == [SourceDisposition.IGNORED]


@pytest.mark.asyncio
async def test_policy_filter_rejects_unknown_tool() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())

    class _BadLLM:
        async def chat(self, *args: Any, **kwargs: Any) -> Any:
            import json

            from app.core.llm.base import LLMResponse

            payload = {
                "actions": [
                    {
                        "tool_name": "totally_fake_tool",
                        "target_type": "ip",
                        "target": "203.0.113.50",
                        "parameters": {},
                    }
                ],
                "strategy_summary": "bad",
            }
            return LLMResponse(
                content=json.dumps(payload),
                model_name="mock",
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
            )

    agent = ResponseAgent(
        llm_client=_BadLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    assert all(a.tool_name != "totally_fake_tool" for a in plan.actions)


@pytest.mark.asyncio
async def test_containment_quality_gate_rule_fallback_after_ungrounded_llm() -> None:
    """ISSUE-198: high-confidence plans must not stay ticket-only after PolicyFilter."""
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_UngroundedOnlyLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))

    tool_names = {action.tool_name for action in plan.actions}
    assert "block_ip" in tool_names
    assert "disable_account" in tool_names
    block = next(a for a in plan.actions if a.tool_name == "block_ip")
    assert block.target == "203.0.113.50"
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate" in plan.strategy_summary


@pytest.mark.asyncio
async def test_containment_quality_gate_skips_low_severity_ticket_only() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(severity=Severity.LOW, event_type=EventType.DATA_EXFILTRATION),
    )
    agent = ResponseAgent(
        llm_client=_UngroundedOnlyLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.LOW, score=25),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.5,
            ),
        )
    )
    response_tools = {
        action.tool_name
        for action in plan.actions
        if action.tool_name
        not in {TERMINAL_DISPOSITION_TOOL, "create_ticket", "notify_security_team"}
    }
    assert not response_tools


@pytest.mark.asyncio
async def test_containment_quality_gate_confirmed_threat_at_medium_severity() -> None:
    """ISSUE-198: confirmed_threat triggers containment even when triage severity is MEDIUM."""
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(severity=Severity.MEDIUM, event_type=EventType.OTHER),
    )
    agent = ResponseAgent(
        llm_client=_UngroundedOnlyLLM(),
        working_memory=wm,
        event_service=_FakeEventService(final_verdict=FinalVerdict.CONFIRMED_THREAT),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.MEDIUM, score=55),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.9,
            ),
        )
    )
    tool_names = {action.tool_name for action in plan.actions}
    assert "block_ip" in tool_names
    assert "containment_quality_gate" in plan.strategy_summary


@pytest.mark.asyncio
async def test_containment_quality_gate_aligns_block_ip_with_grounded_entity() -> None:
    """ISSUE-198: rule fallback block_ip must target a grounded EntitySet IOC."""
    grounded_ip = "203.0.113.50"
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_UngroundedOnlyLLM(),
        working_memory=wm,
        event_service=_FakeEventService(final_verdict=FinalVerdict.CONFIRMED_THREAT),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    block_targets = {action.target for action in plan.actions if action.tool_name == "block_ip"}
    assert grounded_ip in block_targets
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate" in plan.strategy_summary


@pytest.mark.asyncio
async def test_evidence_failed_high_severity_blocks_l2_plus_actions() -> None:
    """ISSUE-248: collection failed + high risk must not plan L2/L3 containment."""
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=_FakeEventService(final_verdict=FinalVerdict.NONE),
        capability_manifest=build_mock_capability_manifest(),
        scenario_id="insider_data_exfiltration",
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.HIGH, score=90, evidence_limited=True),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.FAILED,
                overall_confidence=0.0,
            ),
        )
    )
    high_impact = [
        action
        for action in plan.actions
        if action.tool_name != TERMINAL_DISPOSITION_TOOL
        and action.action_level not in {ActionLevel.L0, ActionLevel.L1}
    ]
    assert high_impact == []
    assert "evidence_sufficiency_gate" in plan.strategy_summary
    assert "containment_quality_gate" not in plan.strategy_summary
    # Deferred disposition writeback remains (approval/execution gates unchanged).
    assert any(a.tool_name == TERMINAL_DISPOSITION_TOOL for a in plan.actions)


@pytest.mark.asyncio
async def test_zero_evidence_limited_high_blocks_l2_plus_even_from_rules() -> None:
    """ISSUE-248: zero-evidence evidence_limited strips L2+ from rule fallback too."""
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(final_verdict=FinalVerdict.NONE),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.HIGH, score=88, evidence_limited=True),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.DEGRADED,
                overall_confidence=0.05,
            ),
        )
    )
    response_levels = {
        action.action_level
        for action in plan.actions
        if action.tool_name != TERMINAL_DISPOSITION_TOOL
    }
    assert response_levels <= {ActionLevel.L0, ActionLevel.L1}
    assert "zero_evidence_limited" in plan.strategy_summary


@pytest.mark.asyncio
async def test_sufficient_evidence_confirmed_threat_still_allows_l2_plus() -> None:
    """ISSUE-248: usable evidence + confirmed_threat must still plan high-impact actions."""
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_UngroundedOnlyLLM(),
        working_memory=wm,
        event_service=_FakeEventService(final_verdict=FinalVerdict.CONFIRMED_THREAT),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.HIGH, score=90, evidence_limited=False),
            evidence_output=EvidenceOutput(
                evidence_list=[_sample_evidence(event_id)],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.92,
            ),
        )
    )
    tool_names = {action.tool_name for action in plan.actions}
    assert "block_ip" in tool_names or "disable_account" in tool_names or "isolate_host" in tool_names
    assert "evidence_sufficiency_gate" not in plan.strategy_summary


@pytest.mark.asyncio
async def test_capability_missing_excludes_tool() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    manifest = build_mock_capability_manifest(disabled_tools=frozenset({"block_ip"}))
    agent = ResponseAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=manifest,
    )
    plan = await agent.execute(_agent_input(event_id))
    assert all(action.tool_name != "block_ip" for action in plan.actions)


@pytest.mark.parametrize("event_type", list(EventType))
def test_default_response_rules_cover_all_event_types(event_type: EventType) -> None:
    assert event_type in DEFAULT_RESPONSE_RULES
    rules = DEFAULT_RESPONSE_RULES[event_type]
    assert Severity.LOW in rules
    for actions in rules.values():
        assert actions
        for action in actions:
            assert action.tool_name


def test_data_exfiltration_high_rules_include_required_tools() -> None:
    actions = get_rule_actions(EventType.DATA_EXFILTRATION, Severity.HIGH)
    names = {item.tool_name for item in actions}
    assert "disable_account" in names
    assert "block_ip" in names
    assert "create_ticket" in names
    assert "notify_security_team" in names


def test_other_low_medium_never_include_destructive_tools() -> None:
    destructive = {"block_ip", "disable_account", "isolate_host", "quarantine_file"}
    for severity in (Severity.LOW, Severity.MEDIUM):
        names = {item.tool_name for item in get_rule_actions(EventType.OTHER, severity)}
        assert names.isdisjoint(destructive)


def test_other_high_critical_include_containment_tools() -> None:
    """ISSUE-197: unresolved OTHER at high severity gets conservative containment."""
    high = {item.tool_name for item in get_rule_actions(EventType.OTHER, Severity.HIGH)}
    critical = {item.tool_name for item in get_rule_actions(EventType.OTHER, Severity.CRITICAL)}
    assert "block_ip" in high
    assert "isolate_host" in critical
    assert "block_ip" in critical


@pytest.mark.asyncio
async def test_llm_failure_falls_back_to_rules() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert plan.actions


@pytest.mark.asyncio
async def test_replay_three_times_same_action_ids() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    event_service = _FakeEventService()
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
    )
    input_data = _agent_input(event_id)
    plan1 = await agent.execute(input_data)
    plan2 = await agent.execute(input_data)
    plan3 = await agent.execute(input_data)
    ids1 = [a.action_id for a in plan1.actions]
    ids2 = [a.action_id for a in plan2.actions]
    ids3 = [a.action_id for a in plan3.actions]
    assert ids1 == ids2 == ids3
    assert len(event_service.actions_by_fp) == len(plan1.actions)


@pytest.mark.asyncio
async def test_playbook_path_used_when_available() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(event_type=EventType.ACCOUNT_ANOMALY))
    wm.values[(event_id, "rag_output")] = {"playbook_refs": [_playbook_ref("pb-a1b2c3d4")]}
    playbook = Playbook(
        playbook_id="pb-a1b2c3d4",
        playbook_name="Account playbook",
        event_type=EventType.ACCOUNT_ANOMALY,
        min_severity=Severity.HIGH,
        steps=[
            PlaybookStep(
                step_order=1,
                action_name="Disable account",
                tool_name="disable_account",
                action_level=ActionLevel.L3,
            ),
            PlaybookStep(
                step_order=2,
                action_name="Create ticket",
                tool_name="create_ticket",
                action_level=ActionLevel.L1,
            ),
        ],
    )
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        playbook_kb_service=_FakePlaybookKB(playbook),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    names = {a.tool_name for a in plan.actions}
    assert "disable_account" in names
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE


@pytest.mark.asyncio
async def test_playbook_release_service_path_used_when_wired() -> None:
    from app.models.knowledge_release import KnowledgeReleaseLifecycleState
    from app.models.playbook_release import PlaybookRef

    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(event_type=EventType.ACCOUNT_ANOMALY))
    ref = PlaybookRef.model_validate(_playbook_ref("pb-a1b2c3d4"))
    wm.values[(event_id, "rag_output")] = {"playbook_refs": [ref.model_dump(mode="json")]}
    playbook = Playbook(
        playbook_id="pb-a1b2c3d4",
        playbook_name="Account playbook",
        event_type=EventType.ACCOUNT_ANOMALY,
        min_severity=Severity.HIGH,
        steps=[
            PlaybookStep(
                step_order=1,
                action_name="Disable account",
                tool_name="disable_account",
                action_level=ActionLevel.L3,
            ),
        ],
    )

    class _FakeReleaseService:
        async def resolve_playbook_ref(
            self,
            playbook_ref: PlaybookRef,
            *,
            allow_retired: bool = False,
        ) -> tuple[Playbook, SimpleNamespace]:
            assert allow_retired is False
            assert playbook_ref.playbook_id == "pb-a1b2c3d4"
            return playbook, SimpleNamespace(
                release_version="v1-test",
                lifecycle_state=KnowledgeReleaseLifecycleState.ACTIVE,
            )

    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        playbook_release_service=_FakeReleaseService(),
        playbook_kb_service=_FakePlaybookKB(None),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    assert any(a.tool_name == "disable_account" for a in plan.actions)
    assert plan.generated_by is ResponsePlanGeneratedBy.TEMPLATE


@pytest.mark.asyncio
async def test_playbook_ref_validation_error_skips_legacy_fallback() -> None:
    from app.core.errors import ValidationError as ShadowValidationError
    from app.models.playbook_release import PlaybookRef

    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(event_type=EventType.ACCOUNT_ANOMALY))
    ref = PlaybookRef.model_validate(_playbook_ref("pb-a1b2c3d4"))
    wm.values[(event_id, "rag_output")] = {"playbook_refs": [ref.model_dump(mode="json")]}
    playbook = Playbook(
        playbook_id="pb-a1b2c3d4",
        playbook_name="Account playbook",
        event_type=EventType.ACCOUNT_ANOMALY,
        min_severity=Severity.HIGH,
        steps=[
            PlaybookStep(
                step_order=1,
                action_name="Disable account",
                tool_name="disable_account",
                action_level=ActionLevel.L3,
            ),
        ],
    )

    class _RejectingReleaseService:
        async def resolve_playbook_ref(self, *_args: Any, **_kwargs: Any) -> tuple[Playbook, Any]:
            raise ShadowValidationError(
                "playbook content hash mismatch",
                details={"reason": "content_hash_mismatch"},
            )

    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        playbook_release_service=_RejectingReleaseService(),
        playbook_kb_service=_FakePlaybookKB(playbook),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    assert not any(a.playbook_ref is not None for a in plan.actions)
    assert "playbook resolution failed" in plan.strategy_summary


@pytest.mark.asyncio
async def test_invalid_playbook_refs_fallback_to_rules_without_playbook_pinning() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(event_type=EventType.ACCOUNT_ANOMALY))
    wm.values[(event_id, "rag_output")] = {
        "playbook_refs": [{"playbook_id": "pb-incomplete-ref-only"}],
    }

    class _RejectingReleaseService:
        async def resolve_playbook_ref(self, *_args: Any, **_kwargs: Any) -> tuple[Playbook, Any]:
            raise AssertionError("resolve_playbook_ref must not run for invalid refs")

    agent = ResponseAgent(
        working_memory=wm,
        capability_manifest=build_mock_capability_manifest(),
        playbook_release_service=_RejectingReleaseService(),
        llm_client=_FailingLLM(),
    )
    plan = await agent.execute(_agent_input(event_id))
    assert not any(a.playbook_ref is not None for a in plan.actions)
    assert "playbook_refs_invalid" in plan.strategy_summary


def test_action_fingerprint_and_id_are_stable() -> None:
    fp = compute_action_fingerprint(
        event_id="evt-1",
        plan_revision=1,
        tool_name="block_ip",
        target_type="ip",
        canonical_target="203.0.113.50",
        normalized_params_hash="abc",
        execution_owner=ExecutionOwner.XDR_MANAGED,
        source_locator_hash="loc",
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        approved_template_hash="",
    )
    assert fp == compute_action_fingerprint(
        event_id="evt-1",
        plan_revision=1,
        tool_name="block_ip",
        target_type="ip",
        canonical_target="203.0.113.50",
        normalized_params_hash="abc",
        execution_owner=ExecutionOwner.XDR_MANAGED,
        source_locator_hash="loc",
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        approved_template_hash="",
    )
    assert derive_stable_action_id(fp).startswith("act-")


def test_plan_id_format() -> None:
    plan_id = generate_response_plan_id("evt-abc", 2)
    assert plan_id.startswith("rsp-")
    assert len(plan_id) == len("rsp-") + 8


def test_approval_confidence_uses_fp_adjudication_max_score() -> None:
    confidence = approval_confidence_for_disposition_only(
        event_confidence=0.5,
        fp_adjudication={
            "recommendation": "close_as_fp",
            "max_score": FP_HIGH_THRESHOLD,
        },
    )
    assert confidence >= FP_HIGH_THRESHOLD


@pytest.mark.asyncio
async def test_actions_persisted_for_query() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    event_service = _FakeEventService()
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
    )
    await agent.execute(_agent_input(event_id))
    rows = event_service.list_actions(event_id)
    assert rows
    assert all(row["status"] == ActionStatus.PENDING.value for row in rows)
    assert all(row["action_category"] == ActionCategory.RESPONSE.value for row in rows)


@pytest.mark.asyncio
async def test_new_revision_supersedes_undeployed_deferred() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    event_service = _FakeEventService()
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(), plan_revision=1)
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
    )
    await agent.execute(_agent_input(event_id))

    wm.values[(event_id, "execution_plan")] = {
        "plan_id": "pln-test",
        "event_id": event_id,
        "revision": 1,
        "steps": [],
    }
    await agent.execute(_agent_input(event_id))
    rows = event_service.list_actions(event_id)
    superseded = [
        row
        for row in rows
        if row["tool_name"] == TERMINAL_DISPOSITION_TOOL
        and row.get("status") == ActionStatus.SUPERSEDED.value
    ]
    pending = [
        row
        for row in rows
        if row["tool_name"] == TERMINAL_DISPOSITION_TOOL
        and row.get("status") == ActionStatus.PENDING.value
    ]
    assert len(superseded) == 1
    assert len(pending) == 1
    assert pending[0]["plan_revision"] == 2


@pytest.mark.asyncio
async def test_dispatched_deferred_is_not_superseded_on_new_revision() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    event_service = _FakeEventService()
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(), plan_revision=1)
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        capability_manifest=build_mock_capability_manifest(),
    )
    plan_v1 = await agent.execute(_agent_input(event_id))
    deferred_v1 = next(a for a in plan_v1.actions if a.tool_name == TERMINAL_DISPOSITION_TOOL)
    event_service.actions_by_fp[deferred_v1.action_fingerprint]["execution_job_id"] = "job-dispatch"
    event_service.actions_by_fp[deferred_v1.action_fingerprint]["status"] = (
        ActionStatus.EXECUTING.value
    )

    wm.values[(event_id, "execution_plan")] = {
        "plan_id": "pln-test",
        "event_id": event_id,
        "revision": 1,
        "steps": [],
    }
    await agent.execute(_agent_input(event_id))
    dispatched = event_service.actions_by_fp[deferred_v1.action_fingerprint]
    assert dispatched["status"] == ActionStatus.EXECUTING.value
    assert dispatched.get("execution_job_id") == "job-dispatch"


@pytest.mark.asyncio
async def test_low_severity_llm_proposal_capped_to_ticket_only() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(
        wm,
        event_id,
        triage=_triage(event_type=EventType.OTHER, severity=Severity.LOW),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )
    agent = ResponseAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=_FakeEventService(disposition_policy=DispositionPolicy.NOT_REQUIRED),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(
        ResponseAgentInput(
            event_id=event_id,
            risk_assessment=_risk(Severity.LOW, score=12),
            evidence_output=EvidenceOutput(
                evidence_list=[],
                collection_status=CollectionStatus.COMPLETED,
                overall_confidence=0.3,
            ),
        )
    )
    immediate = [a for a in plan.actions if a.tool_name != TERMINAL_DISPOSITION_TOOL]
    assert len(immediate) == 1
    assert immediate[0].tool_name == "create_ticket"


@pytest.mark.asyncio
async def test_deferred_writeback_blocked_when_locator_missing() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage())
    wm.values[(event_id, "event")] = {
        "event_id": event_id,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
    }
    manifest = build_mock_capability_manifest()
    manifest = manifest.model_copy(update={"event_disposition": CapabilityState.UNKNOWN})
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        capability_manifest=manifest,
    )
    plan = await agent.execute(_agent_input(event_id))
    deferred = next(a for a in plan.actions if a.tool_name == TERMINAL_DISPOSITION_TOOL)
    assert deferred.writeback_required is True
    assert deferred.writeback_applicable is True
    assert deferred.writeback_readiness.value != "ready"
    assert deferred.auto_execute is False


@pytest.mark.asyncio
async def test_playbook_expands_all_entity_targets() -> None:
    event_id = f"evt-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    _seed_wm(wm, event_id, triage=_triage(event_type=EventType.DATA_EXFILTRATION))
    wm.values[(event_id, "rag_output")] = {"playbook_refs": [_playbook_ref("pb-a1b2c3d5")]}
    playbook = Playbook(
        playbook_id="pb-a1b2c3d5",
        playbook_name="Multi IP block",
        event_type=EventType.DATA_EXFILTRATION,
        min_severity=Severity.HIGH,
        steps=[
            PlaybookStep(
                step_order=1,
                action_name="Block external IPs",
                tool_name="block_ip",
                action_level=ActionLevel.L2,
            ),
        ],
    )
    agent = ResponseAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FakeEventService(),
        playbook_kb_service=_FakePlaybookKB(playbook),
        capability_manifest=build_mock_capability_manifest(),
    )
    plan = await agent.execute(_agent_input(event_id))
    block_actions = [a for a in plan.actions if a.tool_name == "block_ip"]
    targets = {a.target for a in block_actions}
    assert "203.0.113.50" in targets
    assert "10.0.0.5" in targets


def test_enforce_execution_owner_consistency_drops_direct_tool() -> None:
    manifest = build_mock_capability_manifest()

    class _OwnerFilter(ResponsePolicyFilter):
        def resolve_execution_owner(self, tool_name: str) -> ExecutionOwner | None:
            if tool_name == "disable_account":
                return ExecutionOwner.XDR_MANAGED
            if tool_name == "create_ticket":
                return ExecutionOwner.DIRECT_TOOL
            return super().resolve_execution_owner(tool_name)

    owner_filter = _OwnerFilter(
        manifest=manifest,
        entities=_entities(),
        disposition_policy=DispositionPolicy.REQUIRED,
        source_locator=None,
    )
    candidates = [
        ActionCandidate(
            tool_name="disable_account",
            target_type="account",
            target="svc-backup",
            parameters={},
            reason="managed",
        ),
        ActionCandidate(
            tool_name="create_ticket",
            target_type="ticket",
            target="ticket",
            parameters={"title": "t", "description": "d"},
            reason="direct",
        ),
    ]
    filtered = _enforce_execution_owner_consistency(candidates, owner_filter)
    assert [item.tool_name for item in filtered] == ["disable_account"]


def test_cap_low_severity_candidates_limits_to_ticket() -> None:
    candidates = [
        ActionCandidate("disable_account", "account", "svc-backup", {}, "x"),
        ActionCandidate("create_ticket", "ticket", "ticket", {}, "y"),
    ]
    capped = _cap_low_severity_candidates(
        candidates,
        Severity.LOW,
        disposition_only=False,
    )
    assert [item.tool_name for item in capped] == ["create_ticket"]
