"""ISSUE-205: unified ReportAgentInput builder backfill tests.

Covers the acceptance criteria:
- existing response_plan / verification_result are backfilled (never the
  silent 「暂无…」 placeholders);
- analysis-only style calls without any persisted phase render 「本调查未执行…」;
- ORM/context read failures degrade explicitly instead of swallowing data;
- the ORM fallback never fabricates execution results.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.agents.report_section_builder import (
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    INCOMPLETE_VERIFICATION_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    UNAVAILABLE_ACTIONS,
    UNAVAILABLE_VERIFICATION,
    ReportSectionBuilder,
)
from app.agents.response_agent import generate_response_plan_id
from app.models.action import Action
from app.models.agent_io import (
    CollectionStatus,
    EffectStatus,
    EvidenceOutput,
    ReportAgentInput,
    ReportPhaseStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
    Severity,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    WritebackReadiness,
)
from app.models.context import EventContext
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ExecutionOwner,
)
from app.models.enums import (
    WritebackReadiness as WritebackReadinessEnum,
)
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
from app.services.report_input_builder import build_report_agent_input

EVENT_ID = "evt-report-builder-205"


def _evidence() -> EvidenceOutput:
    return EvidenceOutput(collection_status=CollectionStatus.COMPLETED)


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=55,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _response_action(
    *,
    action_id: str = "act-205-001",
    status: ActionStatus = ActionStatus.SUCCESS,
    plan_revision: int = 1,
) -> Action:
    return Action(
        action_id=action_id,
        event_id=EVENT_ID,
        plan_revision=plan_revision,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=status,
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def _plan(*, plan_id: str = "plan-205") -> ResponsePlan:
    return ResponsePlan(
        plan_id=plan_id,
        actions=[_response_action()],
        strategy_summary="contain exfiltration",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )


def _verification() -> VerificationResult:
    return VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
        results=[
            VerificationActionResult(
                action_id="act-205-001",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )
        ],
    )


class _FakeContextStore:
    def __init__(
        self,
        data: dict[str, Any] | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.data = data or {}
        self.error = error
        self.reads: list[str] = []

    async def get(self, event_id: str, key: str) -> Any:
        assert event_id == EVENT_ID
        self.reads.append(key)
        if self.error is not None:
            raise self.error
        return self.data.get(key)


class _JournalResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def first(self) -> Any:
        if self._value is None:
            return None
        return (self._value,)


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _ActionsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class _FakeSession:
    """Scripted stand-in for AsyncSession; returns queued results in call order."""

    def __init__(self, results: list[Any], *, error: Exception | None = None) -> None:
        self._results = list(results)
        self.error = error
        self.calls = 0

    async def execute(self, _statement: Any) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self._results.pop(0)


def _orm_action_row(
    *,
    action_id: str = "act-orm-001",
    status: str = ActionStatus.PENDING.value,
    plan_revision: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        action_id=action_id,
        event_id=EVENT_ID,
        plan_revision=plan_revision,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE.value,
        action_name="Isolate host",
        tool_name="isolate_host",
        action_level=ActionLevel.L4.value,
        execution_phase="immediate",
        activation_condition=None,
        approved_operation_template_hash=None,
        approved_terminal_dispositions=[],
        target_type="host",
        target="PC-FIN-023",
        parameters={},
        status=status,
        auto_execute=False,
        reason=None,
        impact_assessment=None,
        playbook_id=None,
        playbook_ref=None,
        action_template_snapshot=None,
        provider_name=None,
        execution_owner=ExecutionOwner.XDR_MANAGED.value,
        execution_job_id=None,
        tool_call_id=None,
        idempotency_key=None,
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadinessEnum.NOT_REQUIRED.value,
        writeback_block_reason=None,
        writeback_status=None,
        disposition_source_ref=None,
        superseded_by_revision=None,
        executed_at=None,
        effect_verification_status=None,
        rollback_status=None,
        source_action_id=None,
        updated_at=None,
    )


async def _build(**kwargs: Any) -> ReportAgentInput:
    return await build_report_agent_input(
        EVENT_ID,
        evidence_output=_evidence(),
        risk_assessment=_risk(),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Backfill resolution
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_backfills_plan_from_state_and_verification_from_store() -> None:
    store = _FakeContextStore({"verification_result": _verification().model_dump(mode="json")})
    result = await _build(
        state={"response_plan": _plan().model_dump(mode="json")},
        context_store=store,
        escalated=True,
        replan_count=2,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-205"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_result is not None
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED
    assert result.escalated is True
    assert result.replan_count == 2
    # The plan was satisfied from state — the store is only read for verify.
    assert store.reads == ["verification_result"]


@pytest.mark.asyncio
async def test_backfills_from_event_context() -> None:
    ec = EventContext(
        response_plan=_plan().model_dump(mode="json"),
        verification_result=_verification().model_dump(mode="json"),
    )
    result = await _build(event_context=ec)
    assert result.response_plan is not None
    assert result.verification_result is not None
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_state_takes_precedence_over_event_context() -> None:
    ec = EventContext(response_plan=_plan(plan_id="plan-from-ec").model_dump(mode="json"))
    result = await _build(
        state={"response_plan": _plan(plan_id="plan-from-state").model_dump(mode="json")},
        event_context=ec,
    )
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-from-state"


@pytest.mark.asyncio
async def test_no_sources_defaults_to_not_executed() -> None:
    result = await _build()
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_context_store_read_failure_is_unavailable_not_placeholder() -> None:
    store = _FakeContextStore(error=RuntimeError("context store unavailable"))
    result = await _build(context_store=store)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.UNAVAILABLE
    assert result.verification_phase_status is ReportPhaseStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_invalid_state_plan_fails_closed_to_incomplete() -> None:
    result = await _build(state={"response_plan": {"plan_id": "broken"}})
    assert result.response_plan is None
    assert result.response_phase_status is ReportPhaseStatus.INCOMPLETE


@pytest.mark.asyncio
async def test_invalid_store_verification_fails_closed_to_incomplete() -> None:
    store = _FakeContextStore({"verification_result": {"overall_status": "not-a-status"}})
    result = await _build(context_store=store)
    assert result.verification_result is None
    assert result.verification_phase_status is ReportPhaseStatus.INCOMPLETE


# --------------------------------------------------------------------------- #
# ORM (session) fallback
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_session_journal_fallback_restores_plan_and_verification() -> None:
    session = _FakeSession(
        [
            _JournalResult(_plan(plan_id="plan-journal").model_dump(mode="json")),
            _JournalResult(_verification().model_dump(mode="json")),
        ]
    )
    result = await _build(session=session)
    assert result.response_plan is not None
    assert result.response_plan.plan_id == "plan-journal"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.verification_result is not None
    assert result.verification_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_session_action_table_fallback_derives_plan_without_fabrication() -> None:
    session = _FakeSession(
        [
            _JournalResult(None),  # response_plan journal: absent
            _ActionsResult(
                [
                    _orm_action_row(action_id="act-orm-001", plan_revision=1),
                    _orm_action_row(
                        action_id="act-orm-002",
                        status=ActionStatus.PENDING.value,
                        plan_revision=2,
                    ),
                ]
            ),
            _JournalResult(None),  # verification_result journal: absent
        ]
    )
    result = await _build(session=session)
    plan = result.response_plan
    assert plan is not None
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert plan.generated_by is ResponsePlanGeneratedBy.RECOVERED
    assert plan.plan_id == generate_response_plan_id(EVENT_ID, 2)
    assert [a.action_id for a in plan.actions] == ["act-orm-001", "act-orm-002"]
    # Never fabricate success: pending rows stay pending.
    assert plan.actions[1].status is ActionStatus.PENDING
    assert "Action 表恢复" in plan.strategy_summary
    # No verification data exists anywhere — honest NOT_EXECUTED.
    assert result.verification_result is None
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_session_factory_opens_session_for_action_recovery() -> None:
    """Production call sites pass session_factory; builder must open it for ORM."""
    session = _FakeSession(
        [
            _JournalResult(None),
            _ActionsResult([_orm_action_row(action_id="act-factory-001", plan_revision=1)]),
            _JournalResult(None),
        ]
    )

    class _Factory:
        def __init__(self) -> None:
            self.entered = 0

        def __call__(self) -> Any:
            factory = self

            class _Ctx:
                async def __aenter__(self) -> _FakeSession:
                    factory.entered += 1
                    return session

                async def __aexit__(self, *_args: Any) -> None:
                    return None

            return _Ctx()

    factory = _Factory()
    result = await _build(session_factory=factory)
    assert factory.entered == 1
    assert result.response_plan is not None
    assert result.response_plan.actions[0].action_id == "act-factory-001"
    assert result.response_phase_status is ReportPhaseStatus.EXECUTED
    assert result.response_plan.generated_by is ResponsePlanGeneratedBy.RECOVERED


@pytest.mark.asyncio
async def test_session_failure_marks_unavailable() -> None:
    session = _FakeSession([], error=RuntimeError("db unavailable"))
    result = await _build(session=session)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.UNAVAILABLE
    assert result.verification_phase_status is ReportPhaseStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_empty_session_leaves_not_executed() -> None:
    session = _FakeSession(
        [
            _JournalResult(None),  # response_plan journal
            _ActionsResult([]),  # Action table
            _JournalResult(None),  # verification_result journal
        ]
    )
    result = await _build(session=session)
    assert result.response_plan is None
    assert result.verification_result is None
    assert result.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert result.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


# --------------------------------------------------------------------------- #
# Section rendering contract (builder status → chapter wording)
# --------------------------------------------------------------------------- #


def _sections(**kwargs: Any) -> dict[str, Any]:
    sections = ReportSectionBuilder().build(
        event_id=EVENT_ID,
        evidence_output=_evidence(),
        risk_assessment=_risk(),
        **kwargs,
    )
    return {s.key: s for s in sections}


def test_sections_default_to_not_executed_wording() -> None:
    by_key = _sections()
    executed = by_key["executed_actions"].content
    assert NOT_EXECUTED_ACTIONS in executed
    assert executed.endswith(NOT_EXECUTED_ACTIONS)
    assert "actions_status_summary:" in executed
    assert by_key["verification_results"].content == NOT_EXECUTED_VERIFICATION
    assert PLACEHOLDER_NO_ACTIONS not in executed
    assert PLACEHOLDER_NO_VERIFICATION not in by_key["verification_results"].content


def test_sections_list_actions_when_plan_backfilled() -> None:
    by_key = _sections(
        response_plan=_plan(),
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_result=_verification(),
        verification_phase_status=ReportPhaseStatus.EXECUTED,
    )
    executed = by_key["executed_actions"].content
    verification = by_key["verification_results"].content
    assert "act-205-001" in executed
    assert PLACEHOLDER_NO_ACTIONS not in executed
    assert NOT_EXECUTED_ACTIONS not in executed
    assert PLACEHOLDER_NO_VERIFICATION not in verification
    assert NOT_EXECUTED_VERIFICATION not in verification
    assert "overall_status=success" in verification


def test_unavailable_status_marks_sections_degraded() -> None:
    by_key = _sections(
        response_phase_status=ReportPhaseStatus.UNAVAILABLE,
        verification_phase_status=ReportPhaseStatus.UNAVAILABLE,
    )
    executed = by_key["executed_actions"].content
    assert UNAVAILABLE_ACTIONS in executed
    assert executed.endswith(UNAVAILABLE_ACTIONS)
    assert "actions_status_summary:" in executed
    assert by_key["verification_results"].content == UNAVAILABLE_VERIFICATION
    assert by_key["executed_actions"].data.get("degraded") is True
    assert by_key["verification_results"].data.get("degraded") is True


def test_incomplete_status_uses_incomplete_placeholder() -> None:
    for status in (ReportPhaseStatus.EXECUTED, ReportPhaseStatus.INCOMPLETE):
        by_key = _sections(
            response_phase_status=status,
            verification_phase_status=status,
        )
        executed = by_key["executed_actions"].content
        assert INCOMPLETE_ACTIONS_PLACEHOLDER in executed
        assert executed.endswith(INCOMPLETE_ACTIONS_PLACEHOLDER)
        assert "actions_status_summary:" in executed
        assert by_key["verification_results"].content == INCOMPLETE_VERIFICATION_PLACEHOLDER


def test_backfilled_data_wins_even_with_default_status() -> None:
    # Callers that pass data without an explicit status must never see the
    # NOT_EXECUTED wording — present data always renders.
    by_key = _sections(response_plan=_plan(), verification_result=_verification())
    assert "act-205-001" in by_key["executed_actions"].content
    assert "overall_status=success" in by_key["verification_results"].content


# --------------------------------------------------------------------------- #
# Call-site wiring regressions
# --------------------------------------------------------------------------- #


class _CapturingReportAgent:
    def __init__(self) -> None:
        self.inputs: list[ReportAgentInput] = []

    async def execute(self, input: ReportAgentInput) -> None:
        self.inputs.append(input)
        return None


@pytest.mark.asyncio
async def test_analysis_only_pipeline_report_input_is_not_executed() -> None:
    """Analysis-only never runs response/verify → chapters say 「未执行」."""
    report_agent = _CapturingReportAgent()
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=report_agent,
        context_store=_FakeContextStore(),
    )
    await pipeline._run_report(EVENT_ID, _evidence(), _risk())
    assert len(report_agent.inputs) == 1
    captured = report_agent.inputs[0]
    assert captured.response_plan is None
    assert captured.verification_result is None
    assert captured.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert captured.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_analysis_only_pipeline_backfills_existing_context() -> None:
    report_agent = _CapturingReportAgent()
    store = _FakeContextStore(
        {
            "response_plan": _plan().model_dump(mode="json"),
            "verification_result": _verification().model_dump(mode="json"),
        }
    )
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=report_agent,
        context_store=store,
    )
    await pipeline._run_report(EVENT_ID, _evidence(), _risk())
    captured = report_agent.inputs[0]
    assert captured.response_plan is not None
    assert captured.verification_result is not None
    assert captured.response_phase_status is ReportPhaseStatus.EXECUTED


@pytest.mark.asyncio
async def test_builder_rejects_unknown_fields_via_model() -> None:
    """ReportAgentInput stays extra=forbid — the builder must not smuggle fields."""
    with pytest.raises(ValidationError):
        ReportAgentInput(
            event_id=EVENT_ID,
            evidence_output=_evidence(),
            risk_assessment=_risk(),
            response_phase_status="bogus",  # type: ignore[arg-type]
        )


def test_report_executed_actions_splits_writeback_obligation_and_applicability() -> None:
    """ISSUE-331: entity actions keep required=true/applicable=false in report prose."""
    builder = ReportSectionBuilder()
    entity = Action(
        action_id="act-entity-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-entity",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )
    terminal = Action(
        action_id="act-terminal-331",
        event_id=EVENT_ID,
        plan_revision=1,
        action_fingerprint="fp-terminal",
        action_category=ActionCategory.RESPONSE,
        action_name="Update disposition",
        tool_name="update_source_event_disposition",
        action_level=ActionLevel.L1,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        activation_condition="after_effect_resolution",
        status=ActionStatus.APPROVED,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
    )
    text = builder._executed_actions([entity, terminal], ReportPhaseStatus.EXECUTED)
    assert "writeback_required=True | writeback_applicable=False" in text
    assert "writeback_not_applicable_reason=entity_side_effect" in text
    assert "writeback_required=True | writeback_applicable=True" in text
    assert "writeback_status=null" in text


def test_report_verification_results_marks_writeback_not_applicable() -> None:
    """ISSUE-331: verification chapter must not imply entity row completed terminal wb."""
    builder = ReportSectionBuilder()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.DISPOSITION,
        results=[
            VerificationActionResult(
                action_id="act-entity-331",
                effect_status=EffectStatus.SKIPPED,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                writeback_status=None,
                detail="writeback_not_applicable",
                verification_phase=VerificationPhase.DISPOSITION,
            )
        ],
    )
    text = builder._verification_results(verification, ReportPhaseStatus.EXECUTED)
    assert "writeback_applicable=false" in text
    assert "writeback_not_applicable_reason=entity_side_effect" in text
    assert "detail=writeback_not_applicable" in text
