"""ISSUE-204 — optional report generation and closed_requires_report."""

from __future__ import annotations

import json

import pytest

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.core.errors import InvalidStateTransitionError
from app.models.enums import DispositionPolicy, EventStatus
from app.models.workflow import TransitionContext, validate_closed_gate
from app.services.investigation_guidance import derive_investigation_guidance

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    get_settings.cache_clear()
    reset_deps()
    yield
    reset_deps()
    get_settings.cache_clear()


def test_closed_gate_uses_closed_requires_report_error_code() -> None:
    with pytest.raises(InvalidStateTransitionError) as exc:
        validate_closed_gate(
            TransitionContext(
                report_exists=False,
                disposition_policy=DispositionPolicy.NOT_REQUIRED,
            )
        )
    assert exc.value.error_code == "closed_requires_report"
    assert exc.value.details.get("report_exists") is False
    assert "POST /api/v1/events/{event_id}/report" in str(exc.value)


def test_reporting_guidance_when_report_skipped() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.REPORTING,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
        context_snapshot={"report_generated": False},
        orchestration_mode="graph",
    )
    assert guidance.phase_message == "分析完成·报告未生成"
    assert "生成中" not in (guidance.phase_message or "")


def test_investigate_request_default_generate_report_true() -> None:
    from app.api.v1 import schemas as s

    req = s.InvestigateRequest()
    assert req.generate_report is True


def test_investigate_response_echoes_generate_report() -> None:
    from app.api.v1 import schemas as s

    resp = s.InvestigateResponse(
        event_id="evt-204",
        task_id="evt-204",
        status=EventStatus.NEW,
        generate_report=False,
    )
    assert resp.generate_report is False


def test_route_after_report_skips_close_when_report_not_requested() -> None:
    from app.orchestration.graph_state import InvestigationState
    from app.orchestration.workflow_graph import route_after_report

    state: InvestigationState = {
        "event_id": "evt-204",
        "generate_report": False,
        "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
    }  # type: ignore[typeddict-item]
    assert route_after_report(state) == "halt"


def test_route_after_triage_skips_close_when_generate_report_false() -> None:
    from app.orchestration.workflow_graph import ROUTE_REPORT, route_after_triage

    assert (
        route_after_triage(
            {  # type: ignore[arg-type]
                "event_id": "evt-204",
                "need_investigation": False,
                "generate_report": False,
                "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
            }
        )
        == ROUTE_REPORT
    )


@pytest.mark.asyncio
async def test_analysis_only_persist_report_skipped_sets_flag() -> None:
    from unittest.mock import AsyncMock, MagicMock

    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

    store = AsyncMock()
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        context_store=store,
    )
    await pipeline._persist_report_skipped("evt-204-skip")
    store.set.assert_awaited_with("evt-204-skip", "report_generated", False)


@pytest.mark.asyncio
async def test_analysis_only_short_circuit_skips_report_when_generate_report_false() -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from app.models.agent_io import TriageResult
    from app.models.enums import EventType, Severity
    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

    report_agent = MagicMock()
    report_agent.execute = AsyncMock()
    store = AsyncMock()
    state_machine = AsyncMock()
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=report_agent,
        context_store=store,
        state_machine=state_machine,
    )
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        decision_summary="low risk",
    )
    event = SimpleNamespace(title="t", disposition_policy=DispositionPolicy.NOT_REQUIRED)
    result = await pipeline._short_circuit_close(
        "evt-204-sc",
        event,
        triage,
        generate_report=False,
    )
    report_agent.execute.assert_not_awaited()
    assert result.report is None
    assert result.status is EventStatus.REPORTING
    store.set.assert_any_await("evt-204-sc", "report_generated", False)
    # First transition should be to REPORTING (not CLOSED).
    first_call = state_machine.transition.await_args_list[0]
    assert first_call.args[1] is EventStatus.REPORTING
