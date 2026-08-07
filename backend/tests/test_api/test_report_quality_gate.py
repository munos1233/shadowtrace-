"""ISSUE-212 — POST /events/{id}/report quality gate HTTP semantics (unit)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.agents.report_section_builder import (
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    SECTION_KEYS,
)
from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.main import app
from app.models.agent_io import ReportPhaseStatus
from app.models.enums import EventStatus, FinalVerdict, ReportQuality, Severity
from app.models.report import InvestigationReport, ReportSection

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
    monkeypatch.setenv("REPORT_QUALITY_GATE_ENFORCED", "true")
    get_settings.cache_clear()
    reset_deps()
    app.dependency_overrides.clear()
    yield
    reset_deps()
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


def _event_stub(event_id: str, *, status: EventStatus = EventStatus.REPORTING) -> SimpleNamespace:
    return SimpleNamespace(event_id=event_id, status=status)


def _sections(**overrides: str) -> list[ReportSection]:
    contents = {key: f"content for {key}" for key in SECTION_KEYS}
    contents["executed_actions"] = NOT_EXECUTED_ACTIONS
    contents["verification_results"] = NOT_EXECUTED_VERIFICATION
    contents.update(overrides)
    return [ReportSection(key=key, title=key, content=contents[key]) for key in SECTION_KEYS]


def _report(
    *,
    generated_by: str = "llm",
    report_quality: ReportQuality = ReportQuality.COMPLETE,
    sections: list[ReportSection] | None = None,
) -> InvestigationReport:
    return InvestigationReport(
        report_id="rpt-evt-212-gate",
        event_id="evt-212-gate",
        title="gate test",
        summary="summary",
        sections=sections or _sections(),
        final_verdict=FinalVerdict.NONE,
        risk_score=40,
        severity=Severity.MEDIUM,
        generated_by=generated_by,
        generated_at=datetime.now(UTC),
        report_quality=report_quality,
    )


def _client_with_event_service(event_service: object) -> TestClient:
    from app.api.v1.deps import get_event_service

    async def _override() -> object:
        return event_service

    app.dependency_overrides[get_event_service] = _override
    return TestClient(app)


def _patch_generate_stack(
    *,
    report: InvestigationReport,
    response_phase: ReportPhaseStatus = ReportPhaseStatus.EXECUTED,
    verification_phase: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED,
):
    """Patch POST generate_report dependencies around ReportAgent.execute."""
    from app.models.agent_io import (
        CollectionStatus,
        EvidenceOutput,
        RiskAssessment,
        ScoringMode,
    )

    store = AsyncMock()

    async def _store_get(_eid: str, key: str) -> object | None:
        if key == "evidence_output":
            return EvidenceOutput(
                evidence_list=[],
                conflicts=[],
                gaps=[],
                success_sources=[],
                failed_sources=[],
                overall_confidence=0.5,
                collection_status=CollectionStatus.COMPLETED,
            )
        if key == "risk_assessment":
            return RiskAssessment(
                risk_score=40,
                severity=Severity.MEDIUM,
                confidence=0.5,
                risk_factors=[],
                possible_false_positive=False,
                scoring_mode=ScoringMode.RULE_ONLY,
            )
        return None

    store.get = AsyncMock(side_effect=_store_get)
    report_agent = AsyncMock()
    report_agent.execute = AsyncMock(return_value=report)
    stack = {"report": report_agent, "session_factory": MagicMock()}

    report_input = SimpleNamespace(
        response_phase_status=response_phase,
        verification_phase_status=verification_phase,
    )

    def _model_copy(*, update: dict | None = None) -> SimpleNamespace:
        payload = {
            "response_phase_status": response_phase,
            "verification_phase_status": verification_phase,
        }
        if update:
            payload.update(update)
        return SimpleNamespace(**payload)

    report_input.model_copy = _model_copy  # type: ignore[attr-defined]
    return store, stack, report_input


@pytest.mark.asyncio
async def test_post_report_rejects_incomplete_without_force() -> None:
    incomplete = _report(
        generated_by="llm",
        report_quality=ReportQuality.INCOMPLETE_PLACEHOLDER,
        sections=_sections(executed_actions=INCOMPLETE_ACTIONS_PLACEHOLDER),
    )
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(incomplete.event_id),
    )
    event_service.get_report = AsyncMock(return_value=None)
    event_service.upsert_report = AsyncMock()
    event_service.upsert_generate_report_action = AsyncMock()

    store, stack, report_input = _patch_generate_stack(report=incomplete)
    client = _client_with_event_service(event_service)

    with (
        patch("app.api.v1.events._get_context_store", return_value=store),
        patch(
            "app.api.v1.deps._get_investigation_stack",
            new=AsyncMock(return_value=stack),
        ),
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=report_input),
        ),
        patch("app.api.v1.events._get_session_factory", return_value=MagicMock()),
        patch(
            "app.services.report_quality.with_assessed_quality",
            return_value=incomplete,
        ),
    ):
        resp = client.post(
            f"/api/v1/events/{incomplete.event_id}/report",
            headers=_hdr(),
            json={"force": False},
        )

    assert resp.status_code == 422
    body = resp.json()
    assert body["error_code"] == "report_quality_incomplete"
    event_service.upsert_report.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_report_force_archives_incomplete() -> None:
    incomplete = _report(
        generated_by="llm",
        report_quality=ReportQuality.INCOMPLETE_PLACEHOLDER,
        sections=_sections(executed_actions=INCOMPLETE_ACTIONS_PLACEHOLDER),
    )
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(incomplete.event_id),
    )
    event_service.get_report = AsyncMock(return_value=None)
    event_service.upsert_report = AsyncMock(return_value=incomplete)
    event_service.upsert_generate_report_action = AsyncMock()

    store, stack, report_input = _patch_generate_stack(report=incomplete)
    client = _client_with_event_service(event_service)

    with (
        patch("app.api.v1.events._get_context_store", return_value=store),
        patch(
            "app.api.v1.deps._get_investigation_stack",
            new=AsyncMock(return_value=stack),
        ),
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=report_input),
        ),
        patch("app.api.v1.events._get_session_factory", return_value=MagicMock()),
        patch(
            "app.services.report_quality.with_assessed_quality",
            return_value=incomplete,
        ),
        patch("app.api.v1.events._sync_report_context_and_bus", new=AsyncMock()),
    ):
        resp = client.post(
            f"/api/v1/events/{incomplete.event_id}/report?force=true",
            headers=_hdr(),
        )

    assert resp.status_code == 200
    assert resp.json()["report"]["report_quality"] == "incomplete_placeholder"
    event_service.upsert_report.assert_awaited()


@pytest.mark.asyncio
async def test_post_report_template_returns_degraded_template() -> None:
    template = _report(
        generated_by="template",
        report_quality=ReportQuality.DEGRADED_TEMPLATE,
    )
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(template.event_id),
    )
    event_service.get_report = AsyncMock(return_value=None)
    event_service.upsert_report = AsyncMock(return_value=template)
    event_service.upsert_generate_report_action = AsyncMock()

    store, stack, report_input = _patch_generate_stack(
        report=template,
        response_phase=ReportPhaseStatus.NOT_EXECUTED,
    )
    client = _client_with_event_service(event_service)

    with (
        patch("app.api.v1.events._get_context_store", return_value=store),
        patch(
            "app.api.v1.deps._get_investigation_stack",
            new=AsyncMock(return_value=stack),
        ),
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=report_input),
        ),
        patch("app.api.v1.events._get_session_factory", return_value=MagicMock()),
        patch(
            "app.services.report_quality.with_assessed_quality",
            return_value=template,
        ),
        patch("app.api.v1.events._sync_report_context_and_bus", new=AsyncMock()),
    ):
        resp = client.post(
            f"/api/v1/events/{template.event_id}/report",
            headers=_hdr(),
            json={},
        )

    assert resp.status_code == 200
    payload = resp.json()["report"]
    assert payload["report_quality"] == "degraded_template"
    assert payload["degraded"] is True


@pytest.mark.asyncio
async def test_post_report_downgrade_complete_requires_confirm() -> None:
    complete = _report(
        generated_by="llm",
        report_quality=ReportQuality.COMPLETE,
    )
    degraded = _report(
        generated_by="template",
        report_quality=ReportQuality.DEGRADED_TEMPLATE,
    )
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(degraded.event_id),
    )
    event_service.get_report = AsyncMock(return_value=complete)
    event_service.upsert_report = AsyncMock()
    event_service.upsert_generate_report_action = AsyncMock()

    store, stack, report_input = _patch_generate_stack(report=degraded)
    client = _client_with_event_service(event_service)

    with (
        patch("app.api.v1.events._get_context_store", return_value=store),
        patch(
            "app.api.v1.deps._get_investigation_stack",
            new=AsyncMock(return_value=stack),
        ),
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=report_input),
        ),
        patch("app.api.v1.events._get_session_factory", return_value=MagicMock()),
        patch(
            "app.services.report_quality.with_assessed_quality",
            return_value=degraded,
        ),
    ):
        resp = client.post(
            f"/api/v1/events/{degraded.event_id}/report",
            headers=_hdr(),
            json={"force": True},
        )

    assert resp.status_code == 409
    assert resp.json()["error_code"] == "report_quality_conflict"
    event_service.upsert_report.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_report_incomplete_assessed_without_mocking_quality() -> None:
    """POST gate must use real with_assessed_quality (not a stubbed quality)."""
    # Agent returns llm report with EXECUTED-phase placeholder content but a
    # misleading report_quality=complete stamp — assess must rewrite it.
    raw = _report(
        generated_by="llm",
        report_quality=ReportQuality.COMPLETE,
        sections=_sections(executed_actions=INCOMPLETE_ACTIONS_PLACEHOLDER),
    )
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(raw.event_id),
    )
    event_service.get_report = AsyncMock(return_value=None)
    event_service.upsert_report = AsyncMock()
    event_service.upsert_generate_report_action = AsyncMock()

    store, stack, report_input = _patch_generate_stack(
        report=raw,
        response_phase=ReportPhaseStatus.EXECUTED,
    )
    client = _client_with_event_service(event_service)

    with (
        patch("app.api.v1.events._get_context_store", return_value=store),
        patch(
            "app.api.v1.deps._get_investigation_stack",
            new=AsyncMock(return_value=stack),
        ),
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=report_input),
        ),
        patch("app.api.v1.events._get_session_factory", return_value=MagicMock()),
    ):
        resp = client.post(
            f"/api/v1/events/{raw.event_id}/report",
            headers=_hdr(),
            json={"force": False},
        )

    assert resp.status_code == 422
    body = resp.json()
    assert body["error_code"] == "report_quality_incomplete"
    assert body["details"]["report_quality"] == "incomplete_placeholder"
    event_service.upsert_report.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_report_rejects_analyzing_lifecycle() -> None:
    """ISSUE-206: refuse POST /report while investigation is still running."""
    event_id = "evt-206-analyzing"
    event_service = AsyncMock()
    event_service.get_event = AsyncMock(
        return_value=_event_stub(event_id, status=EventStatus.ANALYZING)
    )
    client = _client_with_event_service(event_service)

    resp = client.post(f"/api/v1/events/{event_id}/report", headers=_hdr())

    assert resp.status_code == 400
    body = resp.json()
    assert body["error_code"] == "invalid_state_transition"
    assert body["details"]["status"] == "analyzing"
