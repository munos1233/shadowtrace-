"""OpenTelemetry bootstrap tests (ISSUE-092)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import BaseModel, ConfigDict

from app.agents.base import BaseAgent
from app.core import metrics as metrics_module
from app.core.config import get_settings
from app.core.llm.base import (
    BaseLLMClient,
    InMemoryLLMCallAuditRecorder,
    LLMMessage,
    ProviderResponse,
)
from app.core.metrics import (
    observe_writeback_queue_age,
    record_action_unknown,
    record_writeback,
    record_writeback_dead_letter,
    record_writeback_retry,
    reset_metrics_for_tests,
)
from app.core.telemetry import (
    disposition_span,
    is_telemetry_enabled,
    reset_telemetry_for_tests,
    setup_telemetry,
    traced_operation,
)
from app.models.agent_io import TriageAgentInput
from app.models.enums import ToolCategory
from app.models.tool_meta import RoutingKind, ToolMeta, ToolResult, ToolResultStatus
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry


class _StubLLM(BaseLLMClient):
    async def _request(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> ProviderResponse:
        del messages, temperature, max_tokens, json_mode
        return ProviderResponse(content='{"ok": true}', model_name=model_name)


def _metric_sum(metric_reader: InMemoryMetricReader, name: str) -> float:
    data = metric_reader.collect()
    if data is None:
        data = metric_reader.get_metrics_data()
    assert data is not None
    total = 0.0
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name != name:
                    continue
                for point in metric.data.data_points:
                    total += float(point.value)
    return total


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    get_settings.cache_clear()
    monkeypatch.delenv("OTEL_ENABLED", raising=False)
    reset_telemetry_for_tests()
    reset_metrics_for_tests()
    yield
    get_settings.cache_clear()
    reset_telemetry_for_tests()
    reset_metrics_for_tests()


TelemetryReaders = tuple[InMemorySpanExporter, InMemoryMetricReader, TracerProvider]


@pytest.fixture
def enabled_telemetry(monkeypatch: pytest.MonkeyPatch) -> Iterator[TelemetryReaders]:
    """Patch tracer/meter accessors without fighting global provider overrides."""
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])

    monkeypatch.setattr("app.core.telemetry._ENABLED", True)
    monkeypatch.setattr(
        "app.core.telemetry.get_tracer",
        lambda name: tracer_provider.get_tracer(name),
    )
    monkeypatch.setattr(
        "app.core.telemetry.get_meter",
        lambda name: meter_provider.get_meter(name),
    )
    reset_metrics_for_tests()
    yield span_exporter, metric_reader, tracer_provider
    span_exporter.clear()
    reset_metrics_for_tests()


def test_otel_disabled_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()

    setup_telemetry()
    assert is_telemetry_enabled() is False

    with traced_operation("api.request", route="/health"):
        with disposition_span(
            "disposition.submit",
            event_id="evt-test",
            action_id="act-test",
        ):
            record_writeback(status="confirmed", adapter="mock_xdr")
            record_writeback_retry(adapter="mock_xdr")
            record_action_unknown(adapter="mock_xdr")
            observe_writeback_queue_age(1.5)

    assert metrics_module._writeback_total is None


def test_celery_worker_init_calls_setup_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    log_calls: list[list[object]] = []

    def _capture(**kwargs: object) -> None:
        calls.append(dict(kwargs))

    def _capture_log(*args: object, **__kwargs: object) -> None:
        log_calls.append(list(args))

    monkeypatch.setattr("app.core.telemetry.setup_telemetry", _capture)
    monkeypatch.setattr("app.core.sanitization.configure_app_logging", _capture_log)
    from app.core.celery_app import init_worker_telemetry
    from app.db.session_provider import reset_session_provider

    reset_session_provider()
    init_worker_telemetry(sender=None)
    assert len(calls) == 1
    assert len(log_calls) == 1, (
        f"Expected configure_app_logging to be called once, got {len(log_calls)} call(s)"
    )
    assert "engine" in calls[0]
    from sqlalchemy.pool import NullPool

    assert isinstance(calls[0]["engine"].pool, NullPool)


def test_trace_hierarchy_api_agent_tool_llm(
    enabled_telemetry: TelemetryReaders,
) -> None:
    span_exporter, _, _ = enabled_telemetry

    with traced_operation("api.request", route="/events/evt-demo/graph"):
        with traced_operation("agent.execute", agent_name="EvidenceAgent", event_id="evt-demo"):
            with traced_operation(
                "tool.execute",
                tool_name="query_evidence",
                event_id="evt-demo",
                agent_name="EvidenceAgent",
            ):
                pass

    span_exporter.force_flush()
    finished = span_exporter.get_finished_spans()
    names = [span.name for span in finished]
    assert "api.request" in names
    assert "agent.execute" in names
    assert "tool.execute" in names

    by_name = {span.name: span for span in finished}
    assert by_name["tool.execute"].context.trace_id == by_name["api.request"].context.trace_id
    assert by_name["agent.execute"].parent.span_id == by_name["api.request"].context.span_id
    assert by_name["tool.execute"].parent.span_id == by_name["agent.execute"].context.span_id


@pytest.mark.asyncio
async def test_llm_chat_emits_span_under_active_trace(
    enabled_telemetry: TelemetryReaders,
) -> None:
    from app.core.llm.base import InMemoryLLMCallAuditRecorder

    span_exporter, _, _ = enabled_telemetry
    llm = _StubLLM(
        primary_model="mock-model",
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )

    with traced_operation("api.request", route="/investigate"):
        with traced_operation("agent.execute", agent_name="TriageAgent", event_id="evt-llm"):
            await llm.chat(
                [LLMMessage(role="user", content="hello")],
                event_id="evt-llm",
                agent_name="TriageAgent",
                prompt_key="triage_extract",
            )

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "llm.chat" in names


class _ChainOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True


def _telemetry_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()

    async def ok_execute(params: dict[str, Any]) -> dict[str, Any]:
        del params
        return ToolResult(
            call_id="call-telemetry-test",
            tool_name="telemetry_ok",
            provider_name="test",
            status=ToolResultStatus.SUCCESS,
            data={"ok": True},
        ).model_dump(mode="json")

    registry.register(
        ToolMeta(
            tool_name="telemetry_ok",
            tool_category=ToolCategory.QUERY,
            routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
            default_timeout_s=5.0,
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={"type": "object"},
        ),
        ok_execute,
    )
    return registry


class _TelemetryChainAgent(BaseAgent[TriageAgentInput, _ChainOutput]):
    agent_name = "triage_agent"

    async def _run(self, input: TriageAgentInput) -> _ChainOutput:
        assert self.tool_executor is not None
        assert self.llm_client is not None
        await self.tool_executor.call(
            "telemetry_ok",
            {},
            input.event_id,
            agent_name="triage_agent",
        )
        await self.llm_client.chat(
            [LLMMessage(role="user", content="ping")],
            event_id=input.event_id,
            agent_name="triage_agent",
            prompt_key="triage_extract",
        )
        return _ChainOutput()


@pytest.mark.asyncio
async def test_investigation_trace_links_agent_tool_llm(
    enabled_telemetry: TelemetryReaders,
) -> None:
    span_exporter, _, _ = enabled_telemetry
    llm = _StubLLM(
        primary_model="mock-model",
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )
    executor = ToolExecutor(registry=_telemetry_tool_registry())
    agent = _TelemetryChainAgent(llm_client=llm, tool_executor=executor)

    with traced_operation("api.request", route="/investigate"):
        await agent.execute(TriageAgentInput(event_id="evt-chain"))

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "api.request" in names
    assert "agent.execute" in names
    assert "tool.execute" in names
    assert "llm.chat" in names

    by_name = {span.name: span for span in span_exporter.get_finished_spans()}
    trace_id = by_name["api.request"].context.trace_id
    assert by_name["agent.execute"].context.trace_id == trace_id
    assert by_name["tool.execute"].context.trace_id == trace_id
    assert by_name["llm.chat"].context.trace_id == trace_id
    assert by_name["agent.execute"].parent.span_id == by_name["api.request"].context.span_id
    assert by_name["tool.execute"].parent.span_id == by_name["agent.execute"].context.span_id
    assert by_name["llm.chat"].parent.span_id == by_name["agent.execute"].context.span_id


def test_business_metrics_record_when_enabled(
    enabled_telemetry: TelemetryReaders,
) -> None:
    _, metric_reader, _ = enabled_telemetry

    record_writeback(status="confirmed", adapter="mock_xdr")
    record_writeback(status="unknown", adapter="mock_xdr")
    record_writeback_retry(adapter="mock_xdr")
    record_writeback_dead_letter(adapter="mock_xdr")
    record_action_unknown(adapter="mock_xdr")
    observe_writeback_queue_age(2.0)

    assert _metric_sum(metric_reader, "shadowtrace_writeback_total") >= 2.0
    assert _metric_sum(metric_reader, "shadowtrace_writeback_retry_total") >= 1.0
    assert _metric_sum(metric_reader, "shadowtrace_writeback_dead_letter_total") >= 1.0
    assert _metric_sum(metric_reader, "shadowtrace_action_unknown_total") >= 1.0


def test_tool_executor_import_with_otel_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()
    setup_telemetry()
    assert ToolExecutor is not None
    assert trace.get_tracer(__name__) is not None


def test_main_app_imports_with_otel_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "false")
    get_settings.cache_clear()
    import importlib

    main = importlib.import_module("app.main")
    assert main.app.title == "ShadowTrace"


def test_mock_xdr_declares_readback_capability() -> None:
    from app.adapters.disposition.http_adapter import candidate_disposition_capabilities
    from app.adapters.mock_xdr import MockXDRDispositionAdapter

    mock_caps = MockXDRDispositionAdapter(
        base_url="http://localhost:8100",
        read_token="r",
        write_token="w",
    ).capabilities()
    http_caps = candidate_disposition_capabilities()
    assert mock_caps.supports_readback_confirmation is True
    assert http_caps.supports_readback_confirmation is False


def test_fastapi_http_span_links_agent_tool_chain(
    enabled_telemetry: TelemetryReaders,
) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    span_exporter, _, tracer_provider = enabled_telemetry
    app = FastAPI()
    FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)

    @app.get("/investigate-chain")
    async def _investigate_chain() -> dict[str, bool]:
        with traced_operation("agent.execute", agent_name="TestAgent", event_id="evt-http"):
            with traced_operation(
                "tool.execute",
                tool_name="telemetry_ok",
                event_id="evt-http",
                agent_name="TestAgent",
            ):
                pass
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/investigate-chain")
    assert response.status_code == 200

    span_exporter.force_flush()
    finished = span_exporter.get_finished_spans()
    http_spans = [span for span in finished if span.name == "GET /investigate-chain"]
    agent_spans = [span for span in finished if span.name == "agent.execute"]
    tool_spans = [span for span in finished if span.name == "tool.execute"]
    assert http_spans
    assert agent_spans
    assert tool_spans
    trace_id = http_spans[0].context.trace_id
    assert agent_spans[0].context.trace_id == trace_id
    assert tool_spans[0].context.trace_id == trace_id
    assert agent_spans[0].parent.span_id == http_spans[0].context.span_id


@pytest.mark.asyncio
async def test_lookup_writeback_status_no_query_span_without_capability(
    enabled_telemetry: TelemetryReaders,
) -> None:
    from unittest.mock import AsyncMock, MagicMock

    from app.adapters.disposition.base import (
        BaseDispositionAdapter,
        DispositionAdapterCapabilities,
    )
    from app.adapters.registry import DispositionAdapterRegistry
    from app.models.disposition import DispositionCommand
    from app.models.enums import ConnectorStatus, WritebackStatus
    from app.services.disposition_sync_service import DispositionSyncService

    class _NoQueryAdapter(BaseDispositionAdapter):
        name = "no_query"

        def capabilities(self) -> DispositionAdapterCapabilities:
            return DispositionAdapterCapabilities()

        def validate_command(self, command: DispositionCommand) -> None:
            del command

        async def submit(self, command: DispositionCommand):
            del command
            raise AssertionError("not used")

        async def health_check(self) -> ConnectorStatus:
            return ConnectorStatus.ONLINE

    outbox = MagicMock()
    outbox.writeback_id = "wbk-test"
    outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
    outbox.command_payload = {
        "source_locator": {
            "source_product": "no_query",
            "source_object_id": "obj-1",
            "source_object_kind": "incident",
        }
    }

    session = AsyncMock()
    session.scalar = AsyncMock(return_value=outbox)
    session_cm = AsyncMock()
    session_cm.__aenter__.return_value = session
    session_cm.__aexit__.return_value = None
    session_factory = MagicMock(return_value=session_cm)

    registry = DispositionAdapterRegistry()
    registry.register("no_query", _NoQueryAdapter())
    sync = DispositionSyncService(
        session_factory,
        context_store=MagicMock(),
        adapter_registry=registry,
    )

    span_exporter, _, _ = enabled_telemetry
    status = await sync.lookup_writeback_status("wbk-test")
    assert status is WritebackStatus.UNKNOWN

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "disposition.query_status" not in names


@pytest.mark.asyncio
async def test_lookup_writeback_status_emits_query_span_with_capability(
    enabled_telemetry: TelemetryReaders,
) -> None:
    from datetime import UTC, datetime
    from unittest.mock import AsyncMock, MagicMock

    from app.adapters.disposition.base import (
        BaseDispositionAdapter,
        DispositionAdapterCapabilities,
    )
    from app.adapters.registry import DispositionAdapterRegistry
    from app.models.disposition import (
        DispositionCommand,
        DispositionReceipt,
        SourceObjectLocator,
        SubmitEntityActionParams,
        TargetDispositionResult,
    )
    from app.models.enums import (
        ConfirmationEvidence,
        ConnectorStatus,
        DispositionIntentKind,
        ExecutionOwner,
        SourceObjectKind,
        TargetExecutionStatus,
        WritebackStatus,
    )
    from app.services.disposition_sync_service import DispositionSyncService

    command = DispositionCommand(
        disposition_id="disp-1",
        action_id="act-1",
        closure_cycle=1,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        source_locator=SourceObjectLocator(
            source_product="lookup_stub",
            source_tenant_id="tenant-a",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id="obj-1",
        ),
        operation_code="submit_entity_action",
        operation_params=SubmitEntityActionParams(
            entity_action_code="isolate_host",
            canonical_target="host:pc-1",
        ),
        target_results=[
            TargetDispositionResult(
                canonical_target="host:pc-1",
                status=TargetExecutionStatus.SUCCESS,
            )
        ],
        operator_id="operator-1",
        idempotency_key="idem-1",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )

    class _LookupAdapter(BaseDispositionAdapter):
        name = "lookup_stub"

        def capabilities(self) -> DispositionAdapterCapabilities:
            return DispositionAdapterCapabilities(supports_lookup_by_idempotency=True)

        def validate_command(self, command: DispositionCommand) -> None:
            del command

        async def submit(self, command: DispositionCommand):
            del command
            raise AssertionError("not used")

        async def lookup_submission(
            self, idempotency_key: str, source_locator
        ) -> DispositionReceipt:
            del idempotency_key, source_locator
            now = datetime.now(UTC)
            return DispositionReceipt(
                writeback_id="wbk-test",
                sequence=1,
                disposition_id="disp-1",
                action_id="act-1",
                source_record_id="src-1",
                status=WritebackStatus.CONFIRMED,
                confirmation_evidence=ConfirmationEvidence.STATUS_QUERIED,
                observed_at=now,
                submitted_at=now,
            )

        async def health_check(self) -> ConnectorStatus:
            return ConnectorStatus.ONLINE

    outbox = MagicMock()
    outbox.writeback_id = "wbk-test"
    outbox.event_id = "evt-1"
    outbox.action_id = "act-1"
    outbox.disposition_id = "disp-1"
    outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
    outbox.command_payload = command.model_dump(mode="json")

    session = AsyncMock()
    session.scalar = AsyncMock(return_value=outbox)
    session_cm = AsyncMock()
    session_cm.__aenter__.return_value = session
    session_cm.__aexit__.return_value = None
    session_factory = MagicMock(return_value=session_cm)

    registry = DispositionAdapterRegistry()
    registry.register("lookup_stub", _LookupAdapter())
    sync = DispositionSyncService(
        session_factory,
        context_store=MagicMock(),
        adapter_registry=registry,
    )

    span_exporter, metric_reader, _ = enabled_telemetry
    status = await sync.lookup_writeback_status("wbk-test")
    assert status is WritebackStatus.CONFIRMED

    span_exporter.force_flush()
    names = [span.name for span in span_exporter.get_finished_spans()]
    assert "disposition.query_status" in names


def test_manual_resolve_records_writeback_metric(
    enabled_telemetry: TelemetryReaders,
) -> None:
    """Terminal writeback outcomes increment shadowtrace_writeback_total (resolve path)."""
    _, metric_reader, _ = enabled_telemetry
    record_writeback(status="confirmed", adapter="mock_xdr")
    assert _metric_sum(metric_reader, "shadowtrace_writeback_total") >= 1.0
