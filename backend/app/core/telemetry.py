"""OpenTelemetry bootstrap (ISSUE-092).

When ``OTEL_ENABLED=false`` (default) tracing and metrics are no-ops with
negligible overhead. Export failures are logged once and discarded so
observability never blocks business logic.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urljoin

from opentelemetry import metrics, trace
from opentelemetry.metrics import NoOpMeterProvider
from opentelemetry.trace import NoOpTracerProvider, Span

from app.core.sanitization import REDACTED, is_sensitive_key

logger = logging.getLogger(__name__)

_ENABLED = False
_CONFIGURED = False


def is_telemetry_enabled() -> bool:
    return _ENABLED


def _normalize_base(endpoint: str) -> str:
    base = (endpoint or "").strip().rstrip("/")
    return base or "http://127.0.0.1:4318"


def _otlp_traces_endpoint(base: str) -> str:
    if base.endswith("/v1/traces"):
        return base
    return urljoin(f"{base}/", "v1/traces")


def _otlp_metrics_endpoint(base: str) -> str:
    if base.endswith("/v1/metrics"):
        return base
    return urljoin(f"{base}/", "v1/metrics")


def _redact_httpx_span_header_attributes(
    span: Span | None,
    headers: Any,
    *,
    normalize_header_name: Callable[[str], str],
) -> None:
    """Overwrite sensitive HTTP header span attributes; never mutates the live request."""

    if span is None or not span.is_recording() or headers is None:
        return
    try:
        header_keys = headers.keys()
    except AttributeError:
        return
    for key in header_keys:
        key_str = key.decode("latin-1") if isinstance(key, bytes) else str(key)
        if not is_sensitive_key(key_str):
            continue
        span.set_attribute(normalize_header_name(key_str), [REDACTED])


def _httpx_request_hook(span: Span, request: Any) -> None:
    from opentelemetry.util.http import normalise_request_header_name

    _redact_httpx_span_header_attributes(
        span,
        request.headers,
        normalize_header_name=normalise_request_header_name,
    )


def _httpx_response_hook(span: Span, request: Any, response: Any) -> None:
    del request
    from opentelemetry.util.http import normalise_response_header_name

    _redact_httpx_span_header_attributes(
        span,
        response.headers,
        normalize_header_name=normalise_response_header_name,
    )


async def _httpx_async_request_hook(span: Span, request: Any) -> None:
    _httpx_request_hook(span, request)


async def _httpx_async_response_hook(span: Span, request: Any, response: Any) -> None:
    _httpx_response_hook(span, request, response)


def setup_telemetry(
    *,
    app: Any | None = None,
    engine: Any | None = None,
) -> None:
    """Initialise OTel providers and optional auto-instrumentation."""
    global _ENABLED, _CONFIGURED

    from app.core.config import get_settings

    settings = get_settings()
    if not settings.otel_enabled:
        trace.set_tracer_provider(NoOpTracerProvider())
        metrics.set_meter_provider(NoOpMeterProvider())
        _ENABLED = False
        _CONFIGURED = True
        return

    if _CONFIGURED:
        return

    resource_attrs = {
        "service.name": settings.otel_service_name,
        "service.version": settings.app_version,
        "deployment.environment": settings.app_env,
    }

    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(resource_attrs)
        tracer_provider = TracerProvider(resource=resource)

        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            tracer_provider.add_span_processor(
                BatchSpanProcessor(
                    OTLPSpanExporter(
                        endpoint=_otlp_traces_endpoint(
                            _normalize_base(settings.otel_exporter_otlp_endpoint)
                        ),
                    )
                )
            )
        except Exception:
            logger.warning(
                "OTLP trace exporter unavailable; spans will not leave the process",
                exc_info=True,
            )

        trace.set_tracer_provider(tracer_provider)

        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

            reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(
                    endpoint=_otlp_metrics_endpoint(
                        _normalize_base(settings.otel_exporter_otlp_endpoint)
                    ),
                ),
                export_interval_millis=15_000,
            )
            metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
        except Exception:
            logger.warning(
                "OTLP metric exporter unavailable; business metrics will not export",
                exc_info=True,
            )

        if app is not None:
            try:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

                FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)
            except Exception:
                logger.warning("FastAPI auto-instrumentation failed", exc_info=True)

        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

            HTTPXClientInstrumentor().instrument(
                request_hook=_httpx_request_hook,
                response_hook=_httpx_response_hook,
                async_request_hook=_httpx_async_request_hook,
                async_response_hook=_httpx_async_response_hook,
            )
        except Exception:
            logger.warning("httpx auto-instrumentation failed", exc_info=True)

        if engine is not None:
            try:
                from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

                sync_engine = getattr(engine, "sync_engine", engine)
                SQLAlchemyInstrumentor().instrument(engine=sync_engine)
            except Exception:
                logger.warning("SQLAlchemy auto-instrumentation failed", exc_info=True)

        try:
            from opentelemetry.instrumentation.celery import CeleryInstrumentor

            CeleryInstrumentor().instrument()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning("Celery auto-instrumentation failed", exc_info=True)

        _ENABLED = True
        logger.info("OpenTelemetry enabled (service=%s)", settings.otel_service_name)
    except Exception:
        trace.set_tracer_provider(NoOpTracerProvider())
        metrics.set_meter_provider(NoOpMeterProvider())
        _ENABLED = False
        logger.warning("OpenTelemetry setup failed; continuing with no-op telemetry", exc_info=True)
    finally:
        _CONFIGURED = True


def setup_test_telemetry() -> tuple[Any, Any]:
    """In-memory trace/metric providers for unit tests (ISSUE-092)."""
    global _ENABLED, _CONFIGURED

    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    span_exporter = InMemorySpanExporter()
    metric_reader = InMemoryMetricReader()

    resource = Resource.create({"service.name": "shadowtrace-test"})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[metric_reader]))

    _ENABLED = True
    _CONFIGURED = True
    return span_exporter, metric_reader


def reset_telemetry_for_tests() -> None:
    """Restore no-op telemetry between tests."""
    global _ENABLED, _CONFIGURED
    trace.set_tracer_provider(NoOpTracerProvider())
    metrics.set_meter_provider(NoOpMeterProvider())
    _ENABLED = False
    _CONFIGURED = False


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def get_meter(name: str) -> metrics.Meter:
    return metrics.get_meter(name)


def _set_span_attrs(span: Span, attrs: dict[str, str | None]) -> None:
    for key, value in attrs.items():
        if value is not None and value != "":
            span.set_attribute(f"shadowtrace.{key}", value)


@contextmanager
def traced_operation(name: str, **attrs: str | None) -> Iterator[Span | None]:
    """Manual business span; no-op when telemetry is disabled."""
    if not _ENABLED:
        yield None
        return
    tracer = get_tracer("shadowtrace")
    with tracer.start_as_current_span(name) as span:
        _set_span_attrs(span, attrs)
        yield span


@contextmanager
def disposition_span(
    name: str,
    *,
    event_id: str | None = None,
    action_id: str | None = None,
    disposition_id: str | None = None,
    writeback_id: str | None = None,
) -> Iterator[Span | None]:
    """Disposition lifecycle spans (ISSUE-092 §统一命名 point 2)."""
    with traced_operation(
        name,
        event_id=event_id,
        action_id=action_id,
        disposition_id=disposition_id,
        writeback_id=writeback_id,
    ) as span:
        yield span


__all__ = [
    "disposition_span",
    "get_meter",
    "get_tracer",
    "is_telemetry_enabled",
    "reset_telemetry_for_tests",
    "setup_telemetry",
    "setup_test_telemetry",
    "traced_operation",
]
