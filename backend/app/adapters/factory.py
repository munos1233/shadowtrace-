"""Single assembly point for Source / Disposition adapters (Layer 7).

All production ``DispositionAdapterRegistry`` entries must call
``build_disposition_adapter_registry``. Agents must not import this module
for vendor paths; KIND=mock stays Canonical Mock.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from app.adapters.disposition.base import BaseDispositionAdapter
from app.adapters.mock_xdr import MockXDRDispositionAdapter, MockXDRSourceAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.adapters.source.base import BaseSourceAdapter
from app.core.config import Settings, is_mock_disposition_mode, is_mock_source_mode
from app.core.errors import ConfigurationError
from app.mock_xdr.state import MOCK_XDR_DEFAULT_READ_TOKEN, MOCK_XDR_DEFAULT_WRITE_TOKEN
from app.models.enums import CapabilityState, ConnectorCapability, ConnectorStatus

logger = logging.getLogger(__name__)

KIND_MOCK = "mock"
KIND_HTTP = "http"
KIND_SANGFOR = "sangfor_xdr"
SUPPORTED_DISPOSITION_KINDS = frozenset({KIND_MOCK, KIND_HTTP, KIND_SANGFOR})
MOCK_XDR_PROVIDER = "mock_xdr"
SANGFOR_PROVIDER = "sangfor_xdr"
HTTP_PROVIDER = "generic_http_disposition"
MOCK_TOOL_PROVIDER = "mock_tool_provider"
_SUPPORTED_SOURCE_MODES = frozenset({MOCK_XDR_PROVIDER, SANGFOR_PROVIDER})
_AUTH_PROBE_PATH = "/api/xdr/v1/incidents/list"


def _normalize(value: str) -> str:
    return (value or "").strip().lower()


def disposition_kind(settings: Settings) -> str:
    kind = _normalize(settings.disposition_adapter_kind)
    mode = _normalize(settings.disposition_mode)
    if mode == "live_xdr" and (not kind or kind == KIND_MOCK):
        raise ConfigurationError(
            "DISPOSITION_MODE=live_xdr forbids DISPOSITION_ADAPTER_KIND=mock",
            error_code="configuration_error",
            details={
                "disposition_mode": settings.disposition_mode,
                "disposition_adapter_kind": settings.disposition_adapter_kind,
            },
        )
    return kind or KIND_MOCK


def disposition_provider_name(settings: Settings) -> str:
    """Job ``provider_name`` for XDR-managed execution. Mock path stays ``mock_xdr``."""
    kind = disposition_kind(settings)
    if kind == KIND_MOCK:
        return MOCK_XDR_PROVIDER
    if kind == KIND_SANGFOR:
        return SANGFOR_PROVIDER
    if kind == KIND_HTTP:
        return HTTP_PROVIDER
    raise ConfigurationError(
        f"unknown DISPOSITION_ADAPTER_KIND={settings.disposition_adapter_kind!r}",
        error_code="configuration_error",
        details={"disposition_adapter_kind": settings.disposition_adapter_kind},
    )


def _reject_unregistered_disposition_mode(settings: Settings) -> None:
    mode = _normalize(settings.disposition_mode)
    if mode == "live":
        raise ConfigurationError(
            "DISPOSITION_MODE=live is unregistered; use live_xdr",
            error_code="configuration_error",
            details={"disposition_mode": settings.disposition_mode},
        )


def _sangfor_auth_code(settings: Settings) -> str:
    return (settings.sangfor_auth_code or os.environ.get("AUTH_CODE") or "").strip()


def sangfor_credentials_configured(settings: Settings) -> bool:
    if _sangfor_auth_code(settings):
        return True
    return bool(settings.sangfor_access_key.strip() and settings.sangfor_secret_key.strip())


def _require_sangfor_credentials(settings: Settings) -> None:
    if sangfor_credentials_configured(settings):
        return
    raise ConfigurationError(
        "Sangfor adapter requires SANGFOR_AUTH_CODE (or AUTH_CODE) or AK/SK",
        error_code="configuration_error",
        details={"kind": KIND_SANGFOR},
    )


def _require_sangfor_base_url(settings: Settings) -> str:
    base_url = (settings.sangfor_xdr_base_url or "").strip()
    if not base_url:
        raise ConfigurationError(
            "Sangfor adapter requires SANGFOR_XDR_BASE_URL",
            error_code="configuration_error",
            details={"kind": KIND_SANGFOR},
        )
    return base_url


def build_sangfor_client(settings: Settings, *, client: Any | None = None) -> Any:
    """Construct the signed HTTP client. Callers must not log credentials."""
    from app.adapters.sangfor.client import SangforXdrClient

    _require_sangfor_credentials(settings)
    return SangforXdrClient(
        _require_sangfor_base_url(settings),
        access_key=settings.sangfor_access_key.strip() or None,
        secret_key=settings.sangfor_secret_key.strip() or None,
        auth_code=_sangfor_auth_code(settings) or None,
        verify=bool(settings.sangfor_tls_verify),
        client=client,
    )


def build_sangfor_live_query_adapters(
    settings: Settings,
    *,
    client: Any | None = None,
) -> list[Any]:
    """Live Evidence query adapters. Empty unless KIND=sangfor_xdr and TOOL_MODE=live."""
    if disposition_kind(settings) != KIND_SANGFOR:
        return []
    if _normalize(settings.tool_mode) != "live":
        return []
    from app.adapters.sangfor.query_provider import build_sangfor_query_adapters
    from app.tools.adapters.base import AdapterConfig

    xdr_client = client if client is not None else build_sangfor_client(settings)
    config = AdapterConfig(
        endpoint=_require_sangfor_base_url(settings),
        auth_type="none",
        enabled=True,
        tls_verify=bool(settings.sangfor_tls_verify),
    )
    return build_sangfor_query_adapters(xdr_client, config)


async def ensure_sangfor_live_query_adapters_registered(
    settings: Settings,
    registry: Any,
) -> list[str]:
    """Idempotently register live Sangfor query adapters in this process.

    FastAPI and Celery are separate processes. Registration therefore belongs
    in shared runtime composition, not only in the FastAPI lifespan hook.
    Existing bindings are retained so calling this from both entry points is
    safe and does not recreate provider implementations.
    """
    if disposition_kind(settings) != KIND_SANGFOR or _normalize(settings.tool_mode) != "live":
        return []

    # Avoid constructing a second HTTP client when API lifespan and lazy
    # worker composition both reach this idempotent assembly point.
    from app.adapters.sangfor.query_provider import QUERY_TOOL_NAMES

    registered_names = {view.tool_meta.tool_name for view in registry.list_registered_tools()}
    already_complete = all(
        tool_name in registered_names
        and any(
            binding.provider_name == f"sangfor_xdr_query:{tool_name}"
            for binding in registry.list_bindings(tool_name)
        )
        for tool_name in QUERY_TOOL_NAMES
    )
    if already_complete:
        return []

    adapters = build_sangfor_live_query_adapters(settings)
    if not adapters:
        return []

    pending: list[Any] = []
    for adapter in adapters:
        bindings = (
            registry.list_bindings(adapter.tool_meta.tool_name)
            if adapter.tool_meta.tool_name in registered_names
            else []
        )
        if any(binding.provider_name == adapter.name for binding in bindings):
            continue
        pending.append(adapter)
    if not pending:
        return []

    registered = await registry.auto_discover_for_mode(
        tool_mode=settings.tool_mode,
        adapters=pending,
        simulation_enabled=settings.simulation_enabled,
        allow_live_side_effects=settings.allow_live_side_effects,
    )
    return [str(tool_name) for tool_name in registered]


def _build_mock_disposition(settings: Settings) -> MockXDRDispositionAdapter:
    base_url = (settings.disposition_base_url or "http://mock-xdr").strip()
    return MockXDRDispositionAdapter(
        base_url=base_url,
        read_token=MOCK_XDR_DEFAULT_READ_TOKEN,
        write_token=MOCK_XDR_DEFAULT_WRITE_TOKEN,
    )


def _build_http_disposition(settings: Settings) -> BaseDispositionAdapter:
    from app.adapters.disposition.http_adapter import HttpDispositionAdapter
    from app.tools.adapters.base import AdapterConfig

    endpoint = (settings.disposition_base_url or "").strip() or "http://127.0.0.1"
    credential_ref = (settings.disposition_credential_ref or "").strip()
    return HttpDispositionAdapter(
        AdapterConfig(
            endpoint=endpoint,
            auth_type="bearer" if credential_ref else "none",
            credential_ref=credential_ref,
            enabled=bool((settings.disposition_base_url or "").strip()),
        ),
        shared_credential_scope_verified=bool(settings.shared_credential_scope_verified),
        allow_side_effects=bool(settings.allow_xdr_writeback),
    )


class _CloseableSangforSource(BaseSourceAdapter):
    """Source wrapper that closes the signed client after a scheduler poll."""

    def __init__(self, inner: BaseSourceAdapter, client: Any) -> None:
        self._inner = inner
        self._client = client
        self.name = getattr(inner, "name", SANGFOR_PROVIDER)
        self.checkpoint_scope = getattr(inner, "checkpoint_scope", "")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def capabilities(self) -> dict[ConnectorCapability, CapabilityState]:
        return self._inner.capabilities()

    async def list_objects(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.list_objects(*args, **kwargs)

    async def list_connectors(self) -> Any:
        return await self._inner.list_connectors()

    async def get_object(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.get_object(*args, **kwargs)

    async def list_evidence_records(self, *args: Any, **kwargs: Any) -> Any:
        return await self._inner.list_evidence_records(*args, **kwargs)

    async def health_check(self) -> ConnectorStatus:
        return await self._inner.health_check()

    async def aclose(self) -> None:
        closer = getattr(self._client, "aclose", None)
        if closer is not None:
            await closer()


def _build_sangfor_disposition(settings: Settings) -> BaseDispositionAdapter:
    from app.adapters.sangfor.disposition import SangforDispositionAdapter
    from app.adapters.sangfor.runtime_config import block_config_from_settings

    if is_mock_disposition_mode(settings.disposition_mode):
        raise ConfigurationError(
            "DISPOSITION_ADAPTER_KIND=sangfor_xdr requires DISPOSITION_MODE=live_xdr",
            error_code="configuration_error",
            details={
                "disposition_adapter_kind": settings.disposition_adapter_kind,
                "disposition_mode": settings.disposition_mode,
            },
        )
    client = build_sangfor_client(settings)
    return SangforDispositionAdapter(
        client,
        block_config=block_config_from_settings(settings),
    )


async def observe_disposition_verification(
    tool_name: str,
    params: dict[str, Any],
) -> dict[str, Any] | None:
    """Verify observation via the registered DispositionAdapter. Tools must not import sangfor."""
    from app.core.config import get_settings

    settings = get_settings()
    kind = _normalize(getattr(settings, "disposition_adapter_kind", None) or "")
    if kind != KIND_SANGFOR:
        return None
    try:
        adapter = _build_sangfor_disposition(settings)
        return await adapter.observe_verification(tool_name, params)
    except Exception:
        from app.adapters.sangfor.verify_observation import observe_sangfor_verification

        return await observe_sangfor_verification(tool_name, params)


def build_disposition_adapter_registry(settings: Settings) -> DispositionAdapterRegistry:
    """Register exactly one KIND. Production API and Celery must share this."""
    _reject_unregistered_disposition_mode(settings)
    kind = disposition_kind(settings)
    if kind not in SUPPORTED_DISPOSITION_KINDS:
        raise ConfigurationError(
            f"unknown DISPOSITION_ADAPTER_KIND={settings.disposition_adapter_kind!r}",
            error_code="configuration_error",
            details={
                "disposition_adapter_kind": settings.disposition_adapter_kind,
                "supported": sorted(SUPPORTED_DISPOSITION_KINDS),
            },
        )
    registry = DispositionAdapterRegistry()
    if kind == KIND_MOCK:
        mock_adapter = _build_mock_disposition(settings)
        registry.register(MOCK_XDR_PROVIDER, mock_adapter)
        return registry
    if kind == KIND_HTTP:
        http_adapter = _build_http_disposition(settings)
        registry.register(HTTP_PROVIDER, http_adapter)
        return registry
    sangfor_adapter = _build_sangfor_disposition(settings)
    registry.register(SANGFOR_PROVIDER, sangfor_adapter)
    return registry


def build_source_adapter(settings: Settings) -> BaseSourceAdapter:
    """Build the ingest SourceAdapter for ``SOURCE_MODE``. KIND=mock stays Mock."""
    source_mode = _normalize(settings.source_mode)
    if is_mock_source_mode(source_mode) or source_mode == MOCK_XDR_PROVIDER:
        base_url = (settings.disposition_base_url or "http://mock-xdr:8100").strip()
        return MockXDRSourceAdapter(
            base_url=base_url,
            read_token=MOCK_XDR_DEFAULT_READ_TOKEN,
            write_token=MOCK_XDR_DEFAULT_WRITE_TOKEN,
            max_retries=0,
        )
    if source_mode != SANGFOR_PROVIDER:
        raise ConfigurationError(
            f"unsupported SOURCE_MODE={settings.source_mode!r}",
            error_code="configuration_error",
            details={"source_mode": settings.source_mode},
        )
    if settings.simulation_enabled:
        raise ConfigurationError(
            "SOURCE_MODE=sangfor_xdr forbids SIMULATION_ENABLED=true",
            error_code="configuration_error",
            details={"source_mode": settings.source_mode},
        )
    from app.adapters.sangfor.source import SangforSourceAdapter

    client = build_sangfor_client(settings)
    inner = SangforSourceAdapter(client)
    return _CloseableSangforSource(inner, client)


def source_mode_is_supported(settings: Settings) -> bool:
    return _normalize(settings.source_mode) in _SUPPORTED_SOURCE_MODES


def _capability_map(
    *,
    log_ingestion: str,
    query: str,
    event_disposition: str,
    entity_response: str,
) -> dict[str, str]:
    return {
        "LOG_INGESTION": log_ingestion,
        "QUERY": query,
        "EVENT_DISPOSITION": event_disposition,
        "ENTITY_RESPONSE": entity_response,
    }


def source_adapter_component(settings: Settings) -> dict[str, Any]:
    """Health component for the SourceAdapter. Never includes credentials."""
    mode = settings.source_mode
    if is_mock_source_mode(mode):
        return {
            "status": "ok",
            "mode": mode,
            "capability": _capability_map(
                log_ingestion="SUPPORTED",
                query="SUPPORTED",
                event_disposition="UNSUPPORTED",
                entity_response="UNSUPPORTED",
            ),
        }
    if _normalize(mode) == SANGFOR_PROVIDER:
        if (
            not sangfor_credentials_configured(settings)
            or not (settings.sangfor_xdr_base_url or "").strip()
        ):
            return {
                "status": "error",
                "mode": mode,
                "capability": _capability_map(
                    log_ingestion="UNKNOWN",
                    query="UNKNOWN",
                    event_disposition="UNSUPPORTED",
                    entity_response="UNSUPPORTED",
                ),
            }
        return {
            "status": "ok",
            "mode": mode,
            "capability": _capability_map(
                log_ingestion="SUPPORTED",
                query="UNSUPPORTED",
                event_disposition="UNSUPPORTED",
                entity_response="UNSUPPORTED",
            ),
        }
    return {
        "status": "degraded",
        "mode": mode,
        "capability": _capability_map(
            log_ingestion="UNKNOWN",
            query="UNKNOWN",
            event_disposition="UNSUPPORTED",
            entity_response="UNSUPPORTED",
        ),
    }


def disposition_adapter_component(settings: Settings) -> dict[str, Any]:
    """Health component for the DispositionAdapter. Never includes credentials."""
    mode = settings.disposition_mode
    kind = disposition_kind(settings)
    if is_mock_disposition_mode(mode) and kind == KIND_MOCK:
        return {
            "status": "ok",
            "mode": mode,
            "capability": _capability_map(
                log_ingestion="UNSUPPORTED",
                query="UNKNOWN",
                event_disposition="SUPPORTED",
                entity_response="SUPPORTED",
            ),
        }
    if kind == KIND_SANGFOR:
        if (
            not sangfor_credentials_configured(settings)
            or not (settings.sangfor_xdr_base_url or "").strip()
        ):
            return {
                "status": "error",
                "mode": mode,
                "capability": _capability_map(
                    log_ingestion="UNSUPPORTED",
                    query="UNKNOWN",
                    event_disposition="UNKNOWN",
                    entity_response="UNKNOWN",
                ),
            }
        return {
            "status": "ok",
            "mode": mode,
            "capability": _capability_map(
                log_ingestion="UNSUPPORTED",
                query="UNKNOWN",
                event_disposition="SUPPORTED",
                entity_response="SUPPORTED",
            ),
        }
    if kind == KIND_HTTP:
        return {
            "status": "ok" if (settings.disposition_base_url or "").strip() else "degraded",
            "mode": mode,
            "capability": _capability_map(
                log_ingestion="UNSUPPORTED",
                query="UNKNOWN",
                event_disposition="UNKNOWN",
                entity_response="UNKNOWN",
            ),
        }
    return {
        "status": "degraded",
        "mode": mode,
        "capability": _capability_map(
            log_ingestion="UNSUPPORTED",
            query="UNKNOWN",
            event_disposition="UNKNOWN",
            entity_response="UNKNOWN",
        ),
    }


async def probe_sangfor_auth(settings: Settings, *, client: Any | None = None) -> ConnectorStatus:
    """Signed incidents/list probe. HTTP 401 is never treated as healthy."""
    owns_client = client is None
    http_client = client or build_sangfor_client(settings)
    try:
        result = await http_client.request(
            "POST",
            _AUTH_PROBE_PATH,
            json_body={"page": 1, "pageSize": 5},
            headers={"content-type": "application/json"},
        )
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("sangfor auth probe failed", exc_info=True)
        return ConnectorStatus.OFFLINE
    finally:
        if owns_client:
            closer = getattr(http_client, "aclose", None)
            if closer is not None:
                await closer()
    if result.http_status == 401:
        return ConnectorStatus.OFFLINE
    if result.http_status >= 500:
        return ConnectorStatus.OFFLINE
    return ConnectorStatus.ONLINE


async def live_auth_failed(settings: Settings, *, client: Any | None = None) -> bool:
    """True when a live Sangfor probe proves auth failure (401 / offline)."""
    live = (
        _normalize(settings.source_mode) == SANGFOR_PROVIDER
        or disposition_kind(settings) == KIND_SANGFOR
    )
    if not live:
        return False
    if (
        not sangfor_credentials_configured(settings)
        or not (settings.sangfor_xdr_base_url or "").strip()
    ):
        return True
    status = await probe_sangfor_auth(settings, client=client)
    return status is ConnectorStatus.OFFLINE


__all__ = [
    "HTTP_PROVIDER",
    "KIND_HTTP",
    "KIND_MOCK",
    "KIND_SANGFOR",
    "MOCK_TOOL_PROVIDER",
    "MOCK_XDR_PROVIDER",
    "SANGFOR_PROVIDER",
    "SUPPORTED_DISPOSITION_KINDS",
    "build_disposition_adapter_registry",
    "build_sangfor_client",
    "build_sangfor_live_query_adapters",
    "build_source_adapter",
    "disposition_adapter_component",
    "disposition_kind",
    "disposition_provider_name",
    "ensure_sangfor_live_query_adapters_registered",
    "live_auth_failed",
    "observe_disposition_verification",
    "probe_sangfor_auth",
    "sangfor_credentials_configured",
    "source_adapter_component",
    "source_mode_is_supported",
]
