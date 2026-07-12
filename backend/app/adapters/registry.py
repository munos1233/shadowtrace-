"""Adapter registries (ISSUE-012)."""

from __future__ import annotations

from app.adapters.disposition.base import BaseDispositionAdapter
from app.adapters.source.base import BaseSourceAdapter
from app.core.errors import AdapterNotFoundError


class SourceAdapterRegistry:
    """Named SourceAdapter lookup. Agents must not call this."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseSourceAdapter] = {}

    def register(self, name: str, adapter: BaseSourceAdapter) -> None:
        self._adapters[name] = adapter

    def get(self, name: str) -> BaseSourceAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise AdapterNotFoundError(
                f"source adapter {name!r} not registered",
                details={"adapter_name": name, "kind": "source"},
            ) from exc

    def list_names(self) -> list[str]:
        return sorted(self._adapters)


class DispositionAdapterRegistry:
    """Named DispositionAdapter lookup."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseDispositionAdapter] = {}

    def register(self, name: str, adapter: BaseDispositionAdapter) -> None:
        self._adapters[name] = adapter

    def get(self, name: str) -> BaseDispositionAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise AdapterNotFoundError(
                f"disposition adapter {name!r} not registered",
                details={"adapter_name": name, "kind": "disposition"},
            ) from exc

    def list_names(self) -> list[str]:
        return sorted(self._adapters)
