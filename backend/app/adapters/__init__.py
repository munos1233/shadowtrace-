"""External system adapters (ISSUE-012).

Agents must not import this package. Event/ingestion services depend on
``BaseSourceAdapter`` / source models; disposition sync depends only on
``BaseDispositionAdapter``.
"""

from __future__ import annotations

from app.adapters.disposition.base import (
    BaseDispositionAdapter,
    DispositionAdapterCapabilities,
)
from app.adapters.file_source import FileSourceAdapter
from app.adapters.mock_xdr import (
    LiveDispositionAdapterStub,
    MockXDRDispositionAdapter,
    MockXDRSourceAdapter,
)
from app.adapters.registry import DispositionAdapterRegistry, SourceAdapterRegistry
from app.adapters.source.base import (
    BaseSourceAdapter,
    DataQualityRecorder,
    InMemoryDataQualityRecorder,
    SourcePage,
)
from app.core.errors import AdapterNotFoundError

__all__ = [
    "AdapterNotFoundError",
    "BaseDispositionAdapter",
    "BaseSourceAdapter",
    "DataQualityRecorder",
    "DispositionAdapterCapabilities",
    "DispositionAdapterRegistry",
    "FileSourceAdapter",
    "InMemoryDataQualityRecorder",
    "LiveDispositionAdapterStub",
    "MockXDRDispositionAdapter",
    "MockXDRSourceAdapter",
    "SourceAdapterRegistry",
    "SourcePage",
]
