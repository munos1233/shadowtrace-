"""Shared base for telemetry generators (ISSUE-010)."""

from __future__ import annotations

import json
import random
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Fixed output filenames (ISSUE-010 naming §3).
TELEMETRY_FILENAMES: dict[str, str] = {
    "identity": "identity_logs.json",
    "endpoint": "endpoint_logs.json",
    "dlp": "dlp_logs.json",
    "network": "network_logs.json",
    "dns": "dns_logs.json",
    "asset": "asset_data.json",
    "threat_intel": "threat_intel.json",
}


class TelemetryGenerator(ABC):
    """Base interface for deterministic telemetry generators."""

    name: str

    def __init__(self, *, seed: int = 0, base_time: datetime | None = None) -> None:
        self.seed = seed
        self.base_time = base_time or datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        self._rng = random.Random(seed)

    @abstractmethod
    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        """Return ``count`` telemetry records (deterministic under seed)."""

    def filename(self) -> str:
        return TELEMETRY_FILENAMES[self.name]


def write_telemetry_files(
    generators: list[TelemetryGenerator],
    out_dir: Path,
    *,
    count: int = 10,
) -> list[Path]:
    """Write each generator's output to the fixed filename under ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for gen in generators:
        records = gen.generate(count=count)
        path = out_dir / gen.filename()
        path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def offset_time(base: datetime, seconds: int) -> datetime:
    return base + timedelta(seconds=seconds)
