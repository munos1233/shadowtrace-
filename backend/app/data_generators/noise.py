"""Background noise event generator (ISSUE-010)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class NoiseGenerator(TelemetryGenerator):
    """Random-looking but deterministic background noise (not Source* objects)."""

    name = "network"  # noise is mixed into network channel by default callers

    def __init__(
        self, *, seed: int = 0, base_time: datetime | None = None, channel: str = "noise"
    ) -> None:
        super().__init__(seed=seed, base_time=base_time)
        self.channel = channel

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"noise-{self.seed}-{i:04d}",
                    "channel": self.channel,
                    "kind": "background",
                    "src_ip": f"172.16.{i % 20}.{i % 200}",
                    "dst_ip": f"198.51.100.{i % 200}",
                    "bytes": self._rng.randint(64, 4096),
                    "logged_at": offset_time(self.base_time, i * 5).isoformat(),
                    "is_conflict_seed": False,
                    "is_noise": True,
                }
            )
        return rows

    def filename(self) -> str:
        # Noise is not one of the seven fixed files; callers merge into others.
        return "noise_events.json"
