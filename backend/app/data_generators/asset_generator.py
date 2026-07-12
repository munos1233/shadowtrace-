"""Asset inventory generator."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class AssetGenerator(TelemetryGenerator):
    name = "asset"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"asset-{self.seed}-{i:04d}",
                    "channel": "asset",
                    "numeric_asset_id": str(1000 + i),
                    "hostname": f"asset-host-{i:03d}",
                    "ip": f"10.2.0.{i % 250}",
                    "agent_status": "online" if i % 3 else "offline",
                    "first_seen_at": offset_time(self.base_time, -86400).isoformat(),
                    "last_seen_at": offset_time(self.base_time, i * 10).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
