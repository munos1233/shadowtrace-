"""Threat-intel indicator generator."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class ThreatIntelGenerator(TelemetryGenerator):
    name = "threat_intel"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"ti-{self.seed}-{i:04d}",
                    "channel": "threat_intel",
                    "indicator": f"ioc-{i}.bad.example",
                    "indicator_type": "domain" if i % 2 == 0 else "ip",
                    "confidence": round(0.4 + (i % 6) * 0.1, 2),
                    "logged_at": offset_time(self.base_time, i * 100).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
