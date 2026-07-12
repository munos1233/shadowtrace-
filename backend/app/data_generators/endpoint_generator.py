"""Endpoint / EDR telemetry generator."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class EndpointGenerator(TelemetryGenerator):
    name = "endpoint"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"ep-log-{self.seed}-{i:04d}",
                    "channel": "endpoint",
                    "hostname": f"host-{i % 5:03d}",
                    "process": "powershell.exe" if i % 4 == 0 else "chrome.exe",
                    "account": f"user-{i % 7}",
                    "action": "process_create",
                    "logged_at": offset_time(self.base_time, i * 45).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
