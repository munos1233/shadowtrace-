"""Identity / auth telemetry generator."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class IdentityGenerator(TelemetryGenerator):
    name = "identity"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"id-log-{self.seed}-{i:04d}",
                    "channel": "identity",
                    "event_type": "login" if i % 3 else "mfa_challenge",
                    "account": f"user-{i % 7}",
                    "src_ip": f"10.0.{i % 20}.{10 + (i % 40)}",
                    "result": "success" if i % 5 else "failure",
                    "logged_at": offset_time(self.base_time, i * 30).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
