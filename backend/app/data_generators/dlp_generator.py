"""DLP telemetry generator."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class DlpGenerator(TelemetryGenerator):
    name = "dlp"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"dlp-log-{self.seed}-{i:04d}",
                    "channel": "dlp",
                    "file_name": f"doc-{i}.zip" if i % 2 else f"sheet-{i}.xlsx",
                    "action": "upload" if i % 3 else "copy",
                    "bytes": 1024 * (i + 1),
                    "logged_at": offset_time(self.base_time, i * 60).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
