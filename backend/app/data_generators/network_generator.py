"""Network flow telemetry generator (also emits dns via NetworkGenerator helper)."""

from __future__ import annotations

from typing import Any

from app.data_generators.base import TelemetryGenerator, offset_time


class NetworkGenerator(TelemetryGenerator):
    name = "network"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"net-log-{self.seed}-{i:04d}",
                    "channel": "network",
                    "src_ip": f"10.1.{i % 10}.{i % 50}",
                    "dst_ip": f"203.0.113.{i % 200}",
                    "dst_port": 443 if i % 2 == 0 else 8080,
                    "bytes_out": 500 * (i + 1),
                    "logged_at": offset_time(self.base_time, i * 20).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows


class DnsGenerator(TelemetryGenerator):
    """DNS query telemetry; writes ``dns_logs.json``."""

    name = "dns"

    def generate(self, *, count: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for i in range(count):
            rows.append(
                {
                    "record_id": f"dns-log-{self.seed}-{i:04d}",
                    "channel": "dns",
                    "query": f"host-{i}.example.test",
                    "qtype": "A",
                    "rcode": "NOERROR",
                    "logged_at": offset_time(self.base_time, i * 15).isoformat(),
                    "is_conflict_seed": False,
                }
            )
        return rows
