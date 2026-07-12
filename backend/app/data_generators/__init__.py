"""Telemetry / scenario generation framework (ISSUE-010)."""

from __future__ import annotations

from app.data_generators.asset_generator import AssetGenerator
from app.data_generators.base import (
    TELEMETRY_FILENAMES,
    TelemetryGenerator,
    offset_time,
    write_telemetry_files,
)
from app.data_generators.dlp_generator import DlpGenerator
from app.data_generators.endpoint_generator import EndpointGenerator
from app.data_generators.identity_generator import IdentityGenerator
from app.data_generators.network_generator import DnsGenerator, NetworkGenerator
from app.data_generators.noise import NoiseGenerator
from app.data_generators.threat_intel_generator import ThreatIntelGenerator


def default_generators(*, seed: int = 0) -> list[TelemetryGenerator]:
    """The seven fixed telemetry channels (noise is optional / merged separately)."""
    return [
        IdentityGenerator(seed=seed),
        EndpointGenerator(seed=seed),
        DlpGenerator(seed=seed),
        NetworkGenerator(seed=seed),
        DnsGenerator(seed=seed),
        AssetGenerator(seed=seed),
        ThreatIntelGenerator(seed=seed),
    ]


__all__ = [
    "TELEMETRY_FILENAMES",
    "AssetGenerator",
    "DlpGenerator",
    "DnsGenerator",
    "EndpointGenerator",
    "IdentityGenerator",
    "NetworkGenerator",
    "NoiseGenerator",
    "TelemetryGenerator",
    "ThreatIntelGenerator",
    "default_generators",
    "offset_time",
    "write_telemetry_files",
]
