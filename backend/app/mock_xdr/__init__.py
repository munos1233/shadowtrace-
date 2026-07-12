"""Standalone Mock XDR server (ISSUE-010).

Provides read + disposition writeback under ``/mock-xdr/v1`` for contract testing.
These URLs and behaviours are ShadowTrace Mock fixtures — not vendor API facts.
"""

from __future__ import annotations

from app.mock_xdr.models import MockFailureProfile, MockXDRScenario, ScenarioTick
from app.mock_xdr.state import MockXDRState

__all__ = [
    "MockFailureProfile",
    "MockXDRScenario",
    "MockXDRState",
    "ScenarioTick",
]
