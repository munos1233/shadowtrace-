"""Contract tests for verification readiness predicates (ISSUE-216)."""

from __future__ import annotations

from pathlib import Path

from app.models.verification_readiness import IMMEDIATE_PENDING_SKIP_DETAILS

BACKEND_DIR = Path(__file__).resolve().parents[2]
VERIFY_AGENT_SOURCE = (BACKEND_DIR / "app" / "agents" / "verify_agent.py").read_text(
    encoding="utf-8"
)


def test_immediate_pending_skip_details_are_declared_in_verify_agent() -> None:
    """Gate detail strings must exist as literals in VerifyAgent phase-1 paths."""
    for detail in IMMEDIATE_PENDING_SKIP_DETAILS:
        assert f'"{detail}"' in VERIFY_AGENT_SOURCE or f"'{detail}'" in VERIFY_AGENT_SOURCE
    assert "deferred_pending_activation" not in IMMEDIATE_PENDING_SKIP_DETAILS


def test_immediate_pending_skip_details_cover_known_immediate_pending_cases() -> None:
    assert IMMEDIATE_PENDING_SKIP_DETAILS == frozenset(
        {
            "pending_execution",
            "approved_pending_execution",
            "action_not_executed",
        }
    )
