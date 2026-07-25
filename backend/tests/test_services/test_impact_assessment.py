"""Tests for ImpactAssessmentService (ISSUE-079)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.models.action import Action, ImpactAssessment
from app.models.enums import (
    ActionCategory,
    ActionLevel,
    ExecutionOwner,
)
from app.services.impact_assessment_service import (
    _ACTION_LEVEL_BASE_SCORE,
    _ASSET_VALUE_BONUS,
    ImpactAssessmentService,
    _base_score,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _action(
    action_id: str = "act-001",
    tool_name: str = "isolate_host",
    action_level: ActionLevel = ActionLevel.L3,
    target: str | None = "10.0.0.1",
    target_type: str | None = "host",
    **kwargs: Any,
) -> Action:
    return Action(
        action_id=action_id,
        event_id="evt-001",
        plan_revision=1,
        action_fingerprint="fp-001",
        action_category=ActionCategory.RESPONSE,
        action_name=tool_name.replace("_", " ").title(),
        tool_name=tool_name,
        action_level=action_level,
        target=target,
        target_type=target_type,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        **kwargs,
    )


def _asset_info(
    asset_value: str = "medium",
    business_role: str = "workstation",
    hostname: str = "HOST-01",
) -> dict[str, Any]:
    return {
        "asset_value": asset_value,
        "business_role": business_role,
        "hostname": hostname,
    }


# --------------------------------------------------------------------------- #
# Score calculation
# --------------------------------------------------------------------------- #


def test_base_scores_by_action_level() -> None:
    assert _base_score("l0") == 10
    assert _base_score("l1") == 10
    assert _base_score("l2") == 30
    assert _base_score("l3") == 50
    assert _base_score("l4") == 70
    assert _base_score("l5") == 90
    assert _base_score("unknown") == 30  # default


def test_asset_bonus_values() -> None:
    assert _ASSET_VALUE_BONUS["critical"] == 20
    assert _ASSET_VALUE_BONUS["high"] == 10
    assert _ASSET_VALUE_BONUS["medium"] == 0
    assert _ASSET_VALUE_BONUS["low"] == 0


# --------------------------------------------------------------------------- #
# Impact assessment: score capped at 100
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_score_capped_at_100() -> None:
    svc = ImpactAssessmentService()
    action = _action(action_level=ActionLevel.L5, tool_name="isolate_host")  # base=90
    # Simulate asset_info with critical value (+20) → total would be 110
    result = await svc.assess(action)
    assert result.impact_score <= 100


# --------------------------------------------------------------------------- #
# Business disruption: isolate_host
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_isolate_host_critical_asset_disruption_high() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="critical"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", target="10.0.0.1")

    result = await svc.assess(action)
    assert result.business_disruption == "high"
    assert "asset_value=critical" in result.affected_scope


@pytest.mark.asyncio
async def test_isolate_host_high_asset_disruption_medium() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="high"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", target="10.0.0.1")

    result = await svc.assess(action)
    assert result.business_disruption == "medium"


@pytest.mark.asyncio
async def test_isolate_host_low_asset_disruption_medium() -> None:
    """Default for isolate_host is medium when asset not critical/high."""
    provider = AsyncMock(return_value=_asset_info(asset_value="low"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", target="10.0.0.1")

    result = await svc.assess(action)
    assert result.business_disruption == "medium"


# --------------------------------------------------------------------------- #
# Business disruption: disable_account
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_disable_account_admin_disruption_high() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="high", business_role="admin"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="disable_account", target="admin_user")

    result = await svc.assess(action)
    assert result.business_disruption == "high"


@pytest.mark.asyncio
async def test_disable_account_domain_admin_disruption_high() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="high", business_role="domain_admin"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="disable_account", target="da_user")

    result = await svc.assess(action)
    assert result.business_disruption == "high"


@pytest.mark.asyncio
async def test_disable_account_regular_user_disruption_medium() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="low", business_role="employee"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="disable_account", target="normal_user")

    result = await svc.assess(action)
    assert result.business_disruption == "medium"


# --------------------------------------------------------------------------- #
# Business disruption: block_ip
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_block_ip_internal_disruption_medium() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="block_ip", target="10.0.0.5")

    result = await svc.assess(action)
    assert result.business_disruption == "medium"


@pytest.mark.asyncio
async def test_block_ip_external_disruption_low() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="block_ip", target="8.8.8.8")

    result = await svc.assess(action)
    assert result.business_disruption == "low"


# --------------------------------------------------------------------------- #
# Zero-disruption tools
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_ticket_disruption_none() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="create_ticket", target=None)
    result = await svc.assess(action)
    assert result.business_disruption == "none"


@pytest.mark.asyncio
async def test_notify_security_team_disruption_none() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="notify_security_team", target=None)
    result = await svc.assess(action)
    assert result.business_disruption == "none"


# --------------------------------------------------------------------------- #
# Reversibility
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_isolate_host_reversible() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="isolate_host", target="10.0.0.1")
    result = await svc.assess(action)
    assert result.reversible is True


@pytest.mark.asyncio
async def test_force_logout_not_reversible() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="force_logout", target="user123")
    result = await svc.assess(action)
    assert result.reversible is False


@pytest.mark.asyncio
async def test_block_ip_reversible() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="block_ip", target="10.0.0.5")
    result = await svc.assess(action)
    assert result.reversible is True


# --------------------------------------------------------------------------- #
# Asset query failure: degradation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_asset_query_failure_uses_medium_estimate() -> None:
    provider = AsyncMock(side_effect=RuntimeError("Asset DB down"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", action_level=ActionLevel.L3, target="10.0.0.1")

    result = await svc.assess(action)
    # Base = 50 (L3), bonus = 0 (no asset info) → 50
    assert result.impact_score == 50
    assert "medium-estimate fallback" in (result.assessment_detail or "")
    # Default disruption for isolate_host = medium (without asset info)
    assert result.business_disruption == "medium"
    assert result.action_id == "act-001"


@pytest.mark.asyncio
async def test_no_asset_provider_uses_medium_estimate() -> None:
    svc = ImpactAssessmentService()  # no provider
    action = _action(
        tool_name="isolate_host",
        action_level=ActionLevel.L4,  # base=70
        target="10.0.0.1",
    )

    result = await svc.assess(action)
    assert result.impact_score == 70  # base only, no bonus
    assert "medium-estimate fallback" in (result.assessment_detail or "")


# --------------------------------------------------------------------------- #
# Impact score with asset bonus
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_score_l3_with_critical_asset() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="critical"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", action_level=ActionLevel.L3, target="10.0.0.1")

    result = await svc.assess(action)
    # Base 50 + critical bonus 20 = 70
    assert result.impact_score == 70


@pytest.mark.asyncio
async def test_score_l5_with_high_asset() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="high"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="isolate_host", action_level=ActionLevel.L5, target="10.0.0.1")

    result = await svc.assess(action)
    # Base 90 + high bonus 10 = 100 (capped)
    assert result.impact_score == 100


@pytest.mark.asyncio
async def test_score_l0_with_low_asset() -> None:
    provider = AsyncMock(return_value=_asset_info(asset_value="low"))
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(tool_name="create_ticket", action_level=ActionLevel.L0, target=None)

    result = await svc.assess(action)
    # Base 10 + low bonus 0 = 10
    assert result.impact_score == 10


# --------------------------------------------------------------------------- #
# Output fields
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_result_fields_are_complete() -> None:
    provider = AsyncMock(
        return_value=_asset_info(
            asset_value="critical",
            business_role="domain_controller",
            hostname="DC-01",
        )
    )
    svc = ImpactAssessmentService(asset_info_provider=provider)
    action = _action(
        action_id="act-isolate-dc",
        tool_name="isolate_host",
        action_level=ActionLevel.L4,
        target="10.0.0.10",
        target_type="host",
    )

    result = await svc.assess(action)

    assert result.action_id == "act-isolate-dc"
    assert result.impact_score == 90  # L4=70 + critical=20
    assert "tool=isolate_host" in result.affected_scope
    assert "target=10.0.0.10" in result.affected_scope
    assert "asset_value=critical" in result.affected_scope
    assert "hostname=DC-01" in result.affected_scope
    assert result.business_disruption == "high"
    assert result.reversible is True
    assert result.assessment_detail is not None
    assert (
        "base score=70" in result.assessment_detail.lower()
        or "base score" in result.assessment_detail.lower()
    )
    assert result.assessed_by == "ImpactAssessmentService"


# --------------------------------------------------------------------------- #
# Unknown tool defaults
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_unknown_tool_defaults_to_low_disruption() -> None:
    svc = ImpactAssessmentService()
    action = _action(tool_name="some_future_tool", target="test-target")

    result = await svc.assess(action)
    assert result.business_disruption == "low"


# --------------------------------------------------------------------------- #
# Integration: ImpactAssessment model validation
# --------------------------------------------------------------------------- #


def test_impact_assessment_model_valid() -> None:
    ia = ImpactAssessment(
        action_id="act-001",
        impact_score=75,
        affected_scope="tool=isolate_host; target=10.0.0.1; asset_value=critical",
        reversible=True,
        business_disruption="high",
        assessment_detail="Critical domain controller isolation",
        assessed_by="ImpactAssessmentService",
    )
    assert ia.action_id == "act-001"
    assert ia.impact_score == 75
    assert ia.business_disruption == "high"
    assert ia.reversible is True


def test_impact_assessment_score_bounds() -> None:
    # impact_score must be 0-100
    with pytest.raises(ValidationError):
        ImpactAssessment(
            action_id="act-001",
            impact_score=150,  # exceeds 100
            affected_scope="test",
            business_disruption="low",
        )

    with pytest.raises(ValidationError):
        ImpactAssessment(
            action_id="act-001",
            impact_score=-1,  # below 0
            affected_scope="test",
            business_disruption="low",
        )


def test_impact_assessment_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        ImpactAssessment(
            action_id="act-001",
            impact_score=50,
            affected_scope="test",
            business_disruption="low",
            extra_field="nope",  # type: ignore[call-arg]
        )


# --------------------------------------------------------------------------- #
# All base score levels registered
# --------------------------------------------------------------------------- #


def test_all_action_levels_have_base_scores() -> None:
    for level in ActionLevel:
        assert level.value in _ACTION_LEVEL_BASE_SCORE, f"Missing base score for {level.value}"
