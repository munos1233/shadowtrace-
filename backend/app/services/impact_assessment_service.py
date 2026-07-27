"""ImpactAssessmentService — business-impact estimation before action execution (ISSUE-079).

Evaluates the blast radius, reversibility, and business disruption risk of a
response action using fixed rules keyed on tool_name, action_level, and asset
information from query_asset_info.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.network_utils import is_internal_ip
from app.models.action import Action, ImpactAssessment
from app.models.enums import ActionLevel, BusinessDisruption
from app.tools.specs.response import RESPONSE_ROLLBACK_MAP

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Fixed rule tables
# --------------------------------------------------------------------------- #

# Base impact score by action level (ISSUE-079 spec).
_ACTION_LEVEL_BASE_SCORE: dict[str, int] = {
    ActionLevel.L0.value: 10,
    ActionLevel.L1.value: 10,
    ActionLevel.L2.value: 30,
    ActionLevel.L3.value: 50,
    ActionLevel.L4.value: 70,
    ActionLevel.L5.value: 90,
}

# Asset value bonus added to base score (capped at 100).
_ASSET_VALUE_BONUS: dict[str, int] = {
    "critical": 20,
    "high": 10,
    "medium": 0,
    "low": 0,
}

# Business disruption rules by tool_name × asset/entity characteristics.
# Each entry: (condition_key, condition_value) → business_disruption.
# Special condition_key "default" matches any tool not explicitly listed.
_BUSINESS_DISRUPTION_RULES: dict[str, list[tuple[str, str, str]]] = {
    "isolate_host": [
        ("asset_value", "critical", BusinessDisruption.HIGH.value),
        ("asset_value", "high", BusinessDisruption.MEDIUM.value),
        ("default", "", BusinessDisruption.MEDIUM.value),
    ],
    "disable_account": [
        ("business_role", "admin", BusinessDisruption.HIGH.value),
        ("business_role", "domain_admin", BusinessDisruption.HIGH.value),
        ("default", "", BusinessDisruption.MEDIUM.value),
    ],
    "block_ip": [
        ("ip_scope", "internal", BusinessDisruption.MEDIUM.value),
        ("ip_scope", "external", BusinessDisruption.LOW.value),
        ("default", "", BusinessDisruption.LOW.value),
    ],
    "quarantine_file": [
        ("default", "", BusinessDisruption.LOW.value),
    ],
    "force_logout": [
        ("default", "", BusinessDisruption.MEDIUM.value),
    ],
}

# Tools with zero business disruption (purely informational / ticketing).
_ZERO_DISRUPTION_TOOLS: frozenset[str] = frozenset(
    {
        "create_ticket",
        "notify_security_team",
        "update_source_event_disposition",
    }
)

# Reversibility derived from RESPONSE_ROLLBACK_MAP (ISSUE-079 §4.5).
# A tool is reversible if it has a corresponding rollback tool in the canonical
# map; tools absent from the map default to reversible=False (matching the intro
# rule: "无映射则 rollback_supported=False").
_REVERSIBLE_TOOLS: dict[str, bool] = {tool: True for tool in RESPONSE_ROLLBACK_MAP}
# force_logout is explicitly irreversible (no rollback tool exists).
_REVERSIBLE_TOOLS["force_logout"] = False


def _base_score(action_level: str) -> int:
    """Return the base impact score for an action level, defaulting to 30."""
    return _ACTION_LEVEL_BASE_SCORE.get(action_level, 30)


def _asset_bonus(asset_value: str | None) -> int:
    """Return the asset-value bonus, defaulting to 0 for unknown/missing."""
    if asset_value is None:
        return 0
    return _ASSET_VALUE_BONUS.get(asset_value.lower(), 0)


def _business_disruption(
    tool_name: str,
    asset_info: dict[str, Any] | None,
    target: str | None,
) -> str:
    """Determine business_disruption from fixed rules.

    Args:
        tool_name: The action's tool_name (e.g. "isolate_host").
        asset_info: Dict from query_asset_info with asset_value, business_role, etc.
        target: The action target (IP, hostname, username, etc.).

    Returns:
        One of "none", "low", "medium", "high".
    """
    # Zero-disruption tools.
    if tool_name in _ZERO_DISRUPTION_TOOLS:
        return BusinessDisruption.NONE.value

    # Look up rules for this tool.
    rules = _BUSINESS_DISRUPTION_RULES.get(tool_name)
    if rules is None:
        return BusinessDisruption.LOW.value

    asset = asset_info or {}

    for condition_key, condition_value, disruption in rules:
        if condition_key == "default":
            return disruption

        # Evaluate condition.
        if condition_key == "asset_value":
            actual = str(asset.get("asset_value", "")).lower()
            if actual == condition_value:
                return disruption

        elif condition_key == "business_role":
            actual = str(asset.get("business_role", "")).lower()
            if actual == condition_value or condition_value in actual:
                return disruption

        elif condition_key == "ip_scope":
            if target:
                if condition_value == "internal" and is_internal_ip(target):
                    return disruption
                if condition_value == "external" and not is_internal_ip(target):
                    return disruption

    return BusinessDisruption.LOW.value


def _is_reversible(tool_name: str) -> bool:
    """Check reversibility against the canonical RESPONSE_ROLLBACK_MAP.

    Defaults to False for tools with no rollback mapping, matching the
    intro §4.5 rule: "无映射则 rollback_supported=False".
    """
    return _REVERSIBLE_TOOLS.get(tool_name, False)


def _describe_scope(action: Action, asset_info: dict[str, Any] | None) -> str:
    """Build a human-readable affected_scope description."""
    parts: list[str] = [f"tool={action.tool_name}"]

    if action.target:
        parts.append(f"target={action.target}")
    if action.target_type:
        parts.append(f"target_type={action.target_type}")

    if asset_info:
        asset_value = asset_info.get("asset_value", "")
        business_role = asset_info.get("business_role", "")
        hostname = asset_info.get("hostname", "")
        if asset_value:
            parts.append(f"asset_value={asset_value}")
        if business_role:
            parts.append(f"business_role={business_role}")
        if hostname:
            parts.append(f"hostname={hostname}")

    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Default asset info provider
# --------------------------------------------------------------------------- #


def create_default_asset_provider() -> Any:
    """Build a default ``asset_info_provider`` backed by ``query_asset_info``.

    The provider tries the real tool first; if the evidence projection is not
    available or the query fails, it returns ``None`` and the service degrades
    gracefully to medium estimates.
    """

    async def _provider(target: str, target_type: str | None) -> dict[str, Any] | None:
        try:
            from app.tools.query.query_asset_info import execute as _query_asset_info

            params: dict[str, Any] = {}
            if target_type in ("ip", "host") or not target_type:
                params["ip"] = target
            else:
                params["hostname"] = target

            result = await _query_asset_info(params)
            data = result.get("data", [])
            if isinstance(data, list) and data:
                first = data[0]
                if isinstance(first, dict):
                    return {
                        "asset_value": first.get("asset_value", "medium"),
                        "business_role": first.get("business_role", ""),
                        "hostname": first.get("hostname", target),
                    }
            return None
        except Exception:
            logger.debug(
                "default asset_info_provider: query_asset_info unavailable for target=%s",
                target,
                exc_info=True,
            )
            return None

    return _provider


# --------------------------------------------------------------------------- #
# ImpactAssessmentService
# --------------------------------------------------------------------------- #


class ImpactAssessmentService:
    """Estimate business impact of a response action before execution.

    Uses fixed rules (tool_name × asset characteristics) to produce an
    :class:`ImpactAssessment` with a composite impact_score, business_disruption
    level, reversibility flag, and human-readable scope / detail.

    Asset information is queried via an optional *asset_info_provider* callable.
    When the provider is unavailable or the query fails, the service falls back
    to a medium estimate and annotates ``assessment_detail`` accordingly.
    """

    def __init__(
        self,
        *,
        asset_info_provider: Any = None,
    ) -> None:
        """Args:
        asset_info_provider: Optional async callable ``(target: str, target_type: str | None)
            -> dict | None`` that queries asset info.  When None, all assessments
            use the medium-estimate fallback.
        """
        self._asset_provider = asset_info_provider

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def assess(self, action: Action, event_context: Any = None) -> ImpactAssessment:
        """Estimate the business impact of *action*.

        Args:
            action: The response action to assess.
            event_context: Reserved for future entity-aware assessment (unused in P0).

        Returns:
            ImpactAssessment with impact_score, business_disruption, reversible,
            affected_scope, and assessment_detail.
        """
        tool_name = action.tool_name
        action_level = action.action_level.value if action.action_level else "l1"

        # --- asset info ---
        asset_info: dict[str, Any] | None = None
        degraded = False
        if self._asset_provider is not None and action.target:
            try:
                asset_info = await self._asset_provider(action.target, action.target_type)
            except Exception:
                logger.warning(
                    "ImpactAssessmentService: asset query failed for target=%s; "
                    "using medium estimate",
                    action.target,
                    exc_info=True,
                )
                degraded = True
        elif self._asset_provider is None:
            degraded = True

        # --- compute components ---
        base = _base_score(action_level)
        bonus = _asset_bonus(asset_info.get("asset_value") if asset_info else None)
        impact_score = min(base + bonus, 100)

        business_disruption = _business_disruption(tool_name, asset_info, action.target)
        reversible = _is_reversible(tool_name)
        affected_scope = _describe_scope(action, asset_info)

        detail_parts: list[str] = []
        if degraded:
            detail_parts.append("Asset information unavailable; using medium-estimate fallback.")
        detail_parts.append(
            f"Base score={base} (level={action_level}), asset bonus={bonus}, "
            f"total={impact_score}; disruption={business_disruption}; "
            f"reversible={reversible}"
        )
        assessment_detail = " | ".join(detail_parts)

        return ImpactAssessment(
            action_id=action.action_id,
            impact_score=impact_score,
            affected_scope=affected_scope,
            reversible=reversible,
            business_disruption=business_disruption,
            assessment_detail=assessment_detail,
            assessed_by="ImpactAssessmentService",
        )


__all__ = [
    "ImpactAssessmentService",
    "create_default_asset_provider",
]
