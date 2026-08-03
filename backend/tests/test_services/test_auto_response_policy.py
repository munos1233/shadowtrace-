"""Auto-response policy unit tests (ISSUE-109 / #613 Phase 1)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.db import models as orm
from app.models.enums import EventStatus, Severity
from app.services.auto_response_policy import AutoResponsePolicyService


def _event(
    *,
    status: str = EventStatus.NEW.value,
    severity: str = Severity.HIGH.value,
    event_type: str = "malicious_process",
    source_product: str = "mock_xdr",
) -> orm.SecurityEvent:
    return orm.SecurityEvent(
        event_id="evt-response-1",
        event_type=event_type,
        title="test",
        description="",
        status=status,
        severity=severity,
        final_verdict="none",
        creation_source_ref={"source_product": source_product},
        source_reference_snapshots=[],
        disposition_policy="not_required",
        raw_alert_ids=[],
        source_type=source_product,
    )


def test_auto_response_disabled_by_default() -> None:
    policy = AutoResponsePolicyService(Settings(AUTO_RESPONSE_ENABLED=False))
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "disabled"


def test_auto_response_independent_of_auto_investigate() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_INVESTIGATE_ENABLED=False,
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is True
    assert decision.reason == "auto_response:policy_match"


def test_settings_reject_non_mock_source_when_auto_response_enabled() -> None:
    with pytest.raises(ConfigurationError, match="source_mode=file"):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="file",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )


def test_auto_response_blocks_analysis_only_orchestration() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            ORCHESTRATION_MODE="analysis_only",
        )
    )
    decision = policy.evaluate(_event(), link_role="primary", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "orchestration_analysis_only"


def test_auto_response_min_severity_high_excludes_medium() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            AUTO_RESPONSE_MIN_SEVERITY="high",
        )
    )
    decision = policy.evaluate(
        _event(severity=Severity.MEDIUM.value),
        link_role="primary",
        source_product="mock_xdr",
    )
    assert decision.eligible is False
    assert decision.reason == "below_min_severity"


def test_auto_response_event_type_allowlist() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            AUTO_RESPONSE_EVENT_TYPES="malicious_process",
        )
    )
    allowed = policy.evaluate(_event(event_type="malicious_process"), link_role="primary")
    blocked = policy.evaluate(_event(event_type="account_anomaly_fp"), link_role="primary")
    assert allowed.eligible is True
    assert blocked.eligible is False
    assert blocked.reason == "event_type_not_allowed"


def test_auto_response_blocks_provisional_link_role() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    decision = policy.evaluate(_event(), link_role="provisional", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "provisional_hold"


def test_auto_response_blocks_unknown_link_role() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    decision = policy.evaluate(_event(), link_role="unknown", source_product="mock_xdr")
    assert decision.eligible is False
    assert decision.reason == "link_role_not_primary"


def test_format_auto_response_audit_reason_skipped() -> None:
    from app.services.auto_response_policy import (
        AutoResponseDecision,
        format_auto_response_audit_reason,
    )

    reason = format_auto_response_audit_reason(
        AutoResponseDecision(False, "below_min_severity"),
    )
    assert reason == "auto_response:skipped_below_min_severity"


def test_auto_response_rejects_untrusted_provenance() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    decision = policy.evaluate(
        _event(source_product="sentinelone"),
        link_role="primary",
        source_product="sentinelone",
    )
    assert decision.eligible is False
    assert decision.reason == "untrusted_provenance"


def test_auto_response_rejects_non_new_status() -> None:
    policy = AutoResponsePolicyService(
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )
    )
    decision = policy.evaluate(
        _event(status=EventStatus.TRIAGING.value),
        link_role="primary",
    )
    assert decision.eligible is False
    assert decision.reason == "status_not_new"


def test_settings_reject_live_tool_mode_when_auto_response_enabled() -> None:
    with pytest.raises(ConfigurationError, match="AUTO_RESPONSE_ENABLED"):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="live",
            DISPOSITION_MODE="mock_xdr",
        )


def test_settings_reject_l2_max_auto_level_when_auto_response_enabled() -> None:
    with pytest.raises(ConfigurationError, match="auto_response_max_auto_level"):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            AUTO_RESPONSE_MAX_AUTO_LEVEL="L2",
        )


def test_resolve_runtime_max_auto_level_none_when_disabled() -> None:
    from app.services.action_approval_policy import resolve_runtime_max_auto_level

    settings = Settings(AUTO_RESPONSE_ENABLED=False)
    assert resolve_runtime_max_auto_level(settings) is None


def test_resolve_runtime_max_auto_level_l0_when_configured() -> None:
    from app.models.enums import ActionLevel
    from app.services.action_approval_policy import resolve_runtime_max_auto_level

    settings = Settings(
        AUTO_RESPONSE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        TOOL_MODE="mock",
        DISPOSITION_MODE="mock_xdr",
        AUTO_RESPONSE_MAX_AUTO_LEVEL="L0",
    )
    assert resolve_runtime_max_auto_level(settings) is ActionLevel.L0
