"""SourcePolicyResolver unit tests (ISSUE-015)."""

from __future__ import annotations

import pytest

from app.models.enums import DispositionPolicy, SourceObjectKind
from app.services.source_policy_resolver import SourcePolicyResolver


@pytest.fixture
def resolver() -> SourcePolicyResolver:
    return SourcePolicyResolver()


def test_file_and_manual_are_not_required(resolver: SourcePolicyResolver) -> None:
    assert resolver.resolve(source_type="file") is DispositionPolicy.NOT_REQUIRED
    assert resolver.resolve(source_type="manual") is DispositionPolicy.NOT_REQUIRED


def test_mock_xdr_defaults_to_required(resolver: SourcePolicyResolver) -> None:
    assert resolver.resolve(source_product="mock_xdr") is DispositionPolicy.REQUIRED
    assert resolver.resolve(source_mode="mock_xdr") is DispositionPolicy.REQUIRED


def test_connector_override_honored(resolver: SourcePolicyResolver) -> None:
    assert (
        resolver.resolve(
            source_product="mock_xdr",
            connector_policy_default=DispositionPolicy.NOT_REQUIRED,
        )
        is DispositionPolicy.NOT_REQUIRED
    )
    assert (
        resolver.resolve(
            source_product="sangfor_xdr",
            connector_policy_default="required",
            source_mode="live",
        )
        is DispositionPolicy.REQUIRED
    )


def test_live_without_explicit_policy_raises(resolver: SourcePolicyResolver) -> None:
    with pytest.raises(ValueError, match="explicit disposition_policy_default"):
        resolver.resolve(source_mode="live", live_configured=True)


def test_readiness_block_reasons(resolver: SourcePolicyResolver) -> None:
    assert (
        resolver.readiness_when_required_but_blocked(
            has_writable_locator=False, capability_state="SUPPORTED"
        )
        == "source_unresolved"
    )
    assert (
        resolver.readiness_when_required_but_blocked(
            has_writable_locator=True, capability_state="UNKNOWN"
        )
        == "capability_unknown"
    )
    assert (
        resolver.readiness_when_required_but_blocked(
            has_writable_locator=True, capability_state="UNSUPPORTED"
        )
        == "capability_unsupported"
    )
    assert (
        resolver.readiness_when_required_but_blocked(
            has_writable_locator=True, capability_state="SUPPORTED"
        )
        is None
    )


def test_kind_does_not_override_file(resolver: SourcePolicyResolver) -> None:
    assert (
        resolver.resolve(source_type="file", source_kind=SourceObjectKind.ALERT)
        is DispositionPolicy.NOT_REQUIRED
    )
