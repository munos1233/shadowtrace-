"""SCENARIO_EXPECTATIONS baseline for ISSUE-086 system tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.enums import EventType, FinalVerdict

# Eight EventType packs: three legacy demo scenarios + five ISSUE-086 packs.
SCENARIO_TO_EVENT_TYPE: dict[str, EventType] = {
    "insider_data_exfiltration": EventType.DATA_EXFILTRATION,
    "account_anomaly_fp": EventType.ACCOUNT_ANOMALY,
    "suspicious_domain_access": EventType.SUSPICIOUS_DOMAIN,
    "host_compromise": EventType.HOST_COMPROMISE,
    "malicious_process": EventType.MALICIOUS_PROCESS,
    "insider_privilege_abuse": EventType.INSIDER_THREAT,
    "lateral_movement": EventType.LATERAL_MOVEMENT,
    "other_unclassified": EventType.OTHER,
}

FULL_RESPONSE_SCENARIOS = frozenset(
    {
        "insider_data_exfiltration",
        "host_compromise",
        "lateral_movement",
    }
)

L3_APPROVAL_RESPONSE_SCENARIOS = frozenset(FULL_RESPONSE_SCENARIOS)

MOCK_WRITEBACK_SCENARIOS = frozenset(
    {
        "insider_data_exfiltration",
        "host_compromise",
        "malicious_process",
        "insider_privilege_abuse",
        "lateral_movement",
    }
)

FILE_ONLY_SCENARIOS = frozenset(
    {"account_anomaly_fp", "suspicious_domain_access", "other_unclassified"}
)


@dataclass(frozen=True)
class ScenarioExpectation:
    scenario_id: str
    event_type: EventType
    verdict: FinalVerdict | None
    acceptable_verdicts: tuple[FinalVerdict, ...]
    risk_min: int
    risk_max: int
    rule_fallback_risk_min: int
    rule_fallback_risk_max: int
    rule_fallback: bool
    allowed_actions: tuple[str, ...]
    disposition_required: bool
    expect_reporting: bool


def risk_bounds_for(spec: ScenarioExpectation, *, rule_only: bool) -> tuple[int, int]:
    if rule_only and spec.rule_fallback:
        return spec.rule_fallback_risk_min, spec.rule_fallback_risk_max
    return spec.risk_min, spec.risk_max


SCENARIO_EXPECTATIONS: dict[str, ScenarioExpectation] = {
    "insider_data_exfiltration": ScenarioExpectation(
        scenario_id="insider_data_exfiltration",
        event_type=EventType.DATA_EXFILTRATION,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(FinalVerdict.CONFIRMED_THREAT, FinalVerdict.NONE),
        risk_min=70,
        risk_max=100,
        rule_fallback_risk_min=82,
        rule_fallback_risk_max=92,
        rule_fallback=True,
        allowed_actions=("isolate_host", "block_ip", "create_ticket", "notify_security_team"),
        disposition_required=True,
        expect_reporting=True,
    ),
    "account_anomaly_fp": ScenarioExpectation(
        scenario_id="account_anomaly_fp",
        event_type=EventType.ACCOUNT_ANOMALY,
        # Demo pack is an ops-change FP in narrative; golden path may land threat/advisory FP.
        # Rule-fallback (LLM fail): score bands stay <70 without post-evidence close_as_fp
        # (ISSUE-114), so VerdictResolver → NONE. #675 also downgrades
        # evidence_limited+CONFIRMED_THREAT → NONE when that path applies.
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(
            FinalVerdict.CONFIRMED_THREAT,
            FinalVerdict.POSSIBLE_FALSE_POSITIVE,
            FinalVerdict.NONE,
        ),
        # Regression golden baseline: confirmed_threat @ 71 (ISSUE-099 enrichment).
        risk_min=65,
        risk_max=75,
        rule_fallback_risk_min=30,
        rule_fallback_risk_max=45,
        rule_fallback=True,
        allowed_actions=("create_ticket",),
        disposition_required=False,
        expect_reporting=False,
    ),
    "suspicious_domain_access": ScenarioExpectation(
        scenario_id="suspicious_domain_access",
        event_type=EventType.SUSPICIOUS_DOMAIN,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(
            FinalVerdict.CONFIRMED_THREAT,
            FinalVerdict.POSSIBLE_FALSE_POSITIVE,
            FinalVerdict.NONE,
        ),
        # Regression golden baseline: confirmed_threat @ 70.
        # Rule-fallback band is <70 → NONE is expected (same as host_compromise pack).
        risk_min=65,
        risk_max=75,
        rule_fallback_risk_min=40,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=("block_domain", "create_ticket", "notify_security_team"),
        disposition_required=False,
        expect_reporting=True,
    ),
    "host_compromise": ScenarioExpectation(
        scenario_id="host_compromise",
        event_type=EventType.HOST_COMPROMISE,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(FinalVerdict.CONFIRMED_THREAT, FinalVerdict.NONE),
        risk_min=70,
        risk_max=95,
        # ISSUE-099: source-enriched entities lift rule-only scores above the old 15-25 band.
        rule_fallback_risk_min=45,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=("isolate_host", "block_ip", "create_ticket", "notify_security_team"),
        disposition_required=True,
        expect_reporting=True,
    ),
    "malicious_process": ScenarioExpectation(
        scenario_id="malicious_process",
        event_type=EventType.MALICIOUS_PROCESS,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(FinalVerdict.CONFIRMED_THREAT, FinalVerdict.NONE),
        risk_min=70,
        risk_max=95,
        rule_fallback_risk_min=45,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=("block_process", "quarantine_file", "isolate_host", "create_ticket"),
        disposition_required=True,
        expect_reporting=True,
    ),
    "insider_privilege_abuse": ScenarioExpectation(
        scenario_id="insider_privilege_abuse",
        event_type=EventType.INSIDER_THREAT,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(FinalVerdict.CONFIRMED_THREAT, FinalVerdict.NONE),
        risk_min=65,
        risk_max=95,
        rule_fallback_risk_min=45,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=(
            "disable_account",
            "force_logout",
            "create_ticket",
            "notify_security_team",
        ),
        disposition_required=True,
        expect_reporting=True,
    ),
    "lateral_movement": ScenarioExpectation(
        scenario_id="lateral_movement",
        event_type=EventType.LATERAL_MOVEMENT,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(FinalVerdict.CONFIRMED_THREAT, FinalVerdict.NONE),
        risk_min=70,
        risk_max=95,
        rule_fallback_risk_min=45,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=("isolate_host", "block_ip", "disable_account", "create_ticket"),
        disposition_required=True,
        expect_reporting=True,
    ),
    "other_unclassified": ScenarioExpectation(
        scenario_id="other_unclassified",
        event_type=EventType.OTHER,
        verdict=FinalVerdict.CONFIRMED_THREAT,
        acceptable_verdicts=(
            FinalVerdict.CONFIRMED_THREAT,
            FinalVerdict.POSSIBLE_FALSE_POSITIVE,
            FinalVerdict.NONE,
        ),
        # Regression golden baseline: confirmed_threat @ 71.
        # Rule-fallback band is <70 → NONE is expected under ISSUE-035 score gate.
        risk_min=65,
        risk_max=75,
        rule_fallback_risk_min=45,
        rule_fallback_risk_max=60,
        rule_fallback=True,
        allowed_actions=("create_ticket", "notify_security_team"),
        disposition_required=False,
        expect_reporting=True,
    ),
}


def expectation_for(scenario_id: str) -> ScenarioExpectation:
    try:
        return SCENARIO_EXPECTATIONS[scenario_id]
    except KeyError as exc:
        known = ", ".join(sorted(SCENARIO_EXPECTATIONS))
        raise KeyError(f"unknown scenario expectation {scenario_id!r}; known: {known}") from exc


def as_public_dict(spec: ScenarioExpectation) -> dict[str, Any]:
    return {
        "scenario_id": spec.scenario_id,
        "event_type": spec.event_type.value,
        "verdict": spec.verdict.value if spec.verdict else None,
        "risk_min": spec.risk_min,
        "risk_max": spec.risk_max,
        "rule_fallback_risk_min": spec.rule_fallback_risk_min,
        "rule_fallback_risk_max": spec.rule_fallback_risk_max,
        "rule_fallback": spec.rule_fallback,
        "allowed_actions": list(spec.allowed_actions),
        "disposition_required": spec.disposition_required,
        "expect_reporting": spec.expect_reporting,
    }
