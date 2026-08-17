"""Minimal system-test scenario packs for eight EventType coverage (ISSUE-086).

Each pack produces 12–18 key telemetry rows across the seven fixed channels and
registers ``expected_outcome`` metadata used by ``SCENARIO_EXPECTATIONS``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.data_generators.scenarios._common import (
    DEFAULT_BASE_TIME,
    DEFAULT_TENANT,
    SCENARIO_VARIANTS,
    capability_gap_connector,
    disposition_connector,
    event,
    failure_profile_for_variant,
    log_only_connector,
    make_ref,
    normalize_variant,
    telemetry_for_variant,
)
from app.mock_xdr.models import MockXDRScenario, ScenarioVariant
from app.models.enums import (
    DispositionPolicy,
    FinalVerdict,
    Severity,
    SourceObjectKind,
)
from app.models.source import SourceAlert, SourceAsset, SourceIncident, SourceLog

# RFC5737 documentation range only.
DOC_IP = "198.51.100.55"
DOC_DOMAIN = "beacon-example.test"


@dataclass(frozen=True)
class SystemScenarioSpec:
    scenario_id: str
    name: str
    event_type: str
    title: str
    description: str
    hostname: str
    account: str
    disposition_policy: DispositionPolicy
    expected_verdict: FinalVerdict
    expected_severity: Severity
    risk_score: int
    risk_min: int
    risk_max: int
    allowed_actions: tuple[str, ...]
    incident_id: str
    alert_id: str
    asset_id: str
    log_id: str
    keyword: str


HOST_COMPROMISE_SPEC = SystemScenarioSpec(
    scenario_id="host_compromise",
    name="Host compromise with beacon activity",
    event_type="host_compromise",
    title="Host compromise detected — persistent beacon to external C2",
    description="Endpoint host compromise with suspicious beacon and host_compromise tag",
    hostname="WKS-HOST-007",
    account="svc-beacon-007",
    disposition_policy=DispositionPolicy.REQUIRED,
    expected_verdict=FinalVerdict.CONFIRMED_THREAT,
    expected_severity=Severity.HIGH,
    risk_score=78,
    risk_min=70,
    risk_max=95,
    allowed_actions=("isolate_host", "block_ip", "create_ticket", "notify_security_team"),
    incident_id="770011",
    alert_id="aabbccdd-0011-4000-8000-000000000011",
    asset_id="asset_host_compromise_007_long",
    log_id="880011",
    keyword="beacon",
)

MALICIOUS_PROCESS_SPEC = SystemScenarioSpec(
    scenario_id="malicious_process",
    name="Malicious process execution chain",
    event_type="malicious_process",
    title="Malicious process spawned — ransomware-like behavior",
    description="Endpoint malicious_process execution with suspicious binary chain",
    hostname="DEV-WKS-012",
    account="dev-user-012",
    disposition_policy=DispositionPolicy.REQUIRED,
    expected_verdict=FinalVerdict.CONFIRMED_THREAT,
    expected_severity=Severity.HIGH,
    risk_score=76,
    risk_min=70,
    risk_max=95,
    allowed_actions=("block_process", "quarantine_file", "isolate_host", "create_ticket"),
    incident_id="770012",
    alert_id="aabbccdd-0012-4000-8000-000000000012",
    asset_id="120012",
    log_id="880012",
    keyword="malicious_process",
)

INSIDER_PRIVILEGE_ABUSE_SPEC = SystemScenarioSpec(
    scenario_id="insider_privilege_abuse",
    name="Insider privilege abuse escalation",
    event_type="insider_threat",
    title="Insider privilege escalation and abuse of admin rights",
    description="Insider threat with privilege escalation and sensitive access",
    hostname="SRV-ADMIN-003",
    account="svc-admin-abuse",
    disposition_policy=DispositionPolicy.REQUIRED,
    expected_verdict=FinalVerdict.CONFIRMED_THREAT,
    expected_severity=Severity.HIGH,
    risk_score=74,
    risk_min=65,
    risk_max=95,
    allowed_actions=("disable_account", "force_logout", "create_ticket", "notify_security_team"),
    incident_id="770013",
    alert_id="xdr_alert_insider_privilege_abuse_20240615",
    asset_id="130013",
    log_id="880013",
    keyword="privilege",
)

LATERAL_MOVEMENT_SPEC = SystemScenarioSpec(
    scenario_id="lateral_movement",
    name="Lateral movement via RDP pivot",
    event_type="lateral_movement",
    title="Lateral movement detected — RDP pivot to internal server",
    description="Lateral movement using RDP pivot between internal hosts",
    hostname="JUMP-HOST-001",
    account="ops-jump-001",
    disposition_policy=DispositionPolicy.REQUIRED,
    expected_verdict=FinalVerdict.CONFIRMED_THREAT,
    expected_severity=Severity.HIGH,
    risk_score=80,
    risk_min=70,
    risk_max=95,
    allowed_actions=("isolate_host", "block_ip", "disable_account", "create_ticket"),
    incident_id="770014",
    alert_id="99110014",
    asset_id="140014",
    log_id="880014",
    keyword="lateral",
)

OTHER_UNCLASSIFIED_SPEC = SystemScenarioSpec(
    scenario_id="other_unclassified",
    name="Unclassified low-confidence alert",
    event_type="other",
    title="Unclassified security signal — insufficient context",
    description="Ambiguous telemetry without a clear event type classification",
    hostname="WKS-GEN-099",
    account="general-user-099",
    disposition_policy=DispositionPolicy.NOT_REQUIRED,
    expected_verdict=FinalVerdict.NONE,
    expected_severity=Severity.LOW,
    risk_score=25,
    risk_min=0,
    risk_max=45,
    allowed_actions=("create_ticket", "notify_security_team"),
    incident_id="770099",
    alert_id="990099",
    asset_id="990099",
    log_id="880099",
    keyword="unclassified",
)

SYSTEM_SCENARIO_SPECS: dict[str, SystemScenarioSpec] = {
    spec.scenario_id: spec
    for spec in (
        HOST_COMPROMISE_SPEC,
        MALICIOUS_PROCESS_SPEC,
        INSIDER_PRIVILEGE_ABUSE_SPEC,
        LATERAL_MOVEMENT_SPEC,
        OTHER_UNCLASSIFIED_SPEC,
    )
}


def build_system_scenario(
    spec: SystemScenarioSpec,
    *,
    seed: int = 42,
    variant: ScenarioVariant | str = ScenarioVariant.NORMAL,
    instance: int = 0,
) -> MockXDRScenario:
    selected_variant = normalize_variant(variant)
    if instance:
        suffix = f"-{instance}"
        spec = SystemScenarioSpec(
            scenario_id=spec.scenario_id,
            name=spec.name,
            event_type=spec.event_type,
            title=spec.title,
            description=spec.description,
            hostname=spec.hostname,
            account=spec.account,
            disposition_policy=spec.disposition_policy,
            expected_verdict=spec.expected_verdict,
            expected_severity=spec.expected_severity,
            risk_score=spec.risk_score,
            risk_min=spec.risk_min,
            risk_max=spec.risk_max,
            allowed_actions=spec.allowed_actions,
            incident_id=f"{spec.incident_id}{suffix}",
            alert_id=(
                f"{spec.alert_id}{suffix}"
                if len(spec.alert_id) < 32
                else f"{spec.alert_id[:28]}{suffix}"
            ),
            asset_id=f"{spec.asset_id}{suffix}",
            log_id=f"{spec.log_id}{suffix}",
            keyword=spec.keyword,
        )
    base = DEFAULT_BASE_TIME
    tenant = DEFAULT_TENANT
    # Per-instance connector IDs so parallel / repeated polls do not share one watermark.
    connector_suffix = f"-{instance}" if instance else ""
    conn_log = log_only_connector(connector_id=f"conn-log-{spec.scenario_id}{connector_suffix}")
    conn_disp = disposition_connector(
        connector_id=f"conn-disp-{spec.scenario_id}{connector_suffix}"
    )
    if spec.disposition_policy is DispositionPolicy.NOT_REQUIRED:
        conn_disp = conn_disp.model_copy(
            update={"disposition_policy_default": DispositionPolicy.NOT_REQUIRED}
        )
    conn_gap = capability_gap_connector(
        connector_id=f"conn-gap-{spec.scenario_id}{connector_suffix}"
    )

    asset_ref = make_ref(
        SourceObjectKind.ASSET,
        spec.asset_id,
        connector_id=conn_disp.connector_id,
        status_raw="managed",
        updated_at=base,
        object_type="endpoint",
    )
    assets = [
        SourceAsset(
            reference=asset_ref,
            numeric_asset_id=spec.asset_id[:8],
            hostname=spec.hostname,
            ip="10.60.1.10",
            owner=spec.account,
            agent_status="online",
            asset_group="system",
        )
    ]
    if selected_variant is ScenarioVariant.AGENT_NOT_INSTALLED:
        no_agent_ref = make_ref(
            SourceObjectKind.ASSET,
            f"{spec.asset_id}-na",
            connector_id=conn_disp.connector_id,
            status_raw="unmanaged",
            updated_at=base,
        )
        assets.append(
            SourceAsset(
                reference=no_agent_ref,
                numeric_asset_id="9999",
                hostname=f"{spec.hostname}-legacy",
                agent_status="not_installed",
            )
        )
    if selected_variant is ScenarioVariant.DEVICE_OFFLINE:
        offline_ref = make_ref(
            SourceObjectKind.ASSET,
            f"{spec.asset_id}-off",
            connector_id=conn_disp.connector_id,
            status_raw="offline",
            updated_at=base,
        )
        assets.append(
            SourceAsset(
                reference=offline_ref,
                numeric_asset_id="9998",
                hostname=f"{spec.hostname}-dr",
                agent_status="offline",
            )
        )

    proc = _scenario_process_name(spec.scenario_id)

    log_ref = make_ref(
        SourceObjectKind.LOG,
        spec.log_id,
        connector_id=conn_log.connector_id,
        parent=spec.alert_id,
        status_raw="indexed",
        updated_at=base,
    )
    logs = [
        SourceLog(
            reference=log_ref,
            device_source="edr",
            category="process",
            logged_at=base,
            src_ip="10.60.1.10",
            normalized={
                "hostname": spec.hostname,
                "account": spec.account,
                "process": proc,
                "channel": "endpoint",
            },
            raw_payload={"hostname": spec.hostname, "account": spec.account},
        )
    ]

    incident_ref = make_ref(
        SourceObjectKind.INCIDENT,
        spec.incident_id,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
    )
    alert_ref = make_ref(
        SourceObjectKind.ALERT,
        spec.alert_id,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
    )
    alert = SourceAlert(
        reference=alert_ref,
        incident_ref=incident_ref,
        source_ip="10.60.1.10",
        related_log_refs=[log_ref],
        normalized={
            "event_type": spec.event_type,
            "alert_type": spec.event_type,
            "severity": spec.expected_severity.value,
            "keyword": spec.keyword,
        },
    )
    incident = SourceIncident(
        reference=incident_ref,
        title=spec.title,
        level=spec.expected_severity.value,
        gpt_verdict_label=spec.event_type,
        related_alert_refs=[alert_ref],
        impacted_asset_refs=[asset_ref],
        normalized={
            "event_type": spec.event_type,
            "risk_score": spec.risk_score,
            "description": spec.description,
            "scenario": spec.scenario_id,
        },
    )

    timeline = telemetry_for_variant(
        _build_timeline(spec=spec, base=base, seed=seed),
        variant=selected_variant,
    )

    return MockXDRScenario(
        scenario_id=spec.scenario_id,
        name=f"{spec.name} [{selected_variant.value}]",
        variant=selected_variant,
        base_time=base,
        source_tenant_id=tenant,
        incidents=[incident],
        alerts=[alert],
        assets=assets,
        logs=logs,
        connectors=[
            conn_log,
            conn_disp,
            *([conn_gap] if selected_variant is ScenarioVariant.CAPABILITY_GAP else []),
        ],
        telemetry_timeline=timeline,
        failure_profile=failure_profile_for_variant(seed=seed, variant=selected_variant),
        expected_outcome={
            "expected_verdict": spec.expected_verdict.value,
            "expected_severity": spec.expected_severity.value,
            "risk_score": spec.risk_score,
            "risk_min": spec.risk_min,
            "risk_max": spec.risk_max,
            "event_type": spec.event_type,
            "disposition_policy": spec.disposition_policy.value,
            "allowed_actions": list(spec.allowed_actions),
            "rule_fallback": True,
            "active_variant": selected_variant.value,
            "variants": list(SCENARIO_VARIANTS),
            "provider_error_codes": (
                ["capacity_limit_exceeded"]
                if selected_variant is ScenarioVariant.CAPACITY_LIMIT_EXCEEDED
                else []
            ),
        },
    )


def _scenario_process_name(scenario_id: str) -> str:
    if scenario_id == "host_compromise":
        return "beacon.exe"
    if scenario_id == "malicious_process":
        return "ransomware_stage.exe"
    if scenario_id == "lateral_movement":
        return "mstsc.exe"
    return "suspicious.bin"


def _build_timeline(*, spec: SystemScenarioSpec, base: datetime, seed: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    proc = _scenario_process_name(spec.scenario_id)

    for i in range(10):
        rows.append(
            event(
                channel="identity",
                record_id=f"id-{spec.scenario_id}-{seed}-{i:04d}",
                offset_s=i * 30,
                base_time=base,
                account=spec.account,
                event_type="login" if i % 2 == 0 else "auth",
                src_ip="10.60.1.10",
                result="success" if i < 8 else "failure",
                is_key_event=True,
            )
        )

    for i in range(12):
        rows.append(
            event(
                channel="endpoint",
                record_id=f"ep-{spec.scenario_id}-{seed}-{i:04d}",
                offset_s=60 + i * 20,
                base_time=base,
                hostname=spec.hostname,
                process=proc,
                account=spec.account,
                action="process_create" if i % 2 == 0 else "network_connect",
                dst_ip=DOC_IP if spec.scenario_id != "other_unclassified" else "10.60.2.20",
                is_key_event=True,
            )
        )

    rows.extend(
        [
            event(
                channel="network",
                record_id=f"net-{spec.scenario_id}-{seed}-0001",
                offset_s=120,
                base_time=base,
                src_ip="10.60.1.10",
                dst_ip=DOC_IP,
                dst_port=443,
                bytes_out=120_000 if spec.scenario_id != "other_unclassified" else 2_000,
                hostname=spec.hostname,
                domain=DOC_DOMAIN,
                is_key_event=True,
            ),
            event(
                channel="dns",
                record_id=f"dns-{spec.scenario_id}-{seed}-0002",
                offset_s=130,
                base_time=base,
                query=DOC_DOMAIN,
                qtype="A",
                rcode="NOERROR",
                hostname=spec.hostname,
                is_key_event=True,
            ),
            event(
                channel="dlp",
                record_id=f"dlp-{spec.scenario_id}-{seed}-0003",
                offset_s=140,
                base_time=base,
                file_name="sensitive.dat",
                action="read",
                bytes=4096,
                account=spec.account,
                hostname=spec.hostname,
                is_key_event=True,
            ),
            event(
                channel="asset",
                record_id=f"asset-{spec.scenario_id}-{seed}-0004",
                offset_s=0,
                base_time=base,
                numeric_asset_id=spec.asset_id[:8],
                hostname=spec.hostname,
                agent_status="online",
                is_key_event=True,
            ),
            event(
                channel="threat_intel",
                record_id=f"ti-{spec.scenario_id}-{seed}-0005",
                offset_s=150,
                base_time=base,
                indicator=DOC_IP,
                indicator_type="ip",
                confidence=0.82 if spec.scenario_id != "other_unclassified" else 0.35,
                tags=[spec.keyword],
                risk_score=spec.risk_score,
                is_key_event=True,
            ),
            event(
                channel="identity",
                record_id=f"id-provider-{spec.scenario_id}-{seed}-0099",
                offset_s=900,
                base_time=base,
                account="system",
                event_type="provider_error",
                result="capacity_limit_exceeded",
                provider_error_code="capacity_limit_exceeded",
                variant="capacity_limit_exceeded",
                is_key_event=True,
            ),
        ]
    )
    return rows


def build_host_compromise(
    *, seed: int = 42, variant: ScenarioVariant | str = ScenarioVariant.NORMAL, instance: int = 0
) -> MockXDRScenario:
    return build_system_scenario(
        HOST_COMPROMISE_SPEC, seed=seed, variant=variant, instance=instance
    )


def build_malicious_process(
    *, seed: int = 42, variant: ScenarioVariant | str = ScenarioVariant.NORMAL, instance: int = 0
) -> MockXDRScenario:
    return build_system_scenario(
        MALICIOUS_PROCESS_SPEC, seed=seed, variant=variant, instance=instance
    )


def build_insider_privilege_abuse(
    *, seed: int = 42, variant: ScenarioVariant | str = ScenarioVariant.NORMAL, instance: int = 0
) -> MockXDRScenario:
    return build_system_scenario(
        INSIDER_PRIVILEGE_ABUSE_SPEC, seed=seed, variant=variant, instance=instance
    )


def build_lateral_movement(
    *, seed: int = 42, variant: ScenarioVariant | str = ScenarioVariant.NORMAL, instance: int = 0
) -> MockXDRScenario:
    return build_system_scenario(
        LATERAL_MOVEMENT_SPEC, seed=seed, variant=variant, instance=instance
    )


def build_other_unclassified(
    *, seed: int = 42, variant: ScenarioVariant | str = ScenarioVariant.NORMAL, instance: int = 0
) -> MockXDRScenario:
    return build_system_scenario(
        OTHER_UNCLASSIFIED_SPEC, seed=seed, variant=variant, instance=instance
    )


__all__ = [
    "INSIDER_PRIVILEGE_ABUSE_SPEC",
    "LATERAL_MOVEMENT_SPEC",
    "HOST_COMPROMISE_SPEC",
    "MALICIOUS_PROCESS_SPEC",
    "OTHER_UNCLASSIFIED_SPEC",
    "SYSTEM_SCENARIO_SPECS",
    "build_host_compromise",
    "build_insider_privilege_abuse",
    "build_lateral_movement",
    "build_malicious_process",
    "build_other_unclassified",
    "build_system_scenario",
]
