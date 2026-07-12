"""CLI: export Mock telemetry files and/or seed a MockXDRState (ISSUE-010/011)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.data_generators import default_generators, write_telemetry_files  # noqa: E402
from app.data_generators.scenarios import (  # noqa: E402
    SCENARIO_BUILDERS,
    SCENARIO_REGISTRY,
    build_scenario,
    write_scenario_artifacts,
)
from app.mock_xdr.models import MockFailureProfile, MockXDRScenario  # noqa: E402
from app.mock_xdr.state import MockXDRState  # noqa: E402
from app.models.enums import (  # noqa: E402
    CapabilityState,
    ConnectorCapability,
    ConnectorStatus,
    DispositionPolicy,
    SourceDisposition,
    SourceObjectKind,
)
from app.models.source import (  # noqa: E402
    SourceAlert,
    SourceAsset,
    SourceConnector,
    SourceIncident,
    SourceLog,
    SourceReference,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("generate_mock_data")


def _minimal_scenario(*, seed: int, tenant: str = "tenant-demo") -> MockXDRScenario:
    """Tiny self-consistent seed used when no scenario pack is provided."""
    base = datetime(2024, 6, 1, 8, 0, 0, tzinfo=UTC)
    connector = SourceConnector(
        connector_id="conn-mock-1",
        source_product="mock_xdr",
        display_name="Mock Disposition Connector",
        status=ConnectorStatus.ONLINE,
        capabilities={
            ConnectorCapability.QUERY: CapabilityState.SUPPORTED,
            ConnectorCapability.EVENT_DISPOSITION: CapabilityState.SUPPORTED,
        },
        disposition_policy_default=DispositionPolicy.REQUIRED,
        schema_version="1",
    )
    asset_ref = SourceReference(
        source_kind=SourceObjectKind.ASSET,
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id=connector.connector_id,
        source_object_id="42",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
    )
    asset = SourceAsset(reference=asset_ref, numeric_asset_id="42", hostname="host-001")
    alert_ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id=connector.connector_id,
        source_object_id="ALERT-1",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
    )
    log_ref = SourceReference(
        source_kind=SourceObjectKind.LOG,
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id=connector.connector_id,
        source_object_id="LOG-1",
        parent_source_object_id="ALERT-1",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
    )
    log = SourceLog(reference=log_ref, device_source="mock", category="auth")
    alert = SourceAlert(
        reference=alert_ref,
        related_log_refs=[log_ref],
    )
    incident_ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id=connector.connector_id,
        source_object_id="INC-1",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
    )
    incident = SourceIncident(
        reference=incident_ref,
        title="demo incident",
        related_alert_refs=[alert_ref],
        impacted_asset_refs=[asset_ref],
    )
    alert = alert.model_copy(update={"incident_ref": incident_ref})
    return MockXDRScenario(
        scenario_id="minimal_framework",
        name="ISSUE-010 minimal framework scenario",
        base_time=base,
        source_tenant_id=tenant,
        incidents=[incident],
        alerts=[alert],
        assets=[asset],
        logs=[log],
        connectors=[connector],
        failure_profile=MockFailureProfile(seed=seed, control_plane_enabled=True),
        expected_outcome={"disposition_policy": "required"},
    )


def _log_state(scenario: MockXDRScenario) -> None:
    state = MockXDRState()
    state.load_scenario(scenario)
    counts = {
        "incident": sum(
            1 for (k, _), o in state.objects.items() if k == "incident" and not o.deleted
        ),
        "alert": sum(1 for (k, _), o in state.objects.items() if k == "alert" and not o.deleted),
        "asset": sum(1 for (k, _), o in state.objects.items() if k == "asset" and not o.deleted),
        "log": sum(1 for (k, _), o in state.objects.items() if k == "log" and not o.deleted),
        "connector": len(state.connectors),
    }
    external_ids = [oid for (_, oid), o in state.objects.items() if not o.deleted]
    logger.info(
        "MockXDRState seeded scenario_id=%s objects=%s external_ids=%s "
        "schema_version=%s seed=%s",
        scenario.scenario_id,
        json.dumps(counts),
        external_ids,
        state.failure_profile.schema_version_override or "1",
        scenario.failure_profile.seed,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Mock telemetry / seed MockXDR")
    parser.add_argument("--out", type=Path, default=Path("data/mock"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        choices=sorted(SCENARIO_BUILDERS),
        help="ISSUE-011 demo scenario pack id (writes 7 telemetry files from the pack).",
    )
    parser.add_argument(
        "--seed-server-state",
        action="store_true",
        help="Also build an in-memory MockXDRState and print object counts (no credentials).",
    )
    parser.add_argument(
        "--dump-scenario",
        type=Path,
        default=None,
        help="Optional path to write the scenario JSON.",
    )
    args = parser.parse_args(argv)

    if args.scenario is not None:
        scenario = build_scenario(args.scenario, seed=args.seed)
        written = write_scenario_artifacts(
            scenario,
            args.out,
            write_scenario_json=False,
        )
        logger.info(
            "wrote %s telemetry files scenario=%s seed=%s",
            len(written),
            scenario.scenario_id,
            args.seed,
        )
        for path in written:
            logger.info("  %s", path)
    else:
        gens = default_generators(seed=args.seed)
        written = write_telemetry_files(gens, args.out, count=args.count)
        logger.info(
            "wrote %s telemetry files seed=%s count=%s schema_version=1",
            len(written),
            args.seed,
            args.count,
        )
        for path in written:
            logger.info("  %s", path)
        scenario = _minimal_scenario(seed=args.seed)

    if args.dump_scenario is not None:
        args.dump_scenario.parent.mkdir(parents=True, exist_ok=True)
        args.dump_scenario.write_text(
            scenario.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        logger.info("scenario dumped to %s", args.dump_scenario)

    if args.seed_server_state:
        _log_state(scenario)

    return 0


if __name__ == "__main__":
    # Re-export registry for discovery / smoke checks.
    _ = SCENARIO_REGISTRY
    raise SystemExit(main())
