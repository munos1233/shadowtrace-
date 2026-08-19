"""Seed the standalone Mock XDR service and ingest via SourceAdapter (ISSUE-088).

Used by ``scripts/bootstrap.sh`` so demo events exist in **both** PostgreSQL and
the mock-xdr container (read + disposition writeback stay consistent).

Usage (inside backend container)::

    python3 scripts/seed_mock_xdr_and_ingest.py \\
        --scenario insider_data_exfiltration \\
        --mock-xdr-url http://mock-xdr:8100 \\
        --seed 42
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

import httpx

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from sqlalchemy import or_, select

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import (
    SCENARIO_BUILDERS,
    build_scenario,
)
from app.db.session import dispose_session_provider, get_session_factory
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import SourceObjectKind
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService
from app.tools.mock_state import (
    MOCK_OBSERVATION_IDEMPOTENCY_KEY,
    MOCK_OBSERVATION_PROJECTION_KEY,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("seed_mock_xdr_and_ingest")

_ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]

from app.mock_xdr.state import MOCK_XDR_DEFAULT_READ_TOKEN, MOCK_XDR_DEFAULT_WRITE_TOKEN

DIRTY_FIXTURE_HINT = "dirty fixture, run down-v or --fresh-volumes"
_OBSERVATION_STAGE = "behavior_observation_projection"


async def _seed_mock_xdr(
    *, mock_xdr_url: str, scenario_id: str, seed: int, instance: int = 0
) -> dict:
    scenario = build_scenario(scenario_id, seed=seed, instance=instance)
    seed_url = f"{mock_xdr_url.rstrip('/')}/mock-xdr/v1/control/seed"
    payload = scenario.model_dump(mode="json")
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(seed_url, json=payload)
        response.raise_for_status()
        return response.json()


async def _snapshot_event_ids() -> set[str]:
    factory = get_session_factory()
    async with factory() as session:
        rows = await session.scalars(select(orm.SecurityEvent.event_id))
        return {str(event_id) for event_id in rows.all()}


def scenario_source_identities(
    scenario_id: str,
    *,
    seed: int,
    instance: int,
) -> tuple[list[str], list[str]]:
    scenario = build_scenario(scenario_id, seed=seed, instance=instance)
    connector_ids = [str(connector.connector_id) for connector in scenario.connectors]
    object_ids = [
        *(str(item.reference.source_object_id) for item in scenario.incidents),
        *(str(item.reference.source_object_id) for item in scenario.alerts),
        *(str(item.reference.source_object_id) for item in scenario.assets),
        *(str(item.reference.source_object_id) for item in scenario.logs),
    ]
    return connector_ids, object_ids


def format_dirty_fixture_error(hits: list[str]) -> str:
    detail = "; ".join(hits) if hits else "prior scenario residue"
    return f"{DIRTY_FIXTURE_HINT}: {detail}"


def gold_fixture_should_fail(output: dict) -> tuple[bool, str]:
    """Fail-closed on rejected ingest; observation-only degraded must not block accepted seed."""
    rejected = int(output.get("rejected") or 0)
    accepted = int(output.get("accepted") or 0)
    errors = output.get("errors") if isinstance(output.get("errors"), list) else []
    other_errors = [
        item
        for item in errors
        if isinstance(item, dict) and item.get("stage") != _OBSERVATION_STAGE
    ]
    observation_errors = [
        item
        for item in errors
        if isinstance(item, dict) and item.get("stage") == _OBSERVATION_STAGE
    ]
    observation_degraded = bool(output.get("observation_degraded") or observation_errors)
    if rejected > 0:
        return True, "ingestion rejected rows present"
    if other_errors:
        return True, "ingestion degraded with non-observation errors"
    if output.get("degraded") and not observation_degraded:
        return True, "ingestion degraded"
    if accepted < 1:
        return True, f"no events accepted for scenario={output.get('scenario_id') or ''}"
    return False, ""


async def detect_dirty_fixture(
    *,
    connector_ids: list[str],
    source_object_ids: list[str],
) -> list[str]:
    hits: list[str] = []
    if not connector_ids and not source_object_ids:
        return hits
    factory = get_session_factory()
    async with factory() as session:
        if connector_ids:
            checkpoint_count = await session.scalar(
                select(orm.SourceCheckpoint.connector_id)
                .where(
                    orm.SourceCheckpoint.connector_id.in_(connector_ids),
                    or_(
                        orm.SourceCheckpoint.watermark.is_not(None),
                        orm.SourceCheckpoint.cursor.is_not(None),
                    ),
                )
                .limit(1)
            )
            if checkpoint_count is not None:
                hits.append("source_checkpoint watermark/cursor present")
            connector_watermark = await session.scalar(
                select(orm.SourceConnector.connector_id)
                .where(
                    orm.SourceConnector.connector_id.in_(connector_ids),
                    orm.SourceConnector.watermark.is_not(None),
                )
                .limit(1)
            )
            if connector_watermark is not None:
                hits.append("source_connector watermark present")
        if source_object_ids:
            source_hit = await session.scalar(
                select(orm.SourceObject.source_object_id)
                .where(orm.SourceObject.source_object_id.in_(source_object_ids))
                .limit(1)
            )
            if source_hit is not None:
                hits.append(f"source_object already exists id={source_hit}")
                linked_events = (
                    await session.scalars(
                        select(orm.SourceEventLink.event_id)
                        .join(
                            orm.SourceObject,
                            orm.SourceObject.source_record_id
                            == orm.SourceEventLink.source_record_id,
                        )
                        .where(orm.SourceObject.source_object_id.in_(source_object_ids))
                    )
                ).all()
                event_ids = [str(item) for item in linked_events]
                if event_ids:
                    task_hit = await session.scalar(
                        select(orm.AgentTaskORM.idempotency_key)
                        .where(
                            orm.AgentTaskORM.event_id.in_(event_ids),
                            orm.AgentTaskORM.idempotency_key.like("response-plan:%"),
                        )
                        .limit(1)
                    )
                    if task_hit is not None:
                        hits.append(f"agent_task residue key={task_hit}")
    return hits


async def _flush_mock_observation_keys() -> None:
    redis = RedisClient()
    try:
        client = redis.get_client()
        await client.delete(
            MOCK_OBSERVATION_PROJECTION_KEY,
            MOCK_OBSERVATION_IDEMPOTENCY_KEY,
        )
        logger.info(
            "flushed mock observation keys %s %s",
            MOCK_OBSERVATION_PROJECTION_KEY,
            MOCK_OBSERVATION_IDEMPOTENCY_KEY,
        )
    finally:
        await redis.aclose()


async def _poll_ingest(*, mock_xdr_url: str) -> dict:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = DegradedFlagService(store, factory)
        events = EventService(factory, store, degraded_flags=degraded)
        ingester = SourceIngester(events, factory, source_mode="mock_xdr")
        adapter = MockXDRSourceAdapter(
            base_url=mock_xdr_url.rstrip("/"),
            read_token=MOCK_XDR_DEFAULT_READ_TOKEN,
            write_token=MOCK_XDR_DEFAULT_WRITE_TOKEN,
            max_retries=0,
        )
        summary = await ingester.poll(adapter, _ALL_SOURCE_KINDS, batch_size=50)
        return summary.model_dump(mode="json")
    finally:
        await redis.aclose()
        await dispose_session_provider()


async def _run(
    *,
    scenario_id: str,
    mock_xdr_url: str,
    seed: int,
    seed_only: bool,
    instance: int = 0,
) -> int:
    if scenario_id not in SCENARIO_BUILDERS:
        raise SystemExit(f"unknown scenario: {scenario_id!r}")

    await _flush_mock_observation_keys()

    if not seed_only:
        connector_ids, object_ids = scenario_source_identities(
            scenario_id, seed=seed, instance=instance
        )
        dirty_hits = await detect_dirty_fixture(
            connector_ids=connector_ids,
            source_object_ids=object_ids,
        )
        if dirty_hits:
            message = format_dirty_fixture_error(dirty_hits)
            logger.error(message)
            print(json.dumps({"error": message, "dirty": dirty_hits}, ensure_ascii=False))
            return 1

    seed_result = await _seed_mock_xdr(
        mock_xdr_url=mock_xdr_url,
        scenario_id=scenario_id,
        seed=seed,
        instance=instance,
    )
    logger.info(
        "mock-xdr seeded scenario=%s counts=%s",
        seed_result.get("scenario_id"),
        seed_result.get("object_counts"),
    )

    if seed_only:
        print(json.dumps(seed_result, ensure_ascii=False, indent=2))
        return 0

    before_event_ids = await _snapshot_event_ids()
    ingest_summary = await _poll_ingest(mock_xdr_url=mock_xdr_url)
    after_event_ids = await _snapshot_event_ids()
    new_event_ids = sorted(after_event_ids - before_event_ids)
    output = dict(ingest_summary)
    output["event_ids"] = new_event_ids
    output["observation_degraded"] = bool(ingest_summary.get("observation_degraded"))
    print(json.dumps(output, ensure_ascii=False, indent=2))
    should_fail, reason = gold_fixture_should_fail(output)
    if output.get("observation_degraded"):
        logger.warning(
            "behavior observation projection degraded; continuing because accepted>=%s",
            output.get("accepted"),
        )
    if should_fail:
        logger.error("%s for scenario=%s", reason, scenario_id)
        return 1
    if not new_event_ids:
        logger.error(
            "ingest accepted rows but produced no new event_ids for scenario=%s",
            scenario_id,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seed mock-xdr control plane and ingest via SourceAdapter poll"
    )
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIO_BUILDERS))
    parser.add_argument(
        "--mock-xdr-url",
        default="http://mock-xdr:8100",
        help="Mock XDR base URL (default: docker service)",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--instance",
        type=int,
        default=0,
        help="Scenario instance suffix for distinct source object IDs (ISSUE-313 pressure gate).",
    )
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="Only seed mock-xdr control plane; skip SourceAdapter poll (ISSUE-107 scheduler smoke)",
    )
    args = parser.parse_args(argv)
    return asyncio.run(
        _run(
            scenario_id=args.scenario,
            mock_xdr_url=args.mock_xdr_url,
            seed=args.seed,
            seed_only=args.seed_only,
            instance=int(args.instance),
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
