"""CLI for explicit offline ingestion through the ISSUE-016 pipeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.redis_client import RedisClient  # noqa: E402
from app.db.session import get_engine, get_session_factory  # noqa: E402
from app.ingestion.file_ingester import FileIngester  # noqa: E402
from app.ingestion.source_ingester import SourceIngester  # noqa: E402
from app.services.context_service import EventContextStore  # noqa: E402
from app.services.degraded_flag_service import DegradedFlagService  # noqa: E402
from app.services.event_service import EventService  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("ingest_mock_data")


async def _run(path: Path, scenario: str | None, batch_size: int) -> int:
    factory = get_session_factory()
    redis = RedisClient()
    try:
        store = EventContextStore(redis, factory)
        degraded = DegradedFlagService(store, factory)
        events = EventService(
            factory,
            store,
            degraded_flags=degraded,
        )
        source_ingester = SourceIngester(
            events,
            factory,
            source_mode="file",
        )
        file_ingester = FileIngester(
            source_ingester,
            events,
            source_mode="file",
        )
        summary = await file_ingester.ingest(
            path,
            scenario=scenario,
            batch_size=batch_size,
        )
        print(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 1 if summary.degraded or summary.rejected else 0
    finally:
        await redis.aclose()
        await get_engine().dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest Mock scenario/telemetry through explicit file fallback"
    )
    parser.add_argument("--path", type=Path, default=Path("data/mock"))
    parser.add_argument("--scenario", type=str, default=None)
    parser.add_argument("--batch-size", type=int, default=10_000)
    args = parser.parse_args(argv)
    logger.info(
        "Explicit file ingestion path=%s scenario=%s",
        args.path,
        args.scenario or "<auto>",
    )
    return asyncio.run(_run(args.path, args.scenario, args.batch_size))


if __name__ == "__main__":
    raise SystemExit(main())
