"""Stage + activate the demo/dev playbook release (ISSUE-245 / #820).

Usage::

    cd backend && python -m scripts.load_playbook_release

Reads ``data/knowledge/playbooks.json``, stages a PlaybookRelease, activates it,
and materializes release-pinned ``playbook_kb`` chunks. Repeated runs are
idempotent via release idempotency keys.

This is the path that makes ``/api/v1/health.playbook_resources.status=ready``.
The legacy ``load_playbook_kb`` chunk upsert does **not** create an active
release and must not be used as the demo readiness gate.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.config import Settings  # noqa: E402
from app.core.embedding.service import EmbeddingService  # noqa: E402
from app.models.knowledge_release import KnowledgeReleaseProvenance  # noqa: E402
from app.services.knowledge_store import KnowledgeStore  # noqa: E402
from app.services.playbook_kb_service import PlaybookKBService  # noqa: E402
from app.services.playbook_release_resolver import default_playbook_provenance  # noqa: E402
from app.services.playbook_release_service import PlaybookReleaseService  # noqa: E402

REPO_ROOT = _BACKEND.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "playbooks.json"
DEFAULT_RELEASE_VERSION = os.environ.get("PLAYBOOK_RELEASE_VERSION", "v1")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


async def load_and_activate_playbook_release(
    *,
    database_url: str = DATABASE_URL,
    data_file: Path = DATA_FILE,
    release_version: str = DEFAULT_RELEASE_VERSION,
) -> str:
    """Stage + activate playbooks.json; return the active release_id."""
    if not data_file.exists():
        raise FileNotFoundError(f"Data file not found: {data_file}")

    bundle = json.loads(data_file.read_text(encoding="utf-8"))
    settings = Settings()
    engine = create_async_engine(database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    embed_service = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed_service)
    playbook_kb = PlaybookKBService(store, session_factory)
    service = PlaybookReleaseService(
        session_factory,
        playbook_kb=playbook_kb,
        settings=settings,
    )

    try:
        provenance = KnowledgeReleaseProvenance.model_validate(
            default_playbook_provenance(str(data_file))
        )
        staged = await service.stage_playbook_bundle(
            bundle,
            release_version=release_version,
            provenance=provenance,
        )
        active = await service.activate_release(staged.release_id)
        verified = await service.get_active_release()
        if verified is None or verified.release_id != active.release_id:
            raise RuntimeError(
                "playbook release activation verification failed: "
                f"expected={active.release_id} actual="
                f"{verified.release_id if verified else None}"
            )
        return active.release_id
    finally:
        await embed_service.close()
        await engine.dispose()


async def _main() -> None:
    try:
        release_id = await load_and_activate_playbook_release()
    except Exception as exc:  # noqa: BLE001 — CLI must exit non-zero with message
        print(f"Playbook release load failed: {exc}")
        sys.exit(1)
    print(f"Playbook release {release_id} activated (source={DATA_FILE})")


if __name__ == "__main__":
    asyncio.run(_main())
