"""Load SOAR playbooks into the playbook_kb knowledge base (ISSUE-044).

Usage::

    cd backend && python -m scripts.load_playbook_kb

The script validates every step's tool_name and action_level against the
baseline ToolMeta catalog.  Invalid steps cause the script to exit with a
hard error before any data is written.  Repeated runs are idempotent.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.embedding.service import EmbeddingService  # noqa: E402
from app.services.knowledge_store import KnowledgeStore  # noqa: E402

from app.core.config import Settings  # noqa: E402
from app.services.playbook_kb_service import PlaybookKBService  # noqa: E402

REPO_ROOT = _BACKEND.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "playbooks.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


async def _main() -> None:
    if not DATA_FILE.exists():
        print(f"Data file not found: {DATA_FILE}")
        sys.exit(1)

    settings = Settings()
    engine = create_async_engine(DATABASE_URL)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    embed_service = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed_service)
    service = PlaybookKBService(store, session_factory)

    try:
        count = await service.load_from_file(DATA_FILE)
        print(f"Loaded {count} playbooks into playbook_kb")
    except ValueError as exc:
        print(f"Validation error: {exc}")
        sys.exit(1)
    finally:
        await embed_service.close()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
