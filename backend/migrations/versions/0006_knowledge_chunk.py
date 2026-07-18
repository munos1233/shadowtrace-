"""knowledge_chunk table with pgvector cosine index and full-text search

Revision ID: 0006_knowledge_chunk
Revises: 0005_llm_call_audit_fields
Create Date: 2026-07-17 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision: str = "0006_knowledge_chunk"
down_revision: str | None = "0005_llm_call_audit_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_chunk",
        sa.Column("chunk_id", sa.String(), nullable=False),
        sa.Column("kb_name", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("embedding", Vector(1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("chunk_id", name=op.f("pk_knowledge_chunk")),
    )
    op.create_index(
        op.f("ix_knowledge_chunk_kb_name"), "knowledge_chunk", ["kb_name"], unique=False
    )
    # ivfflat cosine-similarity index.  lists=1 is fine for small datasets;
    # rebuild with lists >= max(rows/1000, 10) once per-KB chunk counts exceed ~1 000.
    op.execute(
        "CREATE INDEX ix_knowledge_chunk_embedding_ivfflat "
        "ON knowledge_chunk USING ivfflat (embedding vector_cosine_ops) WITH (lists = 1)"
    )
    # GIN full-text index for keyword_search via to_tsvector('simple', content).
    op.execute(
        "CREATE INDEX ix_knowledge_chunk_content_fts "
        "ON knowledge_chunk USING gin (to_tsvector('simple', content))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_chunk_content_fts")
    op.execute("DROP INDEX IF EXISTS ix_knowledge_chunk_embedding_ivfflat")
    op.drop_index(op.f("ix_knowledge_chunk_kb_name"), table_name="knowledge_chunk")
    op.drop_table("knowledge_chunk")
