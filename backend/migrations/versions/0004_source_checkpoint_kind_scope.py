"""Isolate source checkpoints by connector and object kind.

Revision ID: 0004_source_checkpoint_kind
Revises: 0003_outbox_active_head_evt
Create Date: 2026-07-15 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_source_checkpoint_kind"
down_revision: str | None = "0003_outbox_active_head_evt"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_object",
        sa.Column("current_source_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "source_object",
        sa.Column(
            "current_state_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
    )
    op.execute(
        "UPDATE source_object "
        "SET current_source_updated_at = source_updated_at "
        "WHERE current_source_updated_at IS NULL"
    )

    op.create_table(
        "source_checkpoint",
        sa.Column("connector_id", sa.String(), nullable=False),
        sa.Column("object_kind", sa.String(), nullable=False),
        sa.Column(
            "stream_scope",
            sa.String(),
            server_default=sa.text("''"),
            nullable=False,
        ),
        sa.Column("schema_version", sa.String(), nullable=False),
        sa.Column("cursor", sa.String(), nullable=True),
        sa.Column("watermark", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "status",
            sa.String(),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column("degraded_reason", sa.String(), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "row_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"],
            ["source_connector.connector_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("connector_id", "object_kind", "stream_scope"),
    )
    # Do not translate source_connector.watermark into these rows. The legacy
    # value may represent several connectors and kinds behind one adapter, so
    # any backfill could skip data. New rows start empty and replay safely.


def downgrade() -> None:
    op.drop_table("source_checkpoint")
    op.drop_column("source_object", "current_state_version")
    op.drop_column("source_object", "current_source_updated_at")
