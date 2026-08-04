"""add retention_expires_at to shadow_query_artifact (ISSUE-135 / #641)

Revision ID: 0023_shadow_artifact_retention
Revises: 0022_shadow_run
Create Date: 2026-08-03 14:00:00.000000+00:00

NOTE: ``0022_shadow_run`` was later amended to create ``retention_expires_at``
on ``shadow_query_artifact`` at table-create time. Fresh installs therefore
already have the column before this revision runs; upgrade must be
idempotent (ISSUE-167 / #686 CI DuplicateColumnError short-circuit).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_shadow_artifact_retention"
down_revision: str | None = "0022_shadow_run"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column_name in {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    if not _has_column("shadow_query_artifact", "retention_expires_at"):
        op.add_column(
            "shadow_query_artifact",
            sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
        )
    op.execute(
        sa.text(
            "UPDATE shadow_query_artifact SET retention_expires_at = created_at + interval '30 days' "
            "WHERE retention_expires_at IS NULL"
        )
    )
    op.alter_column("shadow_query_artifact", "retention_expires_at", nullable=False)


def downgrade() -> None:
    # Do not drop: current ``0022_shadow_run`` owns the column on create_table.
    # Environments that only gained the column via this revision keep it
    # (harmless additive) so downgrade stays compatible with amended 0022.
    pass
