"""Make source_connector.disposition_policy_default nullable.

Revision ID: 0002_connector_policy_nullable
Revises: 0001_initial_schema
Create Date: 2026-07-13 11:30:00.000000+00:00

Live connectors must carry an *explicit* disposition_policy_default. A non-null
ORM/SQL default of ``not_required`` made "unset" indistinguishable from an
intentional not_required, so live ingest could silently skip writeback policy.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_connector_policy_nullable"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "source_connector",
        "disposition_policy_default",
        existing_type=sa.String(),
        nullable=True,
    )


def downgrade() -> None:
    op.execute(
        "UPDATE source_connector "
        "SET disposition_policy_default = 'not_required' "
        "WHERE disposition_policy_default IS NULL"
    )
    op.alter_column(
        "source_connector",
        "disposition_policy_default",
        existing_type=sa.String(),
        nullable=False,
    )
