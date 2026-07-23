"""approval_record table for tiered approval engine (ISSUE-058)

Revision ID: 0007_approval_record
Revises: 0006_knowledge_chunk
Create Date: 2026-07-23 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_approval_record"
down_revision: str | None = "0006_knowledge_chunk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_record",
        sa.Column("approval_id", sa.String(), nullable=False),
        sa.Column("action_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("plan_revision", sa.Integer(), nullable=False),
        sa.Column("approval_cycle", sa.Integer(), server_default="0", nullable=False),
        sa.Column("decision_id", sa.String(), nullable=True),
        sa.Column("required_level", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("operator", sa.String(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeout_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["action_id"],
            ["action.action_id"],
            name=op.f("fk_approval_record_action_id_action"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_event.event_id"],
            name=op.f("fk_approval_record_event_id_security_event"),
        ),
        sa.PrimaryKeyConstraint("approval_id", name=op.f("pk_approval_record")),
        sa.UniqueConstraint(
            "action_id",
            "approval_cycle",
            name=op.f("uq_approval_record_action_cycle"),
        ),
        sa.UniqueConstraint("decision_id", name=op.f("uq_approval_record_decision_id")),
    )
    op.create_index(
        op.f("ix_approval_record_action_id"), "approval_record", ["action_id"], unique=False
    )
    op.create_index(
        op.f("ix_approval_record_event_id"), "approval_record", ["event_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_approval_record_event_id"), table_name="approval_record")
    op.drop_index(op.f("ix_approval_record_action_id"), table_name="approval_record")
    op.drop_table("approval_record")
