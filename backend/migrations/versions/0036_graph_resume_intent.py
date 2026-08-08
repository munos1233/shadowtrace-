"""graph_resume_intent table (ISSUE-277 / #873)

Revision ID: 0036_graph_resume_intent
Revises: 0035_llm_call_log_error_fields
Create Date: 2026-08-08 07:10:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036_graph_resume_intent"
down_revision: str | None = "0035_llm_call_log_error_fields"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "graph_resume_intent",
        sa.Column("intent_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("operation_id", sa.String(), nullable=False),
        sa.Column("resolution_kind", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("hold_generation", sa.Integer(), nullable=False),
        sa.Column("checkpoint_version", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claim_owner", sa.String(), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("broker_task_id", sa.String(), nullable=True),
        sa.Column("skip_reason", sa.String(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_event.event_id"],
            name="fk_graph_resume_intent_event_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("intent_id"),
        sa.UniqueConstraint("operation_id", name="uq_graph_resume_intent_operation_id"),
    )
    op.create_index(
        "ix_graph_resume_intent_status_updated",
        "graph_resume_intent",
        ["status", "updated_at"],
    )
    op.create_index(
        "ix_graph_resume_intent_claim_expires",
        "graph_resume_intent",
        ["claim_expires_at"],
    )
    op.create_index("ix_graph_resume_intent_event_id", "graph_resume_intent", ["event_id"])
    op.create_index("ix_graph_resume_intent_status", "graph_resume_intent", ["status"])


def downgrade() -> None:
    op.drop_index("ix_graph_resume_intent_status", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_event_id", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_claim_expires", table_name="graph_resume_intent")
    op.drop_index("ix_graph_resume_intent_status_updated", table_name="graph_resume_intent")
    op.drop_table("graph_resume_intent")
