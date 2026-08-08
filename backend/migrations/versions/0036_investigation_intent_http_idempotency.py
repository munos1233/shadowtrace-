"""HTTP investigation intent idempotency fields (ISSUE-276 / #872).

Adds durable idempotency metadata for ``http_investigate`` intents so POST
/events/{id}/investigate can commit a ledger row before returning 202.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036_investigation_intent_http_idempotency"
down_revision = "0035_llm_call_log_error_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_intent",
        sa.Column("idempotency_key", sa.String(), nullable=True),
    )
    op.add_column(
        "investigation_intent",
        sa.Column("payload_hash", sa.String(), nullable=True),
    )
    op.add_column(
        "investigation_intent",
        sa.Column("orchestration_mode", sa.String(), nullable=True),
    )
    op.create_index(
        "uq_investigation_intent_idempotency_key",
        "investigation_intent",
        ["idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_investigation_intent_idempotency_key",
        table_name="investigation_intent",
    )
    op.drop_column("investigation_intent", "orchestration_mode")
    op.drop_column("investigation_intent", "payload_hash")
    op.drop_column("investigation_intent", "idempotency_key")
