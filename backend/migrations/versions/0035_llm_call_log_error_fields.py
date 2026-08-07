"""Add bounded failure class/detail to llm_call_log (ISSUE-240).

Revision ID: 0035_llm_call_log_error_fields
Revises: 0034_ae_job_idem_uq
Create Date: 2026-08-07 00:00:00.000000+00:00

Stores short, redacted failure taxonomy on durable audit rows so dynamic
evaluation can SQL-distinguish empty_content vs invalid_json without
persisting prompt text, API keys, or full completion bodies.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035_llm_call_log_error_fields"
down_revision = "0034_ae_job_idem_uq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_call_log",
        sa.Column("error_class", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "llm_call_log",
        sa.Column("error_detail", sa.String(length=256), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("llm_call_log", "error_detail")
    op.drop_column("llm_call_log", "error_class")
