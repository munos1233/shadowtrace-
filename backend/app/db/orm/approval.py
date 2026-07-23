"""ApprovalRecord ORM (ISSUE-058)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class ApprovalRecordORM(Base):
    __tablename__ = "approval_record"
    __table_args__ = (
        UniqueConstraint("action_id", "approval_cycle", name="uq_approval_record_action_cycle"),
        UniqueConstraint("decision_id", name="uq_approval_record_decision_id"),
    )

    approval_id: Mapped[str] = mapped_column(String, primary_key=True)
    action_id: Mapped[str] = mapped_column(
        String, ForeignKey("action.action_id"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    plan_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    approval_cycle: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    decision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    required_level: Mapped[str] = mapped_column(String, nullable=False)
    decision: Mapped[str] = mapped_column(String, nullable=False)
    operator: Mapped[str | None] = mapped_column(String, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    timeout_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
