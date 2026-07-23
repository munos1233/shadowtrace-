"""ORM models for knowledge / RAG tables (ISSUE-041)."""

from app.db.orm.approval import ApprovalRecordORM
from app.db.orm.knowledge import KnowledgeChunkORM

__all__ = ["ApprovalRecordORM", "KnowledgeChunkORM"]
