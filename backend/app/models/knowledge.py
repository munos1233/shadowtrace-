"""Pydantic domain models for knowledge chunks and retrieval results (ISSUE-041)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class KnowledgeChunk(BaseModel):
    """A chunk of knowledge to be stored and embedded."""

    chunk_id: str = Field(..., description="chk-{8 hex}")
    kb_name: str = Field(..., description="attack_kb | fp_case_kb | history_case_kb | playbook_kb")
    content: str = Field(..., description="Plain-text chunk body")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")


class RetrievedChunk(BaseModel):
    """A chunk returned from vector or keyword search."""

    chunk_id: str
    kb_name: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    score: float = Field(..., description="Similarity (vector) or rank (keyword)")
    retrieval_method: str = Field(..., description="'vector' or 'keyword'")
