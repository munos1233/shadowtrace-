"""Pydantic domain models for SOAR playbook knowledge base (ISSUE-044)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ActionLevel, EventType, Severity


class PlaybookStep(BaseModel):
    """A single step within a playbook, referencing a tool and its action level."""

    model_config = ConfigDict(extra="forbid")

    step_order: int = Field(..., ge=1, description="1-based ordinal position in the playbook")
    action_name: str = Field(..., description="Human-readable action label")
    tool_name: str = Field(..., description="Must match a ToolMeta.tool_name in CapabilityManifest")
    action_level: ActionLevel = Field(..., description="Must agree with ToolMeta.action_level")
    precondition: str = Field(default="", description="What must be true before this step")
    expected_outcome: str = Field(default="", description="What this step should achieve")
    required_capabilities: list[str] = Field(
        default_factory=list, description="e.g. ['entity_response']"
    )


class Playbook(BaseModel):
    """A SOAR playbook: ordered response steps gated by event_type and min_severity."""

    model_config = ConfigDict(extra="forbid")

    playbook_id: str = Field(..., pattern=r"^pb-[0-9a-fA-F]{8}$", description="pb-{8 hex digits}")
    playbook_name: str = Field(..., description="Human-readable playbook name")
    event_type: EventType
    min_severity: Severity = Field(..., description="Minimum severity this playbook applies to")
    description: str = Field(default="", description="What the playbook addresses")
    steps: list[PlaybookStep] = Field(..., min_length=1, description="Ordered response steps")
