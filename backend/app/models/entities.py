"""Entity models and EntitySet (intro §4.3.4).

Six entity classes share ``entity_id``, ``entity_type`` and ``source_refs``.
Network entities carry an ``attributes.scope`` of ``external``/``internal`` rather
than relying on a private-address heuristic to override source-of-truth facts.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.source import SourceReference


class _BaseEntity(BaseModel):
    """Common entity fields."""

    model_config = ConfigDict(extra="forbid")

    entity_id: str
    source_refs: list[SourceReference] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class AccountEntity(_BaseEntity):
    entity_type: Literal["account"] = "account"
    username: str | None = None
    domain: str | None = None
    display_name: str | None = None


class HostEntity(_BaseEntity):
    entity_type: Literal["host"] = "host"
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None


class IPEntity(_BaseEntity):
    entity_type: Literal["ip"] = "ip"
    address: str | None = None
    # scope also mirrored in attributes.scope; external/internal drives targeting.
    scope: Literal["external", "internal", "unknown"] = "unknown"


class DomainEntity(_BaseEntity):
    entity_type: Literal["domain"] = "domain"
    fqdn: str | None = None


class ProcessEntity(_BaseEntity):
    entity_type: Literal["process"] = "process"
    name: str | None = None
    pid: int | None = None
    command_line: str | None = None
    hash: str | None = None


class FileEntity(_BaseEntity):
    entity_type: Literal["file"] = "file"
    path: str | None = None
    name: str | None = None
    hash: str | None = None


class EntitySet(BaseModel):
    """Container of the six entity categories."""

    model_config = ConfigDict(extra="forbid")

    accounts: list[AccountEntity] = Field(default_factory=list)
    hosts: list[HostEntity] = Field(default_factory=list)
    ips: list[IPEntity] = Field(default_factory=list)
    domains: list[DomainEntity] = Field(default_factory=list)
    processes: list[ProcessEntity] = Field(default_factory=list)
    files: list[FileEntity] = Field(default_factory=list)
