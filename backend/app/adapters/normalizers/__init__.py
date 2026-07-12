"""Deep-dive telemetry normalizers for Evidence queries (ISSUE-012).

These are NOT registered as independent XDR SourceAdapters — they only reshape
file/Mock telemetry channels into a common evidence-oriented record.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NormalizedTelemetry(BaseModel):
    """Evidence-oriented telemetry record (channel-agnostic)."""

    model_config = ConfigDict(extra="forbid")

    channel: str
    record_id: str
    logged_at: datetime | None = None
    entities: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    is_conflict_seed: bool = False
    is_key_event: bool = False


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_identity(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="identity",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "account": row.get("account"),
            "src_ip": row.get("src_ip"),
            "event_type": row.get("event_type"),
            "result": row.get("result"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_endpoint(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="endpoint",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "hostname": row.get("hostname"),
            "process": row.get("process"),
            "account": row.get("account"),
            "action": row.get("action"),
            "file_name": row.get("file_name"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_dlp(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="dlp",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "file_name": row.get("file_name"),
            "action": row.get("action"),
            "bytes": row.get("bytes"),
            "account": row.get("account"),
            "hostname": row.get("hostname"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_network(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="network",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "dst_port": row.get("dst_port"),
            "bytes_out": row.get("bytes_out"),
            "hostname": row.get("hostname"),
            "domain": row.get("domain"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_dns(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="dns",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "query": row.get("query"),
            "qtype": row.get("qtype"),
            "rcode": row.get("rcode"),
            "answer": row.get("answer"),
            "hostname": row.get("hostname"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_asset(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="asset",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("last_seen_at") or row.get("logged_at")),
        entities={
            "numeric_asset_id": row.get("numeric_asset_id"),
            "hostname": row.get("hostname"),
            "ip": row.get("ip"),
            "agent_status": row.get("agent_status"),
            "owner": row.get("owner"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


def normalize_threat_intel(row: dict[str, Any]) -> NormalizedTelemetry:
    return NormalizedTelemetry(
        channel="threat_intel",
        record_id=str(row.get("record_id", "")),
        logged_at=_parse_ts(row.get("logged_at")),
        entities={
            "indicator": row.get("indicator"),
            "indicator_type": row.get("indicator_type"),
            "confidence": row.get("confidence"),
            "tags": row.get("tags"),
        },
        raw=dict(row),
        is_conflict_seed=bool(row.get("is_conflict_seed")),
        is_key_event=bool(row.get("is_key_event")),
    )


CHANNEL_NORMALIZERS: dict[str, Callable[[dict[str, Any]], NormalizedTelemetry]] = {
    "identity": normalize_identity,
    "endpoint": normalize_endpoint,
    "dlp": normalize_dlp,
    "network": normalize_network,
    "dns": normalize_dns,
    "asset": normalize_asset,
    "threat_intel": normalize_threat_intel,
}


def normalize_record(row: dict[str, Any]) -> NormalizedTelemetry:
    channel = str(row.get("channel", ""))
    fn = CHANNEL_NORMALIZERS.get(channel)
    if fn is None:
        return NormalizedTelemetry(
            channel=channel or "unknown",
            record_id=str(row.get("record_id", "")),
            logged_at=_parse_ts(row.get("logged_at")),
            entities={},
            raw=dict(row),
            is_conflict_seed=bool(row.get("is_conflict_seed")),
            is_key_event=bool(row.get("is_key_event")),
        )
    return fn(row)


def normalize_channel(channel: str, rows: list[dict[str, Any]]) -> list[NormalizedTelemetry]:
    fn = CHANNEL_NORMALIZERS[channel]
    return [fn(row) for row in rows]
