"""Legacy telemetry aggregation into raw_alert fallback records (ISSUE-016)."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

_ENTITY_KEYS = ("account", "hostname", "src_ip", "dst_ip", "domain", "file_name")
_OPERATIONAL_EVENT_TYPES = frozenset({"provider_error", "health_check", "heartbeat"})


class AlertBuilder:
    """Aggregate suspicious telemetry sharing entity combinations + time window."""

    def __init__(self, *, window: timedelta = timedelta(hours=1)) -> None:
        if window.total_seconds() <= 0:
            raise ValueError("window must be positive")
        self._window = window

    def build(self, normalized_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return deterministic raw_alert dictionaries.

        Output fields are fixed by ISSUE-016: ``alert_type``, ``source_type``,
        ``records``, ``primary_entities`` and ``occurred_at``.
        """
        groups: dict[
            tuple[tuple[str, ...], int],
            list[tuple[datetime, dict[str, Any]]],
        ] = defaultdict(list)
        window_seconds = int(self._window.total_seconds())

        for raw in normalized_records:
            if not isinstance(raw, dict) or not _is_suspicious(raw):
                continue
            occurred = _record_time(raw)
            if occurred is None:
                continue
            entities = _primary_entities(raw)
            if not entities:
                continue
            bucket = int(occurred.timestamp()) // window_seconds
            groups[(tuple(entities), bucket)].append((occurred, dict(raw)))

        alerts: list[dict[str, Any]] = []
        for (entity_key, _bucket), records in sorted(
            groups.items(),
            key=lambda item: (item[0][1], item[0][0]),
        ):
            records.sort(key=lambda item: (item[0], str(item[1].get("record_id", ""))))
            raw_records = [record for _, record in records]
            alerts.append(
                {
                    "alert_type": _alert_type(raw_records),
                    "source_type": "file",
                    "records": raw_records,
                    "primary_entities": list(entity_key),
                    "occurred_at": records[0][0].isoformat(),
                }
            )
        return alerts


def _is_suspicious(record: dict[str, Any]) -> bool:
    if record.get("is_noise") is True or record.get("is_key_event") is False:
        return False
    record_id = str(record.get("record_id") or "").lower()
    if record_id.startswith("noise-") or "-noise-" in record_id:
        return False
    event_type = str(record.get("event_type") or "").lower()
    if event_type in _OPERATIONAL_EVENT_TYPES:
        return False
    if event_type == "login" and str(record.get("result") or "").lower() == "success":
        return False
    if record.get("is_key_event") is True:
        return True
    if record.get("is_conflict_seed") is True:
        return True
    action = str(record.get("action") or "").lower()
    if action in {
        "upload",
        "archive",
        "network_connect",
        "process_create",
        "file_access",
    }:
        return True
    return _as_int(record.get("bytes_out")) >= 1_000_000


def _record_time(record: dict[str, Any]) -> datetime | None:
    raw = record.get("logged_at") or record.get("occurred_at") or record.get("timestamp")
    if isinstance(raw, datetime):
        parsed = raw
    elif isinstance(raw, str):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _primary_entities(record: dict[str, Any]) -> list[str]:
    entities: list[str] = []
    for key in _ENTITY_KEYS:
        value = record.get(key)
        if value is not None and str(value).strip():
            entities.append(f"{key}:{str(value).strip()}")
    return sorted(set(entities))


def _alert_type(records: list[dict[str, Any]]) -> str:
    channels = {str(record.get("channel") or "").lower() for record in records}
    actions = {str(record.get("action") or "").lower() for record in records}
    if "dlp" in channels or "upload" in actions or any(
        _as_int(record.get("bytes_out")) >= 1_000_000 for record in records
    ):
        return "data_exfiltration"
    if "endpoint" in channels:
        return "malicious_process"
    if "identity" in channels:
        return "account_anomaly"
    if "dns" in channels:
        return "suspicious_domain"
    return "other"


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
