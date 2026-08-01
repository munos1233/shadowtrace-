"""Post-evidence false-positive adjudication (ISSUE-114 Phase B)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.models.agent_io import EvidenceOutput, TriageResult
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence
from app.models.fp_adjudication import ChangeWindowBaseline, FpAdjudicationResult
from app.services.change_window_baseline_loader import (
    load_change_window_baseline,
    resolve_tenant_id,
)

logger = logging.getLogger(__name__)

# Minimum confidence persisted on post-evidence close_as_fp for disposition-only approval.
_DISPOSITION_FP_SCORE_FLOOR = 0.88

_MALICIOUS_CONFLICT_SOURCES = frozenset(
    {
        EvidenceSource.ENDPOINT,
        EvidenceSource.DATA_SECURITY,
        EvidenceSource.THREAT_INTEL,
    }
)

_MALICIOUS_RAW_KEYS = (
    "malicious",
    "malware",
    "malware_detected",
    "dlp_blocked",
    "ti_malicious",
    "blocked",
)

_MALICIOUS_VERDICT_VALUES = frozenset({"malicious", "blocked", "critical", "high_risk"})


class PostEvidenceFpAdjudicator:
    """Run typed FP decision after evidence collection.

    Requires positive structured authorization (change window + scope + time).
    Absence of malicious evidence alone is never sufficient for closure.
    """

    def __init__(self, *, baseline_path: str | None = None) -> None:
        self._baseline_path = baseline_path

    def adjudicate(
        self,
        *,
        event_id: str,
        evidence_output: EvidenceOutput,
        triage_result: TriageResult,
        source_snapshot: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> FpAdjudicationResult:
        """Return a structured post-evidence FP recommendation."""
        now = datetime.now(UTC).isoformat()
        tenant_id = resolve_tenant_id(source_snapshot)
        if tenant_id is None:
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                missing_conditions=["tenant_id"],
                adjudicated_at=now,
            )
        baseline = load_change_window_baseline(self._baseline_path).get(tenant_id)
        if baseline is None or not baseline.change_windows:
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                missing_conditions=["org_baseline_available"],
                adjudicated_at=now,
            )

        auth_evidence = _authorization_evidence(evidence_output.evidence_list)
        conflicts = _malicious_conflicts(evidence_output)
        if conflicts:
            return FpAdjudicationResult(
                recommendation="investigate",
                supporting_evidence_ids=[item.evidence_id for item in auth_evidence],
                matched_conditions=_matched_authorization_labels(auth_evidence),
                missing_conditions=["no_malicious_conflicts"],
                conflicts=conflicts,
                adjudicated_at=now,
            )

        if not auth_evidence:
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                missing_conditions=["change_window_authorization_evidence"],
                adjudicated_at=now,
            )

        event_time = _resolve_event_time(auth_evidence, occurred_at)
        accounts = _collect_accounts(triage_result, auth_evidence)
        actions = _collect_actions(triage_result, auth_evidence)
        asset_groups = _collect_asset_groups(evidence_output.evidence_list)

        matched_window = _match_change_window(
            baseline.change_windows,
            event_time=event_time,
            accounts=accounts,
            actions=actions,
            asset_groups=asset_groups,
        )

        matched_conditions = _matched_authorization_labels(auth_evidence)
        missing_conditions: list[str] = []
        if matched_window is None:
            missing_conditions.extend(
                [
                    "baseline_window_match",
                    "identity_scope_match",
                    "action_scope_match",
                    "asset_scope_match",
                    "time_match",
                ]
            )
            return FpAdjudicationResult(
                recommendation="investigate",
                supporting_evidence_ids=[item.evidence_id for item in auth_evidence],
                matched_conditions=matched_conditions,
                missing_conditions=missing_conditions,
                adjudicated_at=now,
            )

        matched_conditions.extend(
            [
                "baseline_window_match",
                "identity_scope_match",
                "action_scope_match",
                "asset_scope_match",
                "time_match",
                "no_malicious_conflicts",
            ]
        )
        logger.info(
            "PostEvidenceFpAdjudicator: close_as_fp event=%s window=%s evidence=%d",
            event_id,
            matched_window.window_id,
            len(auth_evidence),
        )
        return FpAdjudicationResult(
            recommendation="close_as_fp",
            supporting_evidence_ids=[item.evidence_id for item in auth_evidence],
            matched_conditions=matched_conditions,
            missing_conditions=[],
            conflicts=[],
            matched_window_id=matched_window.window_id,
            max_score=_derive_adjudication_score(auth_evidence),
            adjudicated_at=now,
        )


def _authorization_evidence(evidence_list: list[Evidence]) -> list[Evidence]:
    """Identity evidence with explicit change-window authorization flag."""
    authorized: list[Evidence] = []
    for item in evidence_list:
        if item.source is not EvidenceSource.IDENTITY:
            continue
        raw = item.raw_data or {}
        if raw.get("change_window") in (True, "true", "True", 1, "1"):
            authorized.append(item)
    return authorized


def _malicious_conflicts(evidence_output: EvidenceOutput) -> list[str]:
    conflicts: list[str] = []
    for conflict in evidence_output.conflicts:
        conflicts.append(conflict.description or conflict.conflict_id)
    for item in evidence_output.evidence_list:
        if item.is_conflicting:
            conflicts.append(f"conflicting_evidence:{item.evidence_id}")
            continue
        if item.source not in _MALICIOUS_CONFLICT_SOURCES:
            continue
        if _is_malicious_evidence(item):
            conflicts.append(f"malicious_evidence:{item.evidence_id}:{item.source.value}")
    return conflicts


def _is_malicious_evidence(item: Evidence) -> bool:
    raw = item.raw_data or {}
    for key in _MALICIOUS_RAW_KEYS:
        value = raw.get(key)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in _MALICIOUS_VERDICT_VALUES:
            return True
    verdict = raw.get("verdict") or raw.get("severity") or raw.get("risk_label")
    if isinstance(verdict, str) and verdict.strip().lower() in _MALICIOUS_VERDICT_VALUES:
        return True
    return False


def _resolve_event_time(
    auth_evidence: list[Evidence],
    occurred_at: datetime | None,
) -> datetime | None:
    timestamps = [item.timestamp for item in auth_evidence if item.timestamp is not None]
    if timestamps:
        return min(timestamps)
    return occurred_at


def _collect_accounts(triage_result: TriageResult, auth_evidence: list[Evidence]) -> set[str]:
    accounts: set[str] = set()
    for account in triage_result.entities.accounts:
        for value in (account.username, account.display_name, account.entity_id):
            if value:
                accounts.add(str(value).lower())
    for item in auth_evidence:
        raw_account = (item.raw_data or {}).get("account")
        if raw_account:
            accounts.add(str(raw_account).lower())
    return accounts


def _collect_actions(_triage_result: TriageResult, auth_evidence: list[Evidence]) -> set[str]:
    """Collect observed actions from authorization evidence only (ISSUE-114)."""
    actions: set[str] = set()
    for item in auth_evidence:
        for key in ("event_type", "action"):
            value = (item.raw_data or {}).get(key)
            if value:
                actions.add(str(value).lower())
        if item.evidence_type:
            actions.add(str(item.evidence_type).lower())
    return actions


def _collect_asset_groups(evidence_list: list[Evidence]) -> set[str]:
    groups: set[str] = set()
    for item in evidence_list:
        if item.source is not EvidenceSource.ASSET:
            continue
        raw = item.raw_data or {}
        group = raw.get("asset_group") or raw.get("group")
        if group:
            groups.add(str(group).lower())
    return groups


def _match_change_window(
    windows: list[ChangeWindowBaseline],
    *,
    event_time: datetime | None,
    accounts: set[str],
    actions: set[str],
    asset_groups: set[str],
) -> ChangeWindowBaseline | None:
    if event_time is None:
        return None
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=UTC)

    for window in windows:
        try:
            start = datetime.fromisoformat(window.valid_from)
            end = datetime.fromisoformat(window.valid_until)
        except ValueError:
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if not (start <= event_time <= end):
            continue

        authorized_accounts = {value.lower() for value in window.authorized_accounts}
        if authorized_accounts and accounts.isdisjoint(authorized_accounts):
            continue

        authorized_actions = {value.lower() for value in window.authorized_actions}
        if authorized_actions and actions.isdisjoint(authorized_actions):
            continue

        authorized_groups = {value.lower() for value in window.authorized_asset_groups}
        if authorized_groups and (not asset_groups or asset_groups.isdisjoint(authorized_groups)):
            continue

        return window
    return None


def _derive_adjudication_score(auth_evidence: list[Evidence]) -> float:
    """Confidence for disposition-only approval from authorization evidence."""
    scores: list[float] = []
    for item in auth_evidence:
        try:
            scores.append(max(0.0, min(1.0, float(item.confidence))))
        except (TypeError, ValueError):
            continue
    derived = max(scores) if scores else 0.0
    return max(derived, _DISPOSITION_FP_SCORE_FLOOR)


def _matched_authorization_labels(auth_evidence: list[Evidence]) -> list[str]:
    if not auth_evidence:
        return []
    return ["change_window_authorization_present"]


__all__ = ["PostEvidenceFpAdjudicator"]
