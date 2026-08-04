"""Detection governance decision service (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import ROLE_ADMIN, Principal
from app.core.errors import ResourceNotFoundError, ValidationError
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceDecision,
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
    DetectionGovernanceEligibilityAssessment,
    DetectionGovernancePromotionGateResult,
    DetectionGovernanceReasonCode,
)
from app.services.detection_governance_binding import (
    build_candidate_binding,
    build_evaluation_binding,
    build_threshold_binding,
    compute_binding_hash,
    finalize_decision,
    validate_decision_artifact_binding,
)
from app.services.detection_governance_policy import (
    DETECTION_GOVERNANCE_POLICY_VERSION,
    assess_governance_eligibility,
    get_detection_governance_policy,
)

_SYSTEM_REVIEWER = "system:detection-governance"


def assert_governance_tenant_access(principal: Principal, tenant_id: str) -> None:
    """Fail closed when a non-admin principal accesses another tenant's records."""
    if principal.has_any_role([ROLE_ADMIN]):
        return
    scoped = principal.tenant_id
    if not scoped or scoped != tenant_id:
        raise ResourceNotFoundError(
            "detection governance decision not found",
            details={"tenant_id": tenant_id, "reason": "tenant_scope_denied"},
        )


class DetectionGovernanceService:
    """Append-only pre-promotion governance records with fail-closed approval."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._now = now or (lambda: datetime.now(UTC))

    async def assess_eligibility(
        self,
        artifact: DetectionEvaluationArtifact,
        *,
        threshold_manifest_path: Path | None = None,
        principal: Principal | None = None,
    ) -> DetectionGovernanceEligibilityAssessment:
        if principal is not None:
            assert_governance_tenant_access(principal, artifact.tenant_id)
        return assess_governance_eligibility(
            artifact,
            threshold_manifest_path=threshold_manifest_path,
        )

    async def record_decision(
        self,
        principal: Principal,
        artifact: DetectionEvaluationArtifact,
        request: DetectionGovernanceDecisionRequest,
        *,
        threshold_manifest_path: Path | None = None,
    ) -> DetectionGovernanceDecision:
        assert_governance_tenant_access(principal, artifact.tenant_id)
        if request.decision not in {
            DetectionGovernanceDecisionKind.APPROVE,
            DetectionGovernanceDecisionKind.REJECT,
        }:
            raise ValidationError(
                "record_decision only supports approve/reject",
                details={"decision": request.decision.value},
            )
        self._require_human_reviewer(principal)
        if (
            request.decision == DetectionGovernanceDecisionKind.APPROVE
            and threshold_manifest_path is None
        ):
            raise ValidationError(
                "approval blocked: threshold_manifest_path required",
                details={"reason": "threshold_manifest_path_missing"},
            )

        assessment = assess_governance_eligibility(
            artifact,
            threshold_manifest_path=threshold_manifest_path,
        )
        reason_codes = list(assessment.reason_codes)
        if request.decision == DetectionGovernanceDecisionKind.APPROVE:
            if not assessment.eligible:
                raise ValidationError(
                    "approval blocked: evaluation artifact ineligible",
                    details={
                        "reason_codes": [code.value for code in reason_codes],
                        "messages": assessment.messages,
                    },
                )
        elif request.decision == DetectionGovernanceDecisionKind.REJECT:
            if DetectionGovernanceReasonCode.MANUAL_REJECT not in reason_codes:
                reason_codes.append(DetectionGovernanceReasonCode.MANUAL_REJECT)

        candidate_binding = build_candidate_binding(artifact)
        evaluation_binding = build_evaluation_binding(artifact)
        threshold_binding = build_threshold_binding(
            artifact,
            manifest_path=str(threshold_manifest_path) if threshold_manifest_path else None,
        )
        binding_hash = compute_binding_hash(
            tenant_id=artifact.tenant_id,
            candidate_binding=candidate_binding,
            evaluation_binding=evaluation_binding,
            threshold_binding=threshold_binding,
            policy_version=DETECTION_GOVERNANCE_POLICY_VERSION,
        )

        decided_at = self._now()
        expires_at = request.expires_at
        if request.decision == DetectionGovernanceDecisionKind.APPROVE and expires_at is None:
            policy = get_detection_governance_policy()
            expires_at = decided_at + timedelta(hours=policy.default_approval_ttl_hours)
        decision_id = await self._new_decision_id()
        decision = finalize_decision(
            DetectionGovernanceDecision(
                decision_id=decision_id,
                tenant_id=artifact.tenant_id,
                decision=request.decision,
                candidate_binding=candidate_binding,
                evaluation_binding=evaluation_binding,
                threshold_binding=threshold_binding,
                binding_hash=binding_hash,
                policy_version=DETECTION_GOVERNANCE_POLICY_VERSION,
                reviewer_subject=principal.subject,
                reviewer_roles=list(principal.roles),
                reason_codes=reason_codes,
                reason_note=request.reason_note.strip(),
                decided_at=decided_at,
                expires_at=expires_at,
            )
        )
        await self._insert_decision(
            decision,
            require_no_active_approval=request.decision == DetectionGovernanceDecisionKind.APPROVE,
        )
        return decision

    async def revoke_decision(
        self,
        principal: Principal,
        decision_id: str,
        *,
        reason_note: str,
        tenant_id: str | None = None,
    ) -> DetectionGovernanceDecision:
        self._require_human_reviewer(principal)
        target = await self.get_decision(decision_id, tenant_id=tenant_id)
        assert_governance_tenant_access(principal, target.tenant_id)
        if target.decision != DetectionGovernanceDecisionKind.APPROVE:
            raise ValidationError(
                "only approve decisions can be revoked",
                details={"decision_id": decision_id, "decision": target.decision.value},
            )

        decided_at = self._now()
        async with self._session_factory() as session:
            async with session.begin():
                rows = list(
                    await session.scalars(
                        select(DetectionGovernanceDecisionORM)
                        .where(DetectionGovernanceDecisionORM.binding_hash == target.binding_hash)
                        .order_by(DetectionGovernanceDecisionORM.decided_at.asc())
                        .with_for_update()
                    )
                )
                chain = [_row_to_decision(row) for row in rows]
                if _is_superseded(target, chain):
                    raise ValidationError(
                        "approval already revoked or expired",
                        details={
                            "decision_id": decision_id,
                            "reason": DetectionGovernanceReasonCode.DECISION_SUPERSEDED.value,
                        },
                    )
                active = _resolve_active_approval(chain, now=decided_at)
                if active is None or active.decision_id != decision_id:
                    raise ValidationError(
                        "decision is not the active approval for binding",
                        details={"decision_id": decision_id},
                    )
                revoke_id = await self._new_decision_id_in_session(session)
                revoke = finalize_decision(
                    DetectionGovernanceDecision(
                        decision_id=revoke_id,
                        tenant_id=target.tenant_id,
                        decision=DetectionGovernanceDecisionKind.REVOKE,
                        candidate_binding=target.candidate_binding,
                        evaluation_binding=target.evaluation_binding,
                        threshold_binding=target.threshold_binding,
                        binding_hash=target.binding_hash,
                        policy_version=DETECTION_GOVERNANCE_POLICY_VERSION,
                        reviewer_subject=principal.subject,
                        reviewer_roles=list(principal.roles),
                        reason_codes=[DetectionGovernanceReasonCode.MANUAL_REVOKE],
                        reason_note=reason_note.strip(),
                        decided_at=decided_at,
                        supersedes_decision_id=decision_id,
                    )
                )
                session.add(
                    DetectionGovernanceDecisionORM(
                        decision_id=revoke.decision_id,
                        tenant_id=revoke.tenant_id,
                        decision=revoke.decision.value,
                        binding_hash=revoke.binding_hash,
                        decision_hash=revoke.decision_hash,
                        payload=revoke.model_dump(mode="json"),
                        reviewer_subject=revoke.reviewer_subject,
                        supersedes_decision_id=revoke.supersedes_decision_id,
                        expires_at=revoke.expires_at,
                        decided_at=revoke.decided_at,
                    )
                )
        return revoke

    async def expire_active_approvals(self, *, binding_hash: str | None = None) -> list[str]:
        """System expire approvals past ``expires_at`` (append-only)."""
        now = self._now()
        expired_ids: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                candidate_stmt = select(DetectionGovernanceDecisionORM.binding_hash).where(
                    DetectionGovernanceDecisionORM.decision
                    == DetectionGovernanceDecisionKind.APPROVE.value,
                    DetectionGovernanceDecisionORM.expires_at.isnot(None),
                    DetectionGovernanceDecisionORM.expires_at <= now,
                )
                if binding_hash is not None:
                    candidate_stmt = candidate_stmt.where(
                        DetectionGovernanceDecisionORM.binding_hash == binding_hash
                    )
                binding_hashes = {
                    row for row in await session.scalars(candidate_stmt.distinct()) if row
                }

                for current_binding_hash in sorted(binding_hashes):
                    rows = list(
                        await session.scalars(
                            select(DetectionGovernanceDecisionORM)
                            .where(
                                DetectionGovernanceDecisionORM.binding_hash == current_binding_hash
                            )
                            .order_by(DetectionGovernanceDecisionORM.decided_at.asc())
                            .with_for_update()
                        )
                    )
                    chain = [_row_to_decision(row) for row in rows]
                    for record in sorted(chain, key=lambda item: item.decided_at):
                        if record.decision != DetectionGovernanceDecisionKind.APPROVE:
                            continue
                        if record.expires_at is None or record.expires_at > now:
                            continue
                        if _is_superseded(record, chain):
                            continue
                        expire_id = await self._new_decision_id_in_session(session)
                        expire = finalize_decision(
                            DetectionGovernanceDecision(
                                decision_id=expire_id,
                                tenant_id=record.tenant_id,
                                decision=DetectionGovernanceDecisionKind.EXPIRE,
                                candidate_binding=record.candidate_binding,
                                evaluation_binding=record.evaluation_binding,
                                threshold_binding=record.threshold_binding,
                                binding_hash=record.binding_hash,
                                policy_version=DETECTION_GOVERNANCE_POLICY_VERSION,
                                reviewer_subject=_SYSTEM_REVIEWER,
                                reviewer_roles=[],
                                reason_codes=[DetectionGovernanceReasonCode.DECISION_EXPIRED],
                                reason_note=f"approval expired at {record.expires_at.isoformat()}",
                                decided_at=now,
                                supersedes_decision_id=record.decision_id,
                            )
                        )
                        session.add(
                            DetectionGovernanceDecisionORM(
                                decision_id=expire.decision_id,
                                tenant_id=expire.tenant_id,
                                decision=expire.decision.value,
                                binding_hash=expire.binding_hash,
                                decision_hash=expire.decision_hash,
                                payload=expire.model_dump(mode="json"),
                                reviewer_subject=expire.reviewer_subject,
                                supersedes_decision_id=expire.supersedes_decision_id,
                                expires_at=expire.expires_at,
                                decided_at=expire.decided_at,
                            )
                        )
                        chain.append(expire)
                        expired_ids.append(expire.decision_id)
        return expired_ids

    async def get_decision(
        self,
        decision_id: str,
        *,
        tenant_id: str | None = None,
        principal: Principal | None = None,
    ) -> DetectionGovernanceDecision:
        async with self._session_factory() as session:
            row = await session.get(DetectionGovernanceDecisionORM, decision_id)
        if row is None:
            raise ResourceNotFoundError(
                "detection governance decision not found",
                details={"decision_id": decision_id},
            )
        decision = _row_to_decision(row)
        if tenant_id is not None and decision.tenant_id != tenant_id:
            raise ResourceNotFoundError(
                "detection governance decision not found",
                details={"decision_id": decision_id, "tenant_id": tenant_id},
            )
        if principal is not None:
            assert_governance_tenant_access(principal, decision.tenant_id)
        return decision

    async def list_decisions(
        self,
        *,
        tenant_id: str | None = None,
        binding_hash: str | None = None,
        limit: int = 50,
        offset: int = 0,
        principal: Principal | None = None,
    ) -> tuple[list[DetectionGovernanceDecision], int]:
        if tenant_id is not None and principal is not None:
            assert_governance_tenant_access(principal, tenant_id)
        safe_limit = max(1, min(limit, 200))
        safe_offset = max(0, offset)
        async with self._session_factory() as session:
            filters = []
            if tenant_id is not None:
                filters.append(DetectionGovernanceDecisionORM.tenant_id == tenant_id)
            if binding_hash is not None:
                filters.append(DetectionGovernanceDecisionORM.binding_hash == binding_hash)
            count_stmt = select(func.count()).select_from(DetectionGovernanceDecisionORM)
            if filters:
                count_stmt = count_stmt.where(*filters)
            total = int(await session.scalar(count_stmt) or 0)
            stmt = (
                select(DetectionGovernanceDecisionORM)
                .order_by(DetectionGovernanceDecisionORM.decided_at.desc())
                .offset(safe_offset)
                .limit(safe_limit)
            )
            if filters:
                stmt = stmt.where(*filters)
            rows = list(await session.scalars(stmt))
        return [_row_to_decision(row) for row in rows], total

    async def evaluate_promotion_gate(
        self,
        artifact: DetectionEvaluationArtifact,
        *,
        binding_hash: str | None = None,
        principal: Principal | None = None,
    ) -> DetectionGovernancePromotionGateResult:
        """Read-only promotion eligibility snapshot for #629 (Phase A helper)."""
        if principal is not None:
            assert_governance_tenant_access(principal, artifact.tenant_id)
        candidate_binding = build_candidate_binding(artifact)
        evaluation_binding = build_evaluation_binding(artifact)
        threshold_binding = build_threshold_binding(artifact)
        resolved_binding_hash = binding_hash or compute_binding_hash(
            tenant_id=artifact.tenant_id,
            candidate_binding=candidate_binding,
            evaluation_binding=evaluation_binding,
            threshold_binding=threshold_binding,
            policy_version=DETECTION_GOVERNANCE_POLICY_VERSION,
        )
        now = self._now()
        chain, _ = await self.list_decisions(
            tenant_id=artifact.tenant_id,
            binding_hash=resolved_binding_hash,
            limit=200,
        )
        active = _resolve_active_approval(chain, now=now)
        if active is None:
            return DetectionGovernancePromotionGateResult(
                allowed=False,
                reason_codes=[DetectionGovernanceReasonCode.NO_ACTIVE_APPROVAL],
                messages=["no active governance approval for candidate binding"],
            )
        try:
            validate_decision_artifact_binding(active, artifact)
        except ValidationError as exc:
            details = exc.details if isinstance(exc.details, dict) else {}
            reason = details.get(
                "reason",
                DetectionGovernanceReasonCode.ARTIFACT_HASH_MISMATCH.value,
            )
            return DetectionGovernancePromotionGateResult(
                allowed=False,
                decision_id=active.decision_id,
                reason_codes=[DetectionGovernanceReasonCode(reason)],
                messages=[str(exc)],
            )
        return DetectionGovernancePromotionGateResult(
            allowed=True,
            decision_id=active.decision_id,
        )

    async def resolve_active_approval(
        self,
        *,
        tenant_id: str,
        binding_hash: str,
    ) -> DetectionGovernanceDecision | None:
        """Return the currently active APPROVE decision for a binding hash, if any."""
        chain, _ = await self.list_decisions(
            tenant_id=tenant_id,
            binding_hash=binding_hash,
            limit=200,
        )
        return _resolve_active_approval(chain, now=self._now())

    async def _find_active_approval(
        self,
        binding_hash: str,
    ) -> DetectionGovernanceDecision | None:
        chain, _ = await self.list_decisions(binding_hash=binding_hash, limit=200)
        return _resolve_active_approval(chain, now=self._now())

    async def _insert_decision(
        self,
        decision: DetectionGovernanceDecision,
        *,
        require_no_active_approval: bool,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                if require_no_active_approval:
                    rows = list(
                        await session.scalars(
                            select(DetectionGovernanceDecisionORM)
                            .where(
                                DetectionGovernanceDecisionORM.binding_hash == decision.binding_hash
                            )
                            .order_by(DetectionGovernanceDecisionORM.decided_at.asc())
                            .with_for_update()
                        )
                    )
                    chain = [_row_to_decision(row) for row in rows]
                    active = _resolve_active_approval(chain, now=self._now())
                    if active is not None:
                        raise ValidationError(
                            "active approval already exists for binding",
                            details={
                                "binding_hash": decision.binding_hash,
                                "decision_id": active.decision_id,
                            },
                        )
                session.add(
                    DetectionGovernanceDecisionORM(
                        decision_id=decision.decision_id,
                        tenant_id=decision.tenant_id,
                        decision=decision.decision.value,
                        binding_hash=decision.binding_hash,
                        decision_hash=decision.decision_hash,
                        payload=decision.model_dump(mode="json"),
                        reviewer_subject=decision.reviewer_subject,
                        supersedes_decision_id=decision.supersedes_decision_id,
                        expires_at=decision.expires_at,
                        decided_at=decision.decided_at,
                    )
                )

    async def _new_decision_id(self) -> str:
        async with self._session_factory() as session:
            return await self._new_decision_id_in_session(session)

    async def _new_decision_id_in_session(self, session: AsyncSession) -> str:
        for _ in range(8):
            decision_id = f"dgov-{secrets.token_hex(4)}"
            existing = await session.get(DetectionGovernanceDecisionORM, decision_id)
            if existing is None:
                return decision_id
        raise RuntimeError("failed to allocate detection governance decision_id")

    @staticmethod
    def _require_human_reviewer(principal: Principal) -> None:
        from app.core.auth import ROLE_APPROVER

        policy = get_detection_governance_policy()
        if not principal.has_any_role([ROLE_APPROVER]):
            raise ValidationError(
                "governance decision requires approver role",
                details={"reason": DetectionGovernanceReasonCode.REVIEWER_REQUIRED.value},
            )
        if policy.require_human_reviewer_for_approve and (
            principal.subject.startswith("system:") or principal.subject.startswith("agent:")
        ):
            raise ValidationError(
                "governance approval requires human reviewer principal",
                details={"reason": DetectionGovernanceReasonCode.REVIEWER_REQUIRED.value},
            )


def _row_to_decision(row: DetectionGovernanceDecisionORM) -> DetectionGovernanceDecision:
    return DetectionGovernanceDecision.model_validate(row.payload)


def _is_superseded(
    target: DetectionGovernanceDecision,
    chain: list[DetectionGovernanceDecision],
) -> bool:
    for record in chain:
        if record.supersedes_decision_id != target.decision_id:
            continue
        if record.decision in {
            DetectionGovernanceDecisionKind.REVOKE,
            DetectionGovernanceDecisionKind.EXPIRE,
        }:
            return True
    return False


def _resolve_active_approval(
    chain: list[DetectionGovernanceDecision],
    *,
    now: datetime,
) -> DetectionGovernanceDecision | None:
    if not chain:
        return None
    ordered = sorted(chain, key=lambda item: item.decided_at)
    active: DetectionGovernanceDecision | None = None
    for record in ordered:
        if record.decision == DetectionGovernanceDecisionKind.APPROVE:
            if record.expires_at is not None and record.expires_at <= now:
                active = None
                continue
            active = record
        elif record.decision in {
            DetectionGovernanceDecisionKind.REVOKE,
            DetectionGovernanceDecisionKind.EXPIRE,
            DetectionGovernanceDecisionKind.REJECT,
        }:
            supersedes_active = (
                record.supersedes_decision_id
                and active
                and record.supersedes_decision_id == active.decision_id
            )
            if supersedes_active:
                active = None
            elif record.decision == DetectionGovernanceDecisionKind.REJECT:
                active = None
    return active


__all__ = ["DetectionGovernanceService", "assert_governance_tenant_access"]
