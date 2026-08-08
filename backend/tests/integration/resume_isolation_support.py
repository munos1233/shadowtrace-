"""ISSUE-282 / ID-REL-001 isolated checkpoint & approval resume diagnostics.

Two SUSPECTED tail-chain anomalies (not proven same root cause):

1. ``checkpoint_resume_close_node`` — resume after checkpoint interrupt completes
   without ``close_node`` in ``node_trace`` despite a legal not-required tail.
2. ``approval_resume_halted_stale`` — after production approval resume,
   ``needs_approval_wait=false`` while ``halted=true`` (incoherent halt flags).

Tests run on dedicated PostgreSQL/Redis fixtures (``clean_state``) with fixed
config; no parallel DB probes. Artifacts record resume before/after snapshots
for audit and local review.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import ActionStatus, EventStatus, ExecutionSubstate
from app.orchestration.workflow_graph import (
    NODE_CLOSE,
    NODE_HALT,
    NODE_MANUAL_HOLD,
    NODE_WRITEBACK_RECOVERY,
)

ISSUE_ID = "ISSUE-282"
AUDIT_ID = "ID-REL-001"
ISOLATION_PASSES = 10

Phenomenon = Literal["checkpoint_resume_close_node", "approval_resume_halted_stale"]
Verdict = Literal["REPRODUCED", "NOT_REPRODUCED"]


@dataclass(frozen=True)
class ResumeIsolationSnapshot:
    """Structured checkpoint / DB snapshot at one resume phase."""

    phase: str
    graph_wired: bool
    checkpoint_present: bool
    halted: bool | None
    needs_approval_wait: bool | None
    execution_substate: str | None
    event_status: str | None
    db_event_status: str | None
    next_nodes: tuple[str, ...]
    node_trace: tuple[str, ...]
    pending_action_ids: tuple[str, ...] = ()
    pending_action_statuses: tuple[str, ...] = ()
    pending_action_owners: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResumeIsolationArtifact:
    """Audit artifact for one isolated phenomenon probe."""

    phenomenon: Phenomenon
    verdict: Verdict
    consecutive_passes: int
    git_commit: str
    environment: dict[str, str]
    pre_resume: ResumeIsolationSnapshot
    post_resume: ResumeIsolationSnapshot
    issue_id: str = ISSUE_ID
    audit_id: str = AUDIT_ID
    anomaly_detail: str | None = None
    run_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["pre_resume"] = self.pre_resume.to_dict()
        payload["post_resume"] = self.post_resume.to_dict()
        return payload

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        path.write_text(payload, encoding="utf-8")


def git_head_short() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def isolation_environment() -> dict[str, str]:
    """Record non-secret environment markers for artifact replay."""
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "database_url_host": _redact_url_host(os.environ.get("DATABASE_URL", "")),
        "redis_url_host": _redact_url_host(os.environ.get("REDIS_URL", "")),
        "orchestration_mode": os.environ.get("ORCHESTRATION_MODE", ""),
        "task_mode": os.environ.get("TASK_MODE", ""),
    }


def _redact_url_host(url: str) -> str:
    if not url:
        return "unset"
    if "@" in url:
        return url.split("@", 1)[1].split("/", 1)[0]
    return url.split("//", 1)[-1].split("/", 1)[0]


async def capture_db_event_status(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> str | None:
    async with session_factory() as session:
        raw = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
    return str(raw) if raw is not None else None


async def capture_pending_actions(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.Action)
                .where(
                    orm.Action.event_id == event_id,
                    orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
                )
                .order_by(orm.Action.action_id)
            )
        )
    if not rows:
        return (), (), ()
    return (
        tuple(row.action_id for row in rows),
        tuple(str(row.status) for row in rows),
        tuple(str(row.execution_owner or "") for row in rows),
    )


async def capture_graph_checkpoint_snapshot(
    *,
    graph: Any,
    event_id: str,
    phase: str,
    session_factory: async_sessionmaker[AsyncSession],
    graph_wired: bool = True,
) -> ResumeIsolationSnapshot:
    if not graph_wired or graph is None:
        db_status = await capture_db_event_status(session_factory, event_id)
        pending_ids, pending_statuses, pending_owners = await capture_pending_actions(
            session_factory,
            event_id,
        )
        return ResumeIsolationSnapshot(
            phase=phase,
            graph_wired=False,
            checkpoint_present=False,
            halted=None,
            needs_approval_wait=None,
            execution_substate=None,
            event_status=None,
            db_event_status=db_status,
            next_nodes=(),
            node_trace=(),
            pending_action_ids=pending_ids,
            pending_action_statuses=pending_statuses,
            pending_action_owners=pending_owners,
        )

    config = {"configurable": {"thread_id": event_id}}
    snap = await graph.aget_state(config)
    db_status = await capture_db_event_status(session_factory, event_id)
    pending_ids, pending_statuses, pending_owners = await capture_pending_actions(
        session_factory,
        event_id,
    )

    if snap is None or not snap.values:
        return ResumeIsolationSnapshot(
            phase=phase,
            graph_wired=True,
            checkpoint_present=False,
            halted=None,
            needs_approval_wait=None,
            execution_substate=None,
            event_status=None,
            db_event_status=db_status,
            next_nodes=(),
            node_trace=(),
            pending_action_ids=pending_ids,
            pending_action_statuses=pending_statuses,
            pending_action_owners=pending_owners,
        )

    values = snap.values
    return ResumeIsolationSnapshot(
        phase=phase,
        graph_wired=True,
        checkpoint_present=True,
        halted=values.get("halted"),
        needs_approval_wait=values.get("needs_approval_wait"),
        execution_substate=values.get("execution_substate"),
        event_status=values.get("event_status"),
        db_event_status=db_status,
        next_nodes=tuple(str(n) for n in (snap.next or ())),
        node_trace=tuple(str(n) for n in (values.get("node_trace") or [])),
        pending_action_ids=pending_ids,
        pending_action_statuses=pending_statuses,
        pending_action_owners=pending_owners,
    )


def detect_checkpoint_close_node_anomaly(snapshot: ResumeIsolationSnapshot) -> str | None:
    """Return anomaly detail when a legal not-required tail lacks close_node."""
    if not snapshot.checkpoint_present:
        return "checkpoint missing at post-resume tail evaluation"
    if snapshot.halted is True:
        return None
    if NODE_CLOSE in snapshot.node_trace:
        return None
    # Legal not-required analysis tail should include close_node once reporting completes.
    if snapshot.event_status in {
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
    }:
        return (
            f"post-resume tail missing {NODE_CLOSE} "
            f"(event_status={snapshot.event_status}, trace={list(snapshot.node_trace)})"
        )
    if snapshot.event_status == EventStatus.TRIAGING.value and snapshot.node_trace:
        return (
            f"post-resume graph trace ended without {NODE_CLOSE} "
            f"(event_status={snapshot.event_status}, trace={list(snapshot.node_trace)})"
        )
    return None


_LEGITIMATE_HALT_TAIL_NODES = frozenset(
    {
        NODE_MANUAL_HOLD,
        NODE_HALT,
        NODE_WRITEBACK_RECOVERY,
    }
)


def detect_approval_halted_stale_anomaly(snapshot: ResumeIsolationSnapshot) -> str | None:
    """Return anomaly detail for stale approval-wait / halt flag pairs."""
    db_status = snapshot.db_event_status or snapshot.event_status
    if snapshot.needs_approval_wait is True and db_status in {
        EventStatus.EXECUTING_RESPONSE.value,
        EventStatus.VERIFYING.value,
        EventStatus.REPORTING.value,
        EventStatus.REPLANNING.value,
        EventStatus.CLOSED.value,
    }:
        return (
            "stale needs_approval_wait on checkpoint after DB left approval wait: "
            f"needs_approval_wait={snapshot.needs_approval_wait} "
            f"db_status={db_status} halted={snapshot.halted} "
            f"trace_tail={list(snapshot.node_trace)[-5:]}"
        )
    if snapshot.needs_approval_wait is False and snapshot.halted is True:
        trace_tail = list(snapshot.node_trace)
        last_node = trace_tail[-1] if trace_tail else None
        if last_node in _LEGITIMATE_HALT_TAIL_NODES:
            return None
        return (
            "incoherent halt flags after approval resume: "
            f"needs_approval_wait={snapshot.needs_approval_wait} halted={snapshot.halted} "
            f"substate={snapshot.execution_substate} next={list(snapshot.next_nodes)} "
            f"trace_tail={trace_tail[-5:]}"
        )
    return None


def assert_resume_snapshot_coherent(snapshot: ResumeIsolationSnapshot) -> None:
    """Basic self-consistency checks on a post-resume snapshot."""
    if snapshot.needs_approval_wait is True and snapshot.halted is not True:
        raise AssertionError(
            f"needs_approval_wait=true requires halted=true; snapshot={snapshot.to_dict()}"
        )
    if (
        snapshot.execution_substate == ExecutionSubstate.WAITING_APPROVAL.value
        and snapshot.halted is not True
    ):
        raise AssertionError(
            f"waiting_approval substate requires halted=true; snapshot={snapshot.to_dict()}"
        )


def build_artifact(
    *,
    phenomenon: Phenomenon,
    pre_resume: ResumeIsolationSnapshot,
    post_resume: ResumeIsolationSnapshot,
    run_index: int | None = None,
) -> ResumeIsolationArtifact:
    if phenomenon == "checkpoint_resume_close_node":
        anomaly = detect_checkpoint_close_node_anomaly(post_resume)
    else:
        anomaly = detect_approval_halted_stale_anomaly(post_resume)

    return ResumeIsolationArtifact(
        phenomenon=phenomenon,
        verdict="REPRODUCED" if anomaly else "NOT_REPRODUCED",
        consecutive_passes=ISOLATION_PASSES,
        git_commit=git_head_short(),
        environment=isolation_environment(),
        pre_resume=pre_resume,
        post_resume=post_resume,
        anomaly_detail=anomaly,
        run_index=run_index,
    )


def assert_not_reproduced(artifact: ResumeIsolationArtifact) -> None:
    """Fail the test when an isolated probe reproduces a SUSPECTED anomaly."""
    if artifact.verdict == "REPRODUCED":
        raise AssertionError(
            f"{artifact.phenomenon} REPRODUCED on run {artifact.run_index}: "
            f"{artifact.anomaly_detail}\nartifact={json.dumps(artifact.to_dict(), indent=2)}"
        )


@dataclass
class IsolationRunRecord:
    run_index: int
    artifact: ResumeIsolationArtifact = field(repr=False)

    @property
    def passed(self) -> bool:
        return self.artifact.verdict == "NOT_REPRODUCED"


def summarize_consecutive_runs(records: list[IsolationRunRecord]) -> ResumeIsolationArtifact:
    """Collapse per-run records into one artifact after ``ISOLATION_PASSES`` runs."""
    if len(records) != ISOLATION_PASSES:
        raise ValueError(f"expected {ISOLATION_PASSES} runs, got {len(records)}")
    reproduced = [record for record in records if not record.passed]
    last = records[-1].artifact
    if reproduced:
        first_fail = reproduced[0].artifact
        return ResumeIsolationArtifact(
            phenomenon=last.phenomenon,
            verdict="REPRODUCED",
            consecutive_passes=len(records),
            git_commit=last.git_commit,
            environment=last.environment,
            pre_resume=first_fail.pre_resume,
            post_resume=first_fail.post_resume,
            anomaly_detail=first_fail.anomaly_detail,
            run_index=reproduced[0].run_index,
        )
    return ResumeIsolationArtifact(
        phenomenon=last.phenomenon,
        verdict="NOT_REPRODUCED",
        consecutive_passes=ISOLATION_PASSES,
        git_commit=last.git_commit,
        environment=last.environment,
        pre_resume=records[0].artifact.pre_resume,
        post_resume=last.post_resume,
        anomaly_detail=None,
        run_index=ISOLATION_PASSES,
    )
