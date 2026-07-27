"""Trajectory quality analyser (ISSUE-066).

Operates on the unified decision trace produced by ``DecisionTraceService``
and computes structured metrics plus human-readable findings for post-hoc
evaluation of multi-agent investigation efficiency.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.decision_trace import DecisionTraceEntry
from app.models.enums import DecisionTraceEntryType, TrajectoryMetric
from app.models.trajectory import TrajectoryReport
from app.services.decision_trace_service import DecisionTraceService

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Thresholds
# --------------------------------------------------------------------------- #

_DUPLICATE_TOOL_THRESHOLD = 3  # same tool+params called ≥N times → redundant
_LOOP_WINDOW = 5  # consecutive same-agent entries → suspected loop


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class TrajectoryAnalyzer:
    """Derive structured quality metrics from a ``DecisionTrace``."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def analyze(self, event_id: str) -> TrajectoryReport:
        """Produce a ``TrajectoryReport`` for *event_id*.

        Returns an empty report with ``insufficient_trace=True`` when the
        decision trace is unavailable or contains too few entries.
        """
        trace_service = DecisionTraceService(self._session_factory)
        try:
            trace = await trace_service.get_decision_trace(event_id)
        except Exception:
            logger.warning(
                "Failed to fetch decision trace for event=%s — returning insufficient",
                event_id,
                exc_info=True,
            )
            return TrajectoryReport(
                event_id=event_id,
                insufficient_trace=True,
            )

        if not trace.entries:
            logger.info("No decision trace entries for event=%s", event_id)
            return TrajectoryReport(
                event_id=event_id,
                insufficient_trace=True,
            )

        entries = trace.entries
        report = TrajectoryReport(
            event_id=event_id,
            total_steps=len(entries),
            agent_invocations=sum(
                1 for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
            ),
            tool_calls=sum(1 for e in entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL),
            llm_calls=sum(1 for e in entries if e.entry_type == DecisionTraceEntryType.LLM_CALL),
        )

        report.metrics = {
            TrajectoryMetric.REDUNDANT_TOOL_CALLS: _compute_redundant_tool_calls(entries),
            TrajectoryMetric.LOOP_SUSPECTED: _compute_loop_suspected(entries),
            TrajectoryMetric.REPLAN_EFFECTIVENESS: _compute_replan_effectiveness(entries),
            TrajectoryMetric.AVG_AGENT_LATENCY_MS: _compute_avg_agent_latency_ms(entries),
            TrajectoryMetric.EVIDENCE_YIELD: _compute_evidence_yield(entries),
            TrajectoryMetric.STEPS_TO_VERDICT: _compute_steps_to_verdict(entries),
        }

        report.findings = _generate_findings(report.metrics, entries)
        return report


# --------------------------------------------------------------------------- #
# Metric functions
# --------------------------------------------------------------------------- #


def _tool_fingerprint(entry: DecisionTraceEntry) -> str:
    """Stable fingerprint for a tool-call entry.

    Uses ``actor`` (tool_name) as the grouping key.  The decision-trace
    detail for tool calls does not include raw parameters, so the
    fingerprint relies on the tool identity alone.
    """
    return hashlib.sha256(entry.actor.encode()).hexdigest()


def _compute_redundant_tool_calls(entries: list[DecisionTraceEntry]) -> float:
    """Count tool calls where the same (tool_name, parameters) appears ≥3 times."""
    tool_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL]
    if not tool_entries:
        return 0.0

    fingerprints = [_tool_fingerprint(e) for e in tool_entries]
    counts = Counter(fingerprints)
    redundant = sum(c for c in counts.values() if c >= _DUPLICATE_TOOL_THRESHOLD)
    return float(redundant)


def _compute_loop_suspected(entries: list[DecisionTraceEntry]) -> float:
    """Detect consecutive repetitions of the same agent (suspected loop).

    Returns the length of the longest same-agent run within *_LOOP_WINDOW*.
    """
    agent_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION]
    if len(agent_entries) < _LOOP_WINDOW:
        return 0.0

    max_run = 0
    current_run = 1
    for i in range(1, len(agent_entries)):
        if agent_entries[i].actor == agent_entries[i - 1].actor:
            current_run += 1
        else:
            max_run = max(max_run, current_run)
            current_run = 1
    max_run = max(max_run, current_run)
    return float(max_run) if max_run >= _LOOP_WINDOW else 0.0


def _compute_replan_effectiveness(entries: list[DecisionTraceEntry]) -> float:
    """Measure whether a re-plan improved the outcome.

    Heuristic: look for agent_execution entries that follow a planner execution.
    If verification changed from 'failed' to 'success' after replanning, score 1.0.
    """
    agent_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION]
    planner_runs: list[DecisionTraceEntry] = []
    verify_runs: list[DecisionTraceEntry] = []

    for e in agent_entries:
        if "planner" in e.actor.lower():
            planner_runs.append(e)
        elif "verify" in e.actor.lower():
            verify_runs.append(e)

    if len(planner_runs) < 2 or len(verify_runs) < 2:
        return 0.0

    # Compare verification status before and after the *last* planner run.
    last_planner_idx = max(i for i, e in enumerate(agent_entries) if "planner" in e.actor.lower())
    pre_planner_verifies = [e for e in verify_runs if agent_entries.index(e) < last_planner_idx]
    post_planner_verifies = [e for e in verify_runs if agent_entries.index(e) > last_planner_idx]

    if not pre_planner_verifies or not post_planner_verifies:
        return 0.0

    pre_failed = any(
        e.detail.get("status", "") in ("failed", "error") for e in pre_planner_verifies
    )
    post_success = all(e.detail.get("status", "") == "success" for e in post_planner_verifies)
    return 1.0 if (pre_failed and post_success) else 0.0


def _compute_avg_agent_latency_ms(entries: list[DecisionTraceEntry]) -> float:
    """Average agent execution latency in milliseconds."""
    agent_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION]
    latencies = [e.detail.get("duration_ms", 0) or 0 for e in agent_entries]
    if not latencies:
        return 0.0
    return round(sum(latencies) / len(latencies), 1)


def _compute_evidence_yield(entries: list[DecisionTraceEntry]) -> float:
    """Evidence yield = effective evidence items / query calls.

    Effective evidence is the number of evidence-agent entries that have a
    non-empty evidence_list or collection_status=completed.
    """
    evidence_entries = [
        e
        for e in entries
        if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION and "evidence" in e.actor.lower()
    ]
    query_entries = [e for e in entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL]

    if not query_entries:
        return 0.0

    effective = sum(
        1
        for e in evidence_entries
        if e.detail.get("collection_status") == "completed" or e.detail.get("evidence_list")
    )
    return round(effective / len(query_entries), 2)


def _compute_steps_to_verdict(entries: list[DecisionTraceEntry]) -> float:
    """Total steps until the first final verdict is observed.

    Looks for state_transition entries where to_status is REPORTING or CLOSED.
    """
    terminal_statuses = {"reporting", "closed"}
    for i, e in enumerate(entries, start=1):
        if e.entry_type == DecisionTraceEntryType.STATE_TRANSITION:
            to_status = str(e.detail.get("to_status", "")).lower()
            if to_status in terminal_statuses:
                return float(i)
    return float(len(entries))


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _generate_findings(
    metrics: dict[str, float],
    entries: list[DecisionTraceEntry],
) -> list[str]:
    findings: list[str] = []

    redundant = metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0)
    if redundant > 0:
        findings.append(
            f"检测到 {int(redundant)} 次冗余工具调用"
            f"（相同工具+参数 ≥ {_DUPLICATE_TOOL_THRESHOLD} 次）"
        )

    loop = metrics.get(TrajectoryMetric.LOOP_SUSPECTED, 0)
    if loop > 0:
        findings.append(f"疑似循环：同一 Agent 连续执行 {int(loop)} 次（阈值 {_LOOP_WINDOW}）")

    replan = metrics.get(TrajectoryMetric.REPLAN_EFFECTIVENESS, 0)
    if replan > 0:
        findings.append("重规划有效：Verification 由失败转为成功")
    else:
        planner_count = sum(1 for e in entries if "planner" in e.actor.lower())
        if planner_count >= 2:
            findings.append("重规划未带来改善：多次规划但 Verification 未恢复")

    evidence_yield = metrics.get(TrajectoryMetric.EVIDENCE_YIELD, 0)
    if evidence_yield < 0.5:
        findings.append(f"证据产出率偏低（{evidence_yield:.2f}），大量查询未产生有效证据")

    steps = metrics.get(TrajectoryMetric.STEPS_TO_VERDICT, 0)
    total = len(entries)
    if steps >= total and total > 0:
        findings.append("未检测到终态（REPORTING/CLOSED），研判可能未完成")

    if not findings:
        findings.append("轨迹分析未发现异常")

    return findings


__all__ = ["TrajectoryAnalyzer"]
