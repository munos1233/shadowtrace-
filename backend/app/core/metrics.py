"""Business metrics for disposition / writeback observability (ISSUE-092).

Label dimensions are intentionally low-cardinality: ``status``, ``adapter``, and
bounded ``error_code`` buckets for dead-letter metrics only. Never attach
``source_object_id``, IP addresses, or raw payloads.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core import telemetry

logger = logging.getLogger(__name__)

_meter: Any | None = None
_writeback_total: Any | None = None
_writeback_queue_age: Any | None = None
_writeback_retry_total: Any | None = None
_writeback_dead_letter_total: Any | None = None
_action_unknown_total: Any | None = None
_checkpoint_fallback_total: Any | None = None
_checkpoint_memory_fallback_gauge: Any | None = None
_checkpoint_loop_rebind_total: Any | None = None
_budget_redis_fallback_total: Any | None = None
_budget_redis_recovery_total: Any | None = None
_budget_redis_degraded_gauge: Any | None = None
_state_projection_failure_total: Any | None = None
_state_projection_repair_total: Any | None = None
_investigation_intent_enqueue_total: Any | None = None
_graph_failed_transition_noop_total: Any | None = None
_socketio_subscriber_failure_total: Any | None = None
_socketio_subscriber_recovery_total: Any | None = None
_force_close_total: Any | None = None
_initialized = False
_process_checkpoint_fallback_active = False
_process_checkpoint_fallback_triggers = 0
_process_checkpoint_loop_rebinds = 0
_process_budget_redis_degraded = False
_process_reservation_redis_degraded = False
_process_state_projection_failures = 0
_process_state_projection_repairs = 0
_process_investigation_intent_enqueue_success = 0
_process_investigation_intent_enqueue_failure = 0
_process_socketio_subscriber_failures = 0
_process_socketio_subscriber_recoveries = 0


def _ensure_metrics() -> None:
    global _meter, _writeback_total, _writeback_queue_age, _writeback_retry_total
    global _writeback_dead_letter_total, _action_unknown_total, _checkpoint_fallback_total
    global _checkpoint_memory_fallback_gauge, _checkpoint_loop_rebind_total
    global _budget_redis_fallback_total
    global _budget_redis_recovery_total, _budget_redis_degraded_gauge, _initialized
    global _state_projection_failure_total, _state_projection_repair_total
    global _investigation_intent_enqueue_total, _graph_failed_transition_noop_total
    global _socketio_subscriber_failure_total, _socketio_subscriber_recovery_total
    global _force_close_total

    if not telemetry.is_telemetry_enabled():
        return
    if _initialized:
        return

    try:
        _meter = telemetry.get_meter("shadowtrace.metrics")
        _writeback_total = _meter.create_counter(
            name="shadowtrace_writeback_total",
            description="Disposition writeback terminal outcomes",
            unit="1",
        )
        _writeback_queue_age = _meter.create_histogram(
            name="shadowtrace_writeback_queue_age_seconds",
            description="Age of outbox rows when claimed for delivery",
            unit="s",
        )
        _writeback_retry_total = _meter.create_counter(
            name="shadowtrace_writeback_retry_total",
            description="Writeback delivery retries and manual re-enqueues",
            unit="1",
        )
        _writeback_dead_letter_total = _meter.create_counter(
            name="shadowtrace_writeback_dead_letter_total",
            description="Outbox rows moved to DEAD_LETTER after max delivery attempts",
            unit="1",
        )
        _action_unknown_total = _meter.create_counter(
            name="shadowtrace_action_unknown_total",
            description="Actions promoted to UNKNOWN after writeback ambiguity",
            unit="1",
        )
        _checkpoint_fallback_total = _meter.create_counter(
            name="shadowtrace_checkpoint_fallback_total",
            description="LangGraph checkpoint Redis failures that triggered memory fallback",
            unit="1",
        )
        _checkpoint_memory_fallback_gauge = _meter.create_up_down_counter(
            name="shadowtrace_checkpoint_memory_fallback",
            description="1 when any checkpointer in this process uses memory fallback, else 0",
            unit="1",
        )
        _checkpoint_loop_rebind_total = _meter.create_counter(
            name="shadowtrace_checkpoint_loop_rebind_total",
            description="Checkpoint Redis ops recovered by rebinding to the current event loop",
            unit="1",
        )
        _budget_redis_fallback_total = _meter.create_counter(
            name="shadowtrace_budget_redis_fallback_total",
            description="Budget/reservation Redis failures that triggered in-process fallback",
            unit="1",
        )
        _budget_redis_recovery_total = _meter.create_counter(
            name="shadowtrace_budget_redis_recovery_total",
            description="Budget/reservation Redis recovery probes that cleared degraded state",
            unit="1",
        )
        _budget_redis_degraded_gauge = _meter.create_up_down_counter(
            name="shadowtrace_budget_redis_degraded",
            description="1 when a budget/reservation service is in Redis degraded mode, else 0",
            unit="1",
        )
        _state_projection_failure_total = _meter.create_counter(
            name="shadowtrace_state_projection_failure_total",
            description="Post-commit state projection failures by step and failure mode",
            unit="1",
        )
        _state_projection_repair_total = _meter.create_counter(
            name="shadowtrace_state_projection_repair_total",
            description="Bounded post-commit state projection repair outcomes",
            unit="1",
        )
        _investigation_intent_enqueue_total = _meter.create_counter(
            name="shadowtrace_investigation_intent_enqueue_total",
            description="Best-effort Celery dispatch trigger outcomes for pending intents",
            unit="1",
        )
        _graph_failed_transition_noop_total = _meter.create_counter(
            name="shadowtrace_graph_failed_transition_noop_total",
            description=(
                "Bounded no-op outcomes when graph failure marking would duplicate terminal state"
            ),
            unit="1",
        )
        _socketio_subscriber_failure_total = _meter.create_counter(
            name="shadowtrace_socketio_subscriber_failure_total",
            description="Socket.IO Redis subscriber failures by retry phase",
            unit="1",
        )
        _socketio_subscriber_recovery_total = _meter.create_counter(
            name="shadowtrace_socketio_subscriber_recovery_total",
            description="Socket.IO Redis subscriber recovery outcomes",
            unit="1",
        )
        _force_close_total = _meter.create_counter(
            name="shadowtrace_force_close_total",
            description="Admin force_close attempts by outcome",
            unit="1",
        )
    except Exception:
        logger.debug("Business metric registration failed", exc_info=True)
    _initialized = True


def record_writeback(*, status: str, adapter: str) -> None:
    """Increment ``shadowtrace_writeback_total{status,adapter}``."""
    _ensure_metrics()
    if _writeback_total is None:
        return
    try:
        _writeback_total.add(1, {"status": status, "adapter": adapter})
    except Exception:
        logger.debug("writeback metric export failed", exc_info=True)


def observe_writeback_queue_age(seconds: float) -> None:
    """Record outbox queue age in seconds."""
    _ensure_metrics()
    if _writeback_queue_age is None:
        return
    try:
        _writeback_queue_age.record(max(0.0, seconds))
    except Exception:
        logger.debug("queue age metric export failed", exc_info=True)


def record_writeback_retry(*, adapter: str) -> None:
    """Increment ``shadowtrace_writeback_retry_total{adapter}``."""
    _ensure_metrics()
    if _writeback_retry_total is None:
        return
    try:
        _writeback_retry_total.add(1, {"adapter": adapter})
    except Exception:
        logger.debug("writeback retry metric export failed", exc_info=True)


def record_writeback_dead_letter(*, adapter: str, error_code: str | None = None) -> None:
    """Increment ``shadowtrace_writeback_dead_letter_total{adapter,error_code?}``."""
    from app.adapters.disposition.error_classification import bounded_dead_letter_error_code

    _ensure_metrics()
    if _writeback_dead_letter_total is None:
        return
    labels: dict[str, str] = {"adapter": adapter}
    if error_code is not None:
        labels["error_code"] = bounded_dead_letter_error_code(error_code)
    try:
        _writeback_dead_letter_total.add(1, labels)
    except Exception:
        logger.debug("writeback dead letter metric export failed", exc_info=True)


def record_action_unknown(*, adapter: str = "unknown") -> None:
    """Increment ``shadowtrace_action_unknown_total``."""
    _ensure_metrics()
    if _action_unknown_total is None:
        return
    try:
        _action_unknown_total.add(1, {"adapter": adapter})
    except Exception:
        logger.debug("action unknown metric export failed", exc_info=True)


def record_checkpoint_fallback(*, reason: str) -> None:
    """Increment checkpoint fallback counter and process trigger tally."""
    global _process_checkpoint_fallback_triggers
    _process_checkpoint_fallback_triggers += 1
    _ensure_metrics()
    if _checkpoint_fallback_total is None:
        return
    try:
        _checkpoint_fallback_total.add(1, {"reason": reason})
    except Exception:
        logger.debug("checkpoint fallback metric export failed", exc_info=True)


def record_checkpoint_loop_rebind(*, op: str) -> None:
    """Increment counter when checkpoint Redis recovers via event-loop rebind."""
    global _process_checkpoint_loop_rebinds
    _process_checkpoint_loop_rebinds += 1
    _ensure_metrics()
    if _checkpoint_loop_rebind_total is None:
        return
    try:
        _checkpoint_loop_rebind_total.add(1, {"op": op})
    except Exception:
        logger.debug("checkpoint loop rebind metric export failed", exc_info=True)


def set_checkpoint_memory_fallback(active: bool) -> None:
    """Set process-wide checkpoint memory fallback gauge (0/1)."""
    global _process_checkpoint_fallback_active
    if active == _process_checkpoint_fallback_active:
        return
    _process_checkpoint_fallback_active = active
    _ensure_metrics()
    if _checkpoint_memory_fallback_gauge is None:
        return
    try:
        delta = 1 if active else -1
        _checkpoint_memory_fallback_gauge.add(delta)
    except Exception:
        logger.debug("checkpoint memory fallback gauge export failed", exc_info=True)


def checkpoint_health_snapshot() -> dict[str, int | bool]:
    """Low-cardinality checkpoint observability for health probes."""
    return {
        "memory_fallback": _process_checkpoint_fallback_active,
        "fallback_triggers": _process_checkpoint_fallback_triggers,
        "loop_rebinds": _process_checkpoint_loop_rebinds,
    }


def record_budget_redis_fallback(*, service: str, op: str) -> None:
    """Increment budget/reservation Redis fallback counter."""
    _ensure_metrics()
    if _budget_redis_fallback_total is None:
        return
    try:
        _budget_redis_fallback_total.add(1, {"service": service, "op": op})
    except Exception:
        logger.debug("budget redis fallback metric export failed", exc_info=True)


def record_budget_redis_recovery(*, service: str) -> None:
    """Increment budget/reservation Redis recovery counter."""
    _ensure_metrics()
    if _budget_redis_recovery_total is None:
        return
    try:
        _budget_redis_recovery_total.add(1, {"service": service})
    except Exception:
        logger.debug("budget redis recovery metric export failed", exc_info=True)


def set_budget_redis_degraded(*, service: str, active: bool) -> None:
    """Set per-service budget Redis degraded gauge (0/1)."""
    global _process_budget_redis_degraded, _process_reservation_redis_degraded
    if service == "budget":
        if active == _process_budget_redis_degraded:
            return
        _process_budget_redis_degraded = active
    elif service == "reservation":
        if active == _process_reservation_redis_degraded:
            return
        _process_reservation_redis_degraded = active
    else:
        return
    _ensure_metrics()
    if _budget_redis_degraded_gauge is None:
        return
    try:
        delta = 1 if active else -1
        _budget_redis_degraded_gauge.add(delta, {"service": service})
    except Exception:
        logger.debug("budget redis degraded gauge export failed", exc_info=True)


def budget_redis_health_snapshot() -> dict[str, bool]:
    """Process-wide budget/reservation Redis degraded flags for health/tests."""
    return {
        "budget_redis_degraded": _process_budget_redis_degraded,
        "reservation_redis_degraded": _process_reservation_redis_degraded,
    }


def record_state_projection_failure(*, step: str, mode: str) -> None:
    """Record a low-cardinality post-commit projection failure."""
    global _process_state_projection_failures
    _process_state_projection_failures += 1
    _ensure_metrics()
    if _state_projection_failure_total is None:
        return
    try:
        _state_projection_failure_total.add(1, {"step": step, "mode": mode})
    except Exception:
        logger.debug("state projection failure metric export failed", exc_info=True)


def record_state_projection_repair(*, outcome: str) -> None:
    """Record a bounded repair outcome (``success`` or ``exhausted``)."""
    global _process_state_projection_repairs
    _process_state_projection_repairs += 1
    _ensure_metrics()
    if _state_projection_repair_total is None:
        return
    try:
        _state_projection_repair_total.add(1, {"outcome": outcome})
    except Exception:
        logger.debug("state projection repair metric export failed", exc_info=True)


def state_projection_health_snapshot() -> dict[str, int]:
    """Process-local counters for health probes and deterministic tests."""
    return {
        "projection_failures": _process_state_projection_failures,
        "projection_repairs": _process_state_projection_repairs,
    }


def get_budget_redis_health() -> dict[str, object]:
    """Process-wide budget/reservation Redis readiness for health probes (ISSUE-174)."""
    from app.core.config import get_settings

    snapshot = budget_redis_health_snapshot()
    settings = get_settings()
    degraded = snapshot["budget_redis_degraded"] or snapshot["reservation_redis_degraded"]
    return {
        "status": "degraded" if degraded else "ok",
        "budget_redis_degraded": snapshot["budget_redis_degraded"],
        "reservation_redis_degraded": snapshot["reservation_redis_degraded"],
        "redis_recovery_enabled": settings.budget_attempt_redis_recovery,
    }


def get_state_projection_health() -> dict[str, object]:
    """Process-local post-commit projection failure/repair counters (ISSUE-285)."""
    snapshot = state_projection_health_snapshot()
    degraded = snapshot["projection_failures"] > snapshot["projection_repairs"]
    return {
        "status": "degraded" if degraded else "ok",
        "projection_failures": snapshot["projection_failures"],
        "projection_repairs": snapshot["projection_repairs"],
    }


def record_force_close(*, result: str) -> None:
    """Increment ``shadowtrace_force_close_total{result=success|denied}``."""
    normalized = result.strip().lower()
    if normalized not in {"success", "denied"}:
        return
    _ensure_metrics()
    if _force_close_total is None:
        return
    try:
        _force_close_total.add(1, {"result": normalized})
    except Exception:
        logger.debug("force_close metric export failed", exc_info=True)


def record_investigation_intent_enqueue(*, result: str) -> None:
    """Increment ``shadowtrace_investigation_intent_enqueue_total{result=...}``."""
    global \
        _process_investigation_intent_enqueue_success, \
        _process_investigation_intent_enqueue_failure
    normalized = result.strip().lower()
    if normalized == "success":
        _process_investigation_intent_enqueue_success += 1
    elif normalized == "failure":
        _process_investigation_intent_enqueue_failure += 1
    else:
        return
    _ensure_metrics()
    if _investigation_intent_enqueue_total is None:
        return
    try:
        _investigation_intent_enqueue_total.add(1, {"result": normalized})
    except Exception:
        logger.debug("investigation intent enqueue metric export failed", exc_info=True)


def record_graph_failed_transition_noop(*, reason: str) -> None:
    """Increment bounded no-op counter when graph failure marking is skipped."""
    _ensure_metrics()
    if _graph_failed_transition_noop_total is None:
        return
    try:
        _graph_failed_transition_noop_total.add(1, {"reason": reason})
    except Exception:
        logger.debug("graph failed transition noop metric export failed", exc_info=True)


def investigation_intent_enqueue_health_snapshot() -> dict[str, int]:
    """Process-local enqueue counters for health probes and deterministic tests."""
    return {
        "enqueue_success": _process_investigation_intent_enqueue_success,
        "enqueue_failure": _process_investigation_intent_enqueue_failure,
    }


def get_investigation_intent_enqueue_health() -> dict[str, object]:
    """Process-local investigation intent dispatch trigger observability (ISSUE-291)."""
    snapshot = investigation_intent_enqueue_health_snapshot()
    degraded = snapshot["enqueue_failure"] > 0 and snapshot["enqueue_success"] == 0
    return {
        "status": "degraded" if degraded else "ok",
        "enqueue_success": snapshot["enqueue_success"],
        "enqueue_failure": snapshot["enqueue_failure"],
    }


def record_socketio_subscriber_failure(*, reason: str) -> None:
    """Record a Socket.IO Redis subscriber failure (``subscriber_error`` or ``recovery_backoff``)."""
    global _process_socketio_subscriber_failures
    _process_socketio_subscriber_failures += 1
    _ensure_metrics()
    if _socketio_subscriber_failure_total is None:
        return
    try:
        _socketio_subscriber_failure_total.add(1, {"reason": reason})
    except Exception:
        logger.debug("socketio subscriber failure metric export failed", exc_info=True)


def record_socketio_subscriber_recovery(*, outcome: str) -> None:
    """Record a Socket.IO subscriber recovery (``reconnected``)."""
    global _process_socketio_subscriber_recoveries
    _process_socketio_subscriber_recoveries += 1
    _ensure_metrics()
    if _socketio_subscriber_recovery_total is None:
        return
    try:
        _socketio_subscriber_recovery_total.add(1, {"outcome": outcome})
    except Exception:
        logger.debug("socketio subscriber recovery metric export failed", exc_info=True)


def socketio_subscriber_health_snapshot() -> dict[str, int]:
    """Process-local Socket.IO subscriber counters for health probes and tests (ISSUE-298)."""
    return {
        "subscriber_failures": _process_socketio_subscriber_failures,
        "subscriber_recoveries": _process_socketio_subscriber_recoveries,
    }


def reset_socketio_subscriber_metrics_for_tests() -> None:
    """Reset Socket.IO subscriber process counters."""
    global _process_socketio_subscriber_failures, _process_socketio_subscriber_recoveries
    _process_socketio_subscriber_failures = 0
    _process_socketio_subscriber_recoveries = 0


def reset_metrics_for_tests() -> None:
    """Allow tests to re-register instruments after telemetry reset."""
    global _meter, _writeback_total, _writeback_queue_age, _writeback_retry_total
    global _writeback_dead_letter_total, _action_unknown_total, _checkpoint_fallback_total
    global _checkpoint_memory_fallback_gauge, _checkpoint_loop_rebind_total
    global _budget_redis_fallback_total
    global _budget_redis_recovery_total, _budget_redis_degraded_gauge, _initialized
    global _state_projection_failure_total, _state_projection_repair_total
    global _investigation_intent_enqueue_total, _graph_failed_transition_noop_total
    global _socketio_subscriber_failure_total, _socketio_subscriber_recovery_total
    global _process_checkpoint_fallback_active, _process_checkpoint_fallback_triggers
    global _process_checkpoint_loop_rebinds
    global _process_budget_redis_degraded, _process_reservation_redis_degraded
    global _process_state_projection_failures, _process_state_projection_repairs
    global \
        _process_investigation_intent_enqueue_success, \
        _process_investigation_intent_enqueue_failure
    global _process_socketio_subscriber_failures, _process_socketio_subscriber_recoveries
    _meter = None
    _writeback_total = None
    _writeback_queue_age = None
    _writeback_retry_total = None
    _writeback_dead_letter_total = None
    _action_unknown_total = None
    _checkpoint_fallback_total = None
    _checkpoint_memory_fallback_gauge = None
    _checkpoint_loop_rebind_total = None
    _budget_redis_fallback_total = None
    _budget_redis_recovery_total = None
    _budget_redis_degraded_gauge = None
    _state_projection_failure_total = None
    _state_projection_repair_total = None
    _investigation_intent_enqueue_total = None
    _graph_failed_transition_noop_total = None
    _socketio_subscriber_failure_total = None
    _socketio_subscriber_recovery_total = None
    _initialized = False
    _process_checkpoint_fallback_active = False
    _process_checkpoint_fallback_triggers = 0
    _process_checkpoint_loop_rebinds = 0
    _process_budget_redis_degraded = False
    _process_reservation_redis_degraded = False
    _process_state_projection_failures = 0
    _process_state_projection_repairs = 0
    _process_investigation_intent_enqueue_success = 0
    _process_investigation_intent_enqueue_failure = 0
    _process_socketio_subscriber_failures = 0
    _process_socketio_subscriber_recoveries = 0


def reset_investigation_intent_enqueue_metrics_for_tests() -> None:
    """Reset only investigation intent enqueue process counters."""
    global \
        _process_investigation_intent_enqueue_success, \
        _process_investigation_intent_enqueue_failure
    _process_investigation_intent_enqueue_success = 0
    _process_investigation_intent_enqueue_failure = 0


def reset_checkpoint_metrics_for_tests() -> None:
    """Reset only checkpoint metric process counters (alias for tests)."""
    global _process_checkpoint_fallback_active, _process_checkpoint_fallback_triggers
    global _process_checkpoint_loop_rebinds
    _process_checkpoint_fallback_active = False
    _process_checkpoint_fallback_triggers = 0
    _process_checkpoint_loop_rebinds = 0


def reset_budget_redis_metrics_for_tests() -> None:
    """Reset only budget/reservation Redis metric process counters."""
    global _process_budget_redis_degraded, _process_reservation_redis_degraded
    _process_budget_redis_degraded = False
    _process_reservation_redis_degraded = False


__all__ = [
    "budget_redis_health_snapshot",
    "checkpoint_health_snapshot",
    "get_budget_redis_health",
    "get_investigation_intent_enqueue_health",
    "get_state_projection_health",
    "investigation_intent_enqueue_health_snapshot",
    "observe_writeback_queue_age",
    "record_action_unknown",
    "record_budget_redis_fallback",
    "record_budget_redis_recovery",
    "record_checkpoint_fallback",
    "record_checkpoint_loop_rebind",
    "record_force_close",
    "record_graph_failed_transition_noop",
    "record_investigation_intent_enqueue",
    "record_state_projection_failure",
    "record_state_projection_repair",
    "record_writeback",
    "record_writeback_retry",
    "record_writeback_dead_letter",
    "reset_budget_redis_metrics_for_tests",
    "reset_checkpoint_metrics_for_tests",
    "reset_investigation_intent_enqueue_metrics_for_tests",
    "reset_metrics_for_tests",
    "set_budget_redis_degraded",
    "set_checkpoint_memory_fallback",
    "state_projection_health_snapshot",
]
