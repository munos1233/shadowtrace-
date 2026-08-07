"""Celery application factory (ISSUE-056).

Broker and result backend default to ``CELERY_BROKER_URL`` (falling back to
``REDIS_URL``). Investigation tasks route to the ``investigation`` queue.
"""

from __future__ import annotations

import asyncio
import logging

from celery import Celery
from celery.signals import worker_process_init, worker_process_shutdown

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _resolve_broker_url() -> str:
    settings = get_settings()
    broker = (settings.celery_broker_url or "").strip()
    return broker or settings.redis_url


def init_worker_telemetry(**kwargs: object) -> None:
    """Bootstrap SessionProvider + OpenTelemetry in each Celery child (ISSUE-118/092).

    Also installs ``RedactingFormatter`` on the ``app`` package logger so
    that Celery worker log output receives the same credential redaction
    as the API process (ISSUE-223).
    """
    del kwargs
    from app.core.sanitization import configure_app_logging
    from app.core.telemetry import setup_telemetry
    from app.db.session_provider import init_worker_session_provider

    configure_app_logging()
    # ISSUE-223 (P1): Celery's worker_hijack_root_logger=True installs a root
    # logger handler that has no RedactingFormatter.  If propagate stays True
    # (Python default), every log record emitted by an "app" logger also reaches
    # the Celery root handler *unredacted*, leaking credentials to stderr.
    # Turning off propagation keeps the redacted StreamHandler as the sole
    # output path for app loggers.
    logging.getLogger("app").propagate = False
    provider = init_worker_session_provider()
    setup_telemetry(engine=provider.engine())
    logger.debug("Celery worker session provider + telemetry initialized")


def shutdown_worker_resources(**kwargs: object) -> None:
    """Dispose loop-bound worker resources on process shutdown (ISSUE-118/138)."""
    del kwargs
    from app.core.embedding.factory import close_embedding_client
    from app.db.session_provider import dispose_session_provider
    from app.playbook.resources import reset_playbook_resources_cache
    from app.rag.resources import reset_loaded_retrieval_resources

    asyncio.run(dispose_session_provider())
    asyncio.run(close_embedding_client())
    reset_loaded_retrieval_resources()
    reset_playbook_resources_cache()
    logger.debug("Celery worker session provider + retrieval resources disposed")


def shutdown_worker_session_provider(**kwargs: object) -> None:
    """Backward-compatible alias for worker shutdown hook."""
    shutdown_worker_resources(**kwargs)


worker_process_init.connect(init_worker_telemetry, weak=False)
worker_process_shutdown.connect(shutdown_worker_resources, weak=False)

celery_app = Celery("shadowtrace")


def _build_beat_schedule() -> dict[str, dict[str, object]]:
    settings = get_settings()
    schedule: dict[str, dict[str, object]] = {}
    if settings.ingestion_scheduler_enabled:
        schedule["shadowtrace-poll-sources"] = {
            "task": "shadowtrace.poll_sources",
            "schedule": float(settings.ingestion_poll_interval_s),
            "options": {"queue": "ingestion"},
        }
    if settings.auto_investigate_enabled:
        schedule["shadowtrace-dispatch-investigation-intents"] = {
            "task": "shadowtrace.dispatch_investigation_intents",
            "schedule": float(settings.auto_investigate_dispatch_interval_s),
            "options": {"queue": "investigation"},
        }
        schedule["shadowtrace-reconcile-investigation-intents"] = {
            "task": "shadowtrace.reconcile_investigation_intents",
            "schedule": float(settings.auto_investigate_reconcile_interval_s),
            "options": {"queue": "investigation"},
        }
    if settings.behavior_observation_retry_enabled:
        schedule["shadowtrace-behavior-observation-retry-pending"] = {
            "task": "shadowtrace.behavior_observation.retry_pending",
            "schedule": float(settings.behavior_observation_retry_interval_s),
            "options": {"queue": "ingestion"},
        }
    if settings.detection_governance_expire_enabled:
        schedule["shadowtrace-detection-governance-expire"] = {
            "task": "shadowtrace.detection_governance.expire_active_approvals",
            "schedule": float(settings.detection_governance_expire_interval_s),
            "options": {"queue": "investigation"},
        }
    if settings.action_execution_reconcile_enabled:
        schedule["shadowtrace-reconcile-stale-executions"] = {
            "task": "shadowtrace.reconcile_stale_executions",
            "schedule": float(settings.action_execution_reconcile_interval_s),
            "options": {"queue": "investigation"},
        }
    return schedule


celery_app.conf.update(
    broker_url=_resolve_broker_url(),
    result_backend=_resolve_broker_url(),
    task_default_queue="investigation",
    task_routes={
        "shadowtrace.run_investigation": {"queue": "investigation"},
        "shadowtrace.worker_ping": {"queue": "investigation"},
        "shadowtrace.poll_sources": {"queue": "ingestion"},
        "shadowtrace.dispatch_investigation_intents": {"queue": "investigation"},
        "shadowtrace.reconcile_investigation_intents": {"queue": "investigation"},
        "shadowtrace.behavior_observation.retry_pending": {"queue": "ingestion"},
        "shadowtrace.detection_governance.expire_active_approvals": {"queue": "investigation"},
        "shadowtrace.reconcile_stale_executions": {"queue": "investigation"},
    },
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=600,
    worker_prefetch_multiplier=1,
    broker_transport_options={
        "visibility_timeout": 900,
    },
    beat_schedule=_build_beat_schedule(),
    imports=(
        "app.tasks.investigation_tasks",
        "app.tasks.investigation_intent_tasks",
        "app.tasks.worker_tasks",
        "app.tasks.ingestion_tasks",
        "app.tasks.behavior_observation_tasks",
        "app.tasks.detection_governance_tasks",
        "app.tasks.action_execution_tasks",
    ),
)

__all__ = [
    "celery_app",
    "init_worker_telemetry",
    "shutdown_worker_resources",
    "shutdown_worker_session_provider",
]
