"""Application settings (pydantic-settings)."""

import os
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.errors import ConfigurationError
from app.models.workflow import AUTO_APPROVABLE_ACTION_LEVELS, parse_action_level_label


def _looks_mock(value: str) -> bool:
    return "mock" in value.strip().lower()


class Settings(BaseSettings):
    """Runtime configuration. Defaults target Docker Compose service names."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    app_env: str = Field(default="development", alias="APP_ENV")
    trusted_auth_proxy_enabled: bool = Field(
        default=False,
        alias="TRUSTED_AUTH_PROXY_ENABLED",
    )
    trusted_proxy_allowlist: str = Field(default="", alias="TRUSTED_PROXY_ALLOWLIST")

    database_url: str = Field(
        default="postgresql+asyncpg://shadowtrace:shadowtrace@postgres:5432/shadowtrace",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")

    opensearch_enabled: bool = Field(default=False, alias="OPENSEARCH_ENABLED")
    opensearch_url: str = Field(default="http://opensearch:9200", alias="OPENSEARCH_URL")
    opensearch_index_prefix: str = Field(default="shadowtrace", alias="OPENSEARCH_INDEX_PREFIX")

    source_mode: str = Field(default="mock_xdr", alias="SOURCE_MODE")
    source_read_only: bool = Field(default=True, alias="SOURCE_READ_ONLY")

    tool_mode: str = Field(default="mock", alias="TOOL_MODE")

    disposition_mode: str = Field(default="mock_xdr", alias="DISPOSITION_MODE")
    disposition_adapter_kind: str = Field(default="mock", alias="DISPOSITION_ADAPTER_KIND")
    disposition_base_url: str = Field(default="", alias="DISPOSITION_BASE_URL")
    disposition_credential_ref: str = Field(default="", alias="DISPOSITION_CREDENTIAL_REF")

    allow_xdr_writeback: bool = Field(default=False, alias="ALLOW_XDR_WRITEBACK")
    allow_live_side_effects: bool = Field(default=False, alias="ALLOW_LIVE_SIDE_EFFECTS")
    writeback_field_allowlist: str = Field(
        default="status,disposition,comment",
        alias="WRITEBACK_FIELD_ALLOWLIST",
    )
    writeback_max_retries: int = Field(default=5, alias="WRITEBACK_MAX_RETRIES")
    writeback_lookup_poll_interval_s: float = Field(
        default=1.0, alias="WRITEBACK_LOOKUP_POLL_INTERVAL_S"
    )
    simulation_enabled: bool = Field(default=True, alias="SIMULATION_ENABLED")

    llm_mode: str = Field(default="mock", alias="LLM_MODE")
    llm_api_base_url: str = Field(default="", alias="LLM_API_BASE_URL")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")
    llm_primary_model: str = Field(default="mock-model", alias="LLM_PRIMARY_MODEL")
    llm_fallback_models: str = Field(default="", alias="LLM_FALLBACK_MODELS")
    llm_timeout_seconds: int = Field(default=30, alias="LLM_TIMEOUT_SECONDS")
    llm_probe_enabled: bool = Field(default=False, alias="LLM_PROBE_ENABLED")
    llm_probe_ttl_seconds: int = Field(default=60, alias="LLM_PROBE_TTL_SECONDS")
    llm_probe_method: str = Field(default="chat", alias="LLM_PROBE_METHOD")
    llm_required: bool = Field(default=False, alias="LLM_REQUIRED")
    triage_llm_event_type_fallback: bool = Field(
        default=False,
        alias="TRIAGE_LLM_EVENT_TYPE_FALLBACK",
        description=(
            "When true, adopt validated LLM event_type only if source+heuristic "
            "both resolve to OTHER (ISSUE-197)."
        ),
    )
    triage_rewrite_event_type: bool = Field(
        default=True,
        alias="TRIAGE_REWRITE_EVENT_TYPE",
        description=(
            "When true, after triage persists triage_result, rewrite "
            "SecurityEvent.event_type so list/detail match (ISSUE-211). "
            "Skipped during EXECUTING_RESPONSE/VERIFYING without 409."
        ),
    )
    report_quality_gate_enforced: bool = Field(
        default=True,
        alias="REPORT_QUALITY_GATE_ENFORCED",
        description=(
            "When true, POST /events/{id}/report rejects incomplete_placeholder "
            "reports unless force=true (ISSUE-212). When false, warn only."
        ),
    )
    llm_audit_window_minutes: int = Field(default=60, alias="LLM_AUDIT_WINDOW_MINUTES")
    event_chat_enabled: bool = Field(default=True, alias="EVENT_CHAT_ENABLED")
    decision_rationale_mode: str = Field(
        default="structured",
        alias="DECISION_RATIONALE_MODE",
        description=(
            "ISSUE-243: off|structured|short_text. Structured decision briefs are "
            "always synthesized; short_text may add a bounded redacted fallback "
            "into decision basis (never restores CoT keys). Production forbids "
            "short_text."
        ),
    )

    @field_validator("llm_probe_method", mode="before")
    @classmethod
    def validate_llm_probe_method(cls, value: object) -> str:
        normalized = str(value or "chat").strip().lower()
        if normalized not in {"chat", "models"}:
            raise ValueError("LLM_PROBE_METHOD must be 'chat' or 'models'")
        return normalized

    @field_validator("decision_rationale_mode", mode="before")
    @classmethod
    def validate_decision_rationale_mode(cls, value: object) -> str:
        normalized = str(value or "structured").strip().lower()
        if normalized not in {"off", "structured", "short_text"}:
            raise ValueError("DECISION_RATIONALE_MODE must be 'off', 'structured', or 'short_text'")
        return normalized

    embedding_mode: str = Field(default="mock", alias="EMBEDDING_MODE")
    embedding_api_base_url: str = Field(default="", alias="EMBEDDING_API_BASE_URL")
    embedding_api_key: str = Field(default="", alias="EMBEDDING_API_KEY")
    embedding_model_id: str = Field(default="mock-embedder", alias="EMBEDDING_MODEL_ID")
    embedding_release_id: str = Field(default="mock-v1", alias="EMBEDDING_RELEASE_ID")
    embedding_dimension: int = Field(default=1024, alias="EMBEDDING_DIMENSION")
    embedding_distance_metric: str = Field(default="cosine", alias="EMBEDDING_DISTANCE_METRIC")
    embedding_normalization: str = Field(default="unit_l2", alias="EMBEDDING_NORMALIZATION")
    embedding_content_schema_version: str = Field(
        default="1", alias="EMBEDDING_CONTENT_SCHEMA_VERSION"
    )
    embedding_preprocess_schema_version: str = Field(
        default="1",
        alias="EMBEDDING_PREPROCESS_SCHEMA_VERSION",
    )
    embedding_config_hash: str = Field(default="", alias="EMBEDDING_CONFIG_HASH")
    embedding_max_batch_size: int = Field(default=64, alias="EMBEDDING_MAX_BATCH_SIZE")
    embedding_timeout_seconds: float = Field(default=30.0, alias="EMBEDDING_TIMEOUT_SECONDS")

    rerank_mode: str = Field(default="mock", alias="RERANK_MODE")

    retrieval_default_tenant_id: str = Field(default="local", alias="RETRIEVAL_DEFAULT_TENANT_ID")
    retrieval_fixture_fallback: bool = Field(default=False, alias="RETRIEVAL_FIXTURE_FALLBACK")
    playbook_fixture_fallback: bool = Field(default=False, alias="PLAYBOOK_FIXTURE_FALLBACK")
    playbook_release_require_active: bool = Field(
        default=False,
        alias="PLAYBOOK_RELEASE_REQUIRE_ACTIVE",
        description="When true, playbook_kb retrieval requires an active playbook release",
    )
    knowledge_release_require_active: bool = Field(
        default=False,
        alias="KNOWLEDGE_RELEASE_REQUIRE_ACTIVE",
        description="When true, attack_kb retrieval requires an active knowledge release",
    )

    tool_call_compatibility_path_enabled: bool = Field(
        default=True,
        alias="TOOL_CALL_COMPATIBILITY_PATH_ENABLED",
        description="Enable named compatibility path for fixed Evidence queries",
    )
    tool_call_grant_required: bool = Field(
        default=False,
        alias="TOOL_CALL_GRANT_REQUIRED",
        description="When true, ReAct dynamic tool calls require BoundToolExecutor",
    )
    tool_call_grant_policy_version: str = Field(
        default="tool-grant-v1",
        alias="TOOL_CALL_GRANT_POLICY_VERSION",
    )
    tool_call_compatibility_sunset: str = Field(
        default="2026-12-31",
        alias="TOOL_CALL_COMPATIBILITY_SUNSET",
    )

    budget_enabled: bool = Field(default=True, alias="BUDGET_ENABLED")
    global_token_budget: int = Field(default=1_000_000, alias="GLOBAL_TOKEN_BUDGET")
    event_token_budget: int = Field(default=100_000, alias="EVENT_TOKEN_BUDGET")
    event_cost_budget_usd: float = Field(default=5.0, alias="EVENT_COST_BUDGET_USD")
    per_agent_token_cap: int = Field(default=20_000, alias="PER_AGENT_TOKEN_CAP")
    quality_judge_enabled: bool = Field(default=False, alias="QUALITY_JUDGE_ENABLED")
    guardrail_mode: str = Field(default="enforce", alias="GUARDRAIL_MODE")
    wm_strict: bool = Field(default=True, alias="WM_STRICT")

    orchestration_mode: str = Field(default="graph", alias="ORCHESTRATION_MODE")
    react_enabled: bool = Field(default=False, alias="REACT_ENABLED")
    react_shadow_pivot_enabled: bool = Field(
        default=False,
        alias="REACT_SHADOW_PIVOT_ENABLED",
        description="Enable shadow-isolated ReAct mock query pivot (ISSUE-135)",
    )
    react_shadow_max_steps: int = Field(
        default=5,
        alias="REACT_SHADOW_MAX_STEPS",
        ge=1,
        le=20,
    )
    react_shadow_max_tool_calls: int = Field(
        default=5,
        alias="REACT_SHADOW_MAX_TOOL_CALLS",
        ge=0,
        le=50,
    )
    super_agent_transition_max_retries: int = Field(
        default=3,
        alias="SUPER_AGENT_TRANSITION_MAX_RETRIES",
        ge=0,
        le=10,
        description="Bounded retries for transient SuperAgent EventStatus transitions (ISSUE-234)",
    )
    super_agent_transition_retry_backoff_seconds: float = Field(
        default=0.2,
        alias="SUPER_AGENT_TRANSITION_RETRY_BACKOFF_SECONDS",
        ge=0.0,
        le=60.0,
        description="Initial backoff seconds between SuperAgent transition retries (ISSUE-234)",
    )
    react_shadow_retention_hours: int = Field(
        default=168,
        alias="REACT_SHADOW_RETENTION_HOURS",
        ge=1,
        le=720,
    )
    checkpoint_attempt_redis_recovery: bool = Field(
        default=False,
        alias="CHECKPOINT_ATTEMPT_REDIS_RECOVERY",
        description=(
            "When true, periodically probe Redis after checkpoint memory fallback; "
            "only new thread_ids resume Redis persistence (pinned threads stay in-memory)."
        ),
    )
    checkpoint_redis_recovery_interval_seconds: float = Field(
        default=30.0,
        alias="CHECKPOINT_REDIS_RECOVERY_INTERVAL_SECONDS",
        ge=5.0,
        le=600.0,
    )
    checkpoint_fallback_reminder_interval_seconds: float = Field(
        default=300.0,
        alias="CHECKPOINT_FALLBACK_REMINDER_INTERVAL_SECONDS",
        ge=60.0,
        le=3600.0,
    )
    budget_attempt_redis_recovery: bool = Field(
        default=True,
        alias="BUDGET_ATTEMPT_REDIS_RECOVERY",
        description=(
            "When true, probe Redis after budget/reservation memory fallback; "
            "new events/grants resume Redis counters (pinned ones stay in-memory)."
        ),
    )
    budget_redis_recovery_interval_seconds: float = Field(
        default=5.0,
        alias="BUDGET_REDIS_RECOVERY_INTERVAL_SECONDS",
        ge=0.0,
        le=600.0,
    )
    action_execution_lease_seconds: float = Field(
        default=300.0,
        alias="ACTION_EXECUTION_LEASE_SECONDS",
        ge=30.0,
        le=3600.0,
    )
    action_execution_max_attempts: int = Field(
        default=5,
        alias="ACTION_EXECUTION_MAX_ATTEMPTS",
        ge=1,
        le=20,
    )
    action_execution_reconcile_enabled: bool = Field(
        default=True,
        alias="ACTION_EXECUTION_RECONCILE_ENABLED",
    )
    action_execution_reconcile_interval_s: float = Field(
        default=60.0,
        alias="ACTION_EXECUTION_RECONCILE_INTERVAL_S",
        ge=10.0,
        le=600.0,
    )
    outbox_max_attempts: int = Field(
        default=5,
        alias="OUTBOX_MAX_ATTEMPTS",
        ge=1,
        le=50,
    )
    outbox_retry_backoff_seconds: float = Field(
        default=30.0,
        alias="OUTBOX_RETRY_BACKOFF_SECONDS",
        ge=1.0,
        le=3600.0,
    )
    outbox_retry_backoff_max_seconds: float = Field(
        default=900.0,
        alias="OUTBOX_RETRY_BACKOFF_MAX_SECONDS",
        ge=30.0,
        le=86400.0,
    )
    task_mode: str = Field(default="background", alias="TASK_MODE")
    celery_broker_url: str = Field(default="", alias="CELERY_BROKER_URL")
    approval_timeout_minutes: int = Field(default=30, alias="APPROVAL_TIMEOUT_MINUTES")

    ingestion_scheduler_enabled: bool = Field(default=False, alias="INGESTION_SCHEDULER_ENABLED")
    ingestion_poll_interval_s: int = Field(default=60, alias="INGESTION_POLL_INTERVAL_S", ge=1)

    behavior_observation_retry_enabled: bool = Field(
        default=False,
        alias="BEHAVIOR_OBSERVATION_RETRY_ENABLED",
    )
    behavior_observation_retry_interval_s: int = Field(
        default=120,
        alias="BEHAVIOR_OBSERVATION_RETRY_INTERVAL_S",
        ge=60,
        le=300,
    )
    behavior_observation_retry_batch_limit: int = Field(
        default=50,
        alias="BEHAVIOR_OBSERVATION_RETRY_BATCH_LIMIT",
        ge=1,
        le=200,
    )

    detection_governance_expire_enabled: bool = Field(
        default=True,
        alias="DETECTION_GOVERNANCE_EXPIRE_ENABLED",
    )
    detection_governance_expire_interval_s: int = Field(
        default=3600,
        alias="DETECTION_GOVERNANCE_EXPIRE_INTERVAL_S",
        ge=300,
        le=86400,
    )

    auto_investigate_enabled: bool = Field(default=False, alias="AUTO_INVESTIGATE_ENABLED")
    auto_investigate_min_severity: str = Field(
        default="medium",
        alias="AUTO_INVESTIGATE_MIN_SEVERITY",
    )
    auto_investigate_event_types: str = Field(default="", alias="AUTO_INVESTIGATE_EVENT_TYPES")
    auto_investigate_provisional_window_s: int = Field(
        default=300,
        alias="AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S",
        ge=0,
    )
    auto_investigate_claim_lease_s: int = Field(
        default=30,
        alias="AUTO_INVESTIGATE_CLAIM_LEASE_S",
        ge=5,
    )
    auto_investigate_max_attempts: int = Field(
        default=5,
        alias="AUTO_INVESTIGATE_MAX_ATTEMPTS",
        ge=1,
    )
    auto_investigate_dispatch_interval_s: int = Field(
        default=15,
        alias="AUTO_INVESTIGATE_DISPATCH_INTERVAL_S",
        ge=5,
    )
    auto_investigate_reconcile_interval_s: int = Field(
        default=60,
        alias="AUTO_INVESTIGATE_RECONCILE_INTERVAL_S",
        ge=10,
    )
    auto_investigate_materialize_batch_size: int = Field(
        default=20,
        alias="AUTO_INVESTIGATE_MATERIALIZE_BATCH_SIZE",
        ge=1,
    )

    auto_response_enabled: bool = Field(default=False, alias="AUTO_RESPONSE_ENABLED")
    auto_response_min_severity: str = Field(
        default="high",
        alias="AUTO_RESPONSE_MIN_SEVERITY",
    )
    auto_response_max_auto_level: str = Field(
        default="L1",
        alias="AUTO_RESPONSE_MAX_AUTO_LEVEL",
    )
    auto_response_event_types: str = Field(default="", alias="AUTO_RESPONSE_EVENT_TYPES")

    memory_enqueue_after_analysis: bool = Field(
        default=True,
        alias="MEMORY_ENQUEUE_AFTER_ANALYSIS",
        description=(
            "When true, MemoryAgent may enqueue profile candidates after "
            "analysis-only completion (REPORTING + analysis_only_complete or "
            "generated report). fp_rule / history_case candidates still require "
            "CLOSED. Set false to fall back to CLOSED-only scheduling (ISSUE-208)."
        ),
    )

    neo4j_enabled: bool = Field(default=False, alias="NEO4J_ENABLED")
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="shadowtrace", alias="NEO4J_PASSWORD")

    otel_enabled: bool = Field(default=False, alias="OTEL_ENABLED")
    otel_exporter_otlp_endpoint: str = Field(
        default="http://127.0.0.1:4318",
        alias="OTEL_EXPORTER_OTLP_ENDPOINT",
    )
    otel_service_name: str = Field(default="shadowtrace-backend", alias="OTEL_SERVICE_NAME")

    def model_post_init(self, __context: object) -> None:
        if not (self.celery_broker_url or "").strip():
            object.__setattr__(self, "celery_broker_url", self.redis_url)
        auto_response_violations = self.auto_response_fail_closed_violations()
        if auto_response_violations:
            raise ConfigurationError(
                "AUTO_RESPONSE_ENABLED requires mock-only runtime modes: "
                + ", ".join(auto_response_violations),
                error_code="configuration_error",
                details={"violations": auto_response_violations},
            )
        violations = self.production_fail_closed_violations()
        if violations:
            raise ConfigurationError(
                "app_env=production forbids unsafe runtime configuration: " + ", ".join(violations),
                error_code="configuration_error",
                details={"app_env": self.app_env, "violations": violations},
            )
        proxy_violations = self.trusted_proxy_fail_closed_violations()
        if proxy_violations:
            raise ConfigurationError(
                "app_env=production forbids unsafe trusted-proxy configuration: "
                + ", ".join(proxy_violations),
                error_code="configuration_error",
                details={"app_env": self.app_env, "violations": proxy_violations},
            )

    def auto_response_fail_closed_violations(self) -> list[str]:
        """Reject live connector/provider combinations when auto-response is on."""
        if not self.auto_response_enabled:
            return []
        violations: list[str] = []
        if self.source_mode.strip().lower() != "mock_xdr":
            violations.append(f"source_mode={self.source_mode}")
        if not _looks_mock(self.tool_mode):
            violations.append(f"tool_mode={self.tool_mode}")
        if not _looks_mock(self.disposition_mode):
            violations.append(f"disposition_mode={self.disposition_mode}")
        if not _looks_mock(self.disposition_adapter_kind):
            violations.append(f"disposition_adapter_kind={self.disposition_adapter_kind}")
        raw_level = (self.auto_response_max_auto_level or "L1").strip()
        level = parse_action_level_label(raw_level)
        if level is None:
            violations.append(f"auto_response_max_auto_level={raw_level}")
        elif level not in AUTO_APPROVABLE_ACTION_LEVELS:
            violations.append(
                f"auto_response_max_auto_level={level.value} exceeds L1 auto-approve gate"
            )
        return violations

    def is_production(self) -> bool:
        """Whether ``APP_ENV`` denotes production (strip + case-insensitive).

        Shared by auth, CORS, and fail-closed gates so padded values like
        ``" production"`` cannot diverge across subsystems (ISSUE-217).
        """
        return self.app_env.strip().lower() == "production"

    def production_fail_closed_violations(self) -> list[str]:
        """Runtime modes that must never be active when ``app_env=production``.

        Fail-closed (ISSUE-093 §5): a production deployment that is silently
        running mock sources/tools/disposition or simulation mode is a
        security incident, not a warning — construction must raise.
        """
        if not self.is_production():
            return []
        violations: list[str] = []
        if os.environ.get("DEV_AUTH_TOKENS", "").strip():
            # ISSUE-217: dev-token auth is a debugging backdoor that must never
            # survive into a real production deployment. Fail closed at startup
            # instead of letting _principal_from_dev_token authorize requests.
            violations.append("DEV_AUTH_TOKENS set: dev-token auth forbidden in production")
        if self.simulation_enabled:
            violations.append("simulation_enabled=true")
        if _looks_mock(self.source_mode):
            violations.append(f"source_mode={self.source_mode}")
        if _looks_mock(self.tool_mode):
            violations.append(f"tool_mode={self.tool_mode}")
        if _looks_mock(self.disposition_mode):
            violations.append(f"disposition_mode={self.disposition_mode}")
        if _looks_mock(self.disposition_adapter_kind):
            violations.append(f"disposition_adapter_kind={self.disposition_adapter_kind}")
        if _looks_mock(self.llm_mode):
            violations.append(f"llm_mode={self.llm_mode}")
        if _looks_mock(self.embedding_mode):
            violations.append(f"embedding_mode={self.embedding_mode}")
        if self.retrieval_fixture_fallback:
            violations.append("retrieval_fixture_fallback=true")
        if self.playbook_fixture_fallback:
            violations.append("playbook_fixture_fallback=true")
        if self.react_enabled and not self.tool_call_grant_required:
            violations.append("react_enabled=true requires tool_call_grant_required=true")
        if self.react_shadow_pivot_enabled and not self.tool_call_grant_required:
            violations.append(
                "react_shadow_pivot_enabled=true requires tool_call_grant_required=true"
            )
        if self.react_shadow_pivot_enabled and not self.knowledge_release_require_active:
            violations.append(
                "react_shadow_pivot_enabled=true requires knowledge_release_require_active=true"
            )
        if self.react_shadow_pivot_enabled and self.retrieval_fixture_fallback:
            violations.append(
                "react_shadow_pivot_enabled=true forbids retrieval_fixture_fallback=true"
            )
        if self.decision_rationale_mode.strip().lower() == "short_text":
            # ISSUE-243: production may only use off|structured (no free short_text path).
            violations.append("decision_rationale_mode=short_text")
        return violations

    def trusted_proxy_allowlist_hosts(self) -> frozenset[str]:
        """Parse ``TRUSTED_PROXY_ALLOWLIST`` into normalized host entries."""
        return frozenset(
            host.strip() for host in self.trusted_proxy_allowlist.split(",") if host.strip()
        )

    def trusted_proxy_fail_closed_violations(self) -> list[str]:
        """Unsafe trusted-proxy settings when ``app_env=production`` (ISSUE-180)."""
        if not self.is_production():
            return []
        if not self.trusted_auth_proxy_enabled:
            return []
        hosts = self.trusted_proxy_allowlist_hosts()
        violations: list[str] = []
        if not hosts:
            violations.append(
                "trusted_auth_proxy_enabled=true requires non-empty TRUSTED_PROXY_ALLOWLIST"
            )
        if "*" in hosts:
            violations.append("TRUSTED_PROXY_ALLOWLIST must not contain wildcard '*'")
        return violations


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings singleton for FastAPI dependency injection."""
    return Settings()
