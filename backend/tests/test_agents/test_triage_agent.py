"""Tests for TriageAgent and helper functions (ISSUE-032 / ISSUE-114)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pydantic
import pytest

from app.agents.triage_agent import (
    SEVERITY_RULES,
    TriageAgent,
    _apply_severity_rules,
    _extract_iocs,
    _heuristic_event_type,
    _map_event_type,
    _resolve_alert_type_from_snapshot,
    _source_event_type_authoritative,
)
from app.core.errors import (
    DependencyUnavailableError,
    GuardrailViolationError,
    LLMError,
)
from app.models.agent_io import TriageAgentInput, TriageResult
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.enums import EventType, Severity, SourceObjectKind
from app.models.source import SourceReference
from app.services.entity_merge import merge_entity_sets
from app.services.working_memory import FIELD_OWNERSHIP

# --------------------------------------------------------------------------- #
# Mock-working-memory fixtures — signatures MATCH BoundWorkingMemory exactly
# --------------------------------------------------------------------------- #


class _MockBoundWorkingMemory:
    """Minimal mock matching BoundWorkingMemory interface exactly.

    write(self, event_id, key, value) — three positional args, NO ``writer`` keyword.

    Also exposes ``_memory`` and ``for_writer`` so ``TriageAgent.__init__`` can
    mint a separate FP hook memory (mirroring ``WorkingMemory.for_writer``).
    """

    def __init__(self, writer_name: str = "TriageAgent") -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}
        # ``_memory`` is a back-reference to self so that
        # ``working_memory._memory.for_writer(...)`` works in TriageAgent.__init__.
        self._memory = self

    def for_writer(self, writer: str) -> _MockBoundWorkingMemory:
        """Mint a new mock bound to *writer* (mirrors WorkingMemory.for_writer)."""
        from app.services.working_memory import normalize_writer

        return _MockBoundWorkingMemory(writer_name=normalize_writer(writer))

    async def read(self, event_id: str, key: str) -> object:
        return self._store.get(key)

    async def write(self, event_id: str, key: str, value: object) -> None:
        self._store[key] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass

    async def read_scratchpad(self, event_id: str) -> list:
        return []


class _MockDegradedFlags:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: object,
        writer: str,
    ) -> list[str]:
        normalized = str(value)
        self.calls.append((event_id, flag_name, normalized, writer))
        return [f"{flag_name}={normalized}"]


class _GuardrailMockBoundWorkingMemory:
    """Mock that enforces FIELD_OWNERSHIP like the real WorkingMemory.

    write(self, event_id, key, value) — raises GuardrailViolationError
    when writer_name != FIELD_OWNERSHIP[key].

    Also exposes ``_memory`` and ``for_writer`` so that TriageAgent.__init__
    can mint a separate FP hook memory (mirroring ``WorkingMemory.for_writer``).
    """

    def __init__(self, writer_name: str = "TriageAgent") -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}
        # ``_memory`` is a back-reference to self so that
        # ``working_memory._memory.for_writer(...)`` works in TriageAgent.__init__.
        self._memory = self

    def for_writer(self, writer: str) -> _GuardrailMockBoundWorkingMemory:
        """Mint a new guardrail-enforcing mock bound to *writer*."""
        from app.services.working_memory import normalize_writer

        return _GuardrailMockBoundWorkingMemory(writer_name=normalize_writer(writer))

    async def read(self, event_id: str, key: str) -> object:
        return self._store.get(key)

    async def write(self, event_id: str, key: str, value: object) -> None:
        owner = FIELD_OWNERSHIP.get(key)
        if owner and self.writer_name != owner:
            raise GuardrailViolationError(
                f"writer {self.writer_name!r} is not owner of {key!r} (owner={owner!r})",
                error_code="working_memory_unauthorized_write",
                details={
                    "event_id": event_id,
                    "key": key,
                    "writer": self.writer_name,
                    "owner": owner,
                },
            )
        self._store[key] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass

    async def read_scratchpad(self, event_id: str) -> list:
        return []


class _MockLLMClient:
    """Configurable mock LLM client whose .chat() returns a set response."""

    def __init__(self, response: object = None, raise_error: Exception | None = None) -> None:
        self._response = response
        self._raise_error = raise_error
        self.chat_calls: list[dict] = []

    async def chat(
        self,
        messages,
        *,
        event_id,
        agent_name,
        prompt_key,
        scenario_id=None,
        temperature=0.3,
        max_tokens=4096,
        json_mode=False,
        response_model=None,
        timeout=None,
    ):
        self.chat_calls.append(
            {
                "messages": messages,
                "event_id": event_id,
                "agent_name": agent_name,
                "prompt_key": prompt_key,
            }
        )
        if self._raise_error:
            raise self._raise_error
        return self._response


# --------------------------------------------------------------------------- #
# Helper to build sample inputs
# --------------------------------------------------------------------------- #


def _make_input(
    event_id: str = "evt-001",
    raw_event_summary: str = "User admin logged in from 192.168.1.1",
    hint_entities: EntitySet | None = None,
    structured_prompt_context=None,
) -> TriageAgentInput:
    return TriageAgentInput(
        event_id=event_id,
        raw_event_summary=raw_event_summary,
        hint_entities=hint_entities or EntitySet(),
        structured_prompt_context=structured_prompt_context,
    )


def _source_ref(*, source_object_id: str = "INC-099") -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id=source_object_id,
        ingested_at=datetime.now(UTC),
    )


# --------------------------------------------------------------------------- #
# Tests: _apply_severity_rules
# --------------------------------------------------------------------------- #


class TestApplySeverityRules:
    def test_data_exfiltration_with_external_ip_is_high(self):
        """ISSUE-032: data_exfiltration + external IP → HIGH."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="Data exfiltration to external IP 45.153.12.88",
        )
        assert severity == Severity.HIGH
        assert need is True

    def test_data_exfiltration_without_external_ip_is_medium(self):
        """ISSUE-032: data_exfiltration without external IP → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="Data exfiltration to internal server 10.0.0.5",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_data_exfiltration_no_alert_text_is_medium(self):
        """No alert text → cannot verify external IP → MEDIUM."""
        severity, need = _apply_severity_rules(EventType.DATA_EXFILTRATION)
        assert severity == Severity.MEDIUM
        assert need is True

    def test_account_anomaly_is_low(self):
        severity, need = _apply_severity_rules(EventType.ACCOUNT_ANOMALY)
        assert severity == Severity.LOW
        assert need is False

    def test_unlisted_event_type_is_medium(self):
        severity, need = _apply_severity_rules(EventType.OTHER)
        assert severity == Severity.MEDIUM
        assert need is True

    def test_data_exfiltration_with_lateral_is_critical(self):
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="lateral movement detected",
        )
        assert severity == Severity.CRITICAL
        assert need is True

    def test_collateral_does_not_trigger_critical(self):
        """Word 'collateral' should NOT match the \blateral\b boundary check."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="collateral damage from data exfiltration to 45.153.12.88",
        )
        assert severity == Severity.HIGH  # external IP → HIGH, not CRITICAL

    def test_insider_threat_with_external_ip_is_high(self):
        severity, need = _apply_severity_rules(
            EventType.INSIDER_THREAT,
            alert_text="insider packed finance data to 203.0.113.88",
        )
        assert severity == Severity.HIGH
        assert need is True

    def test_insider_threat_without_external_ip_is_medium(self):
        severity, need = _apply_severity_rules(
            EventType.INSIDER_THREAT,
            alert_text="insider packed finance data on internal host 10.20.30.23",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_bilateral_does_not_trigger_critical(self):
        """Word 'bilateral' should NOT match the \blateral\b boundary check."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="bilateral data transfer to 8.8.8.8",
        )
        assert severity == Severity.HIGH  # external IP → HIGH, not CRITICAL


# --------------------------------------------------------------------------- #
# Tests: _extract_iocs
# --------------------------------------------------------------------------- #


class TestExtractIOCs:
    def test_external_ip_included(self):
        iocs = _extract_iocs("Connection from 45.153.12.88 detected")
        assert "45.153.12.88" in iocs

    def test_internal_ip_excluded(self):
        iocs = _extract_iocs("Login from 10.50.1.10")
        assert "10.50.1.10" not in iocs

    def test_loopback_ip_excluded(self):
        iocs = _extract_iocs("Connection from 127.0.0.1")
        assert "127.0.0.1" not in iocs

    def test_domain_included(self):
        iocs = _extract_iocs("Request to evil.example.com")
        assert "evil.example.com" in iocs

    def test_entity_ip_included_when_external(self):
        entities = EntitySet(ips=[IPEntity(entity_id="ip-1", address="8.8.8.8")])
        iocs = _extract_iocs("some text", entities)
        assert "8.8.8.8" in iocs

    def test_entity_ip_excluded_when_internal(self):
        entities = EntitySet(ips=[IPEntity(entity_id="ip-1", address="192.168.1.1")])
        iocs = _extract_iocs("some text", entities)
        assert "192.168.1.1" not in iocs

    def test_entity_domain_included(self):
        """ISSUE-338: validated EntitySet.domains must merge into ioc_list."""
        entities = EntitySet(
            domains=[DomainEntity(entity_id="dom-1", fqdn="storage-sync-cdn.example")]
        )
        iocs = _extract_iocs("Connection from 198.51.100.44", entities)
        assert "storage-sync-cdn.example" in iocs
        assert "198.51.100.44" in iocs

    def test_invalid_entity_domain_not_included(self):
        """ISSUE-338: unvalidated entity fqdn must not land in ioc_list."""
        entities = EntitySet(domains=[DomainEntity(entity_id="dom-bad", fqdn="not a domain")])
        iocs = _extract_iocs("Connection from 198.51.100.44", entities)
        assert "not a domain" not in iocs
        assert "198.51.100.44" in iocs


# --------------------------------------------------------------------------- #
# Tests: _map_event_type
# --------------------------------------------------------------------------- #


class TestMapEventType:
    def test_valid_raw_type_mapped(self):
        assert _map_event_type("data_exfiltration") == EventType.DATA_EXFILTRATION

    def test_unknown_raw_type_fallback_keyword(self):
        assert _map_event_type(None, "failed to login from 10.0.0.1") == EventType.ACCOUNT_ANOMALY

    def test_no_match_returns_other(self):
        assert _map_event_type(None, "some random text") == EventType.OTHER

    def test_source_other_falls_through_to_heuristic(self):
        """ISSUE-197: ingestion OTHER must not block keyword classification."""
        assert (
            _map_event_type("other", "schema-export monitor detected volume anomaly")
            == EventType.DATA_EXFILTRATION
        )

    def test_explicit_source_type_not_overridden_by_heuristic(self):
        assert (
            _map_event_type("malicious_process", "upload exfil to external host")
            == EventType.MALICIOUS_PROCESS
        )


# --------------------------------------------------------------------------- #
# Tests: _merge_hint_entities (idempotency + non-mutation)
# --------------------------------------------------------------------------- #


class TestMergeEntitySets:
    def test_merge_preserves_existing(self):
        llm = EntitySet(accounts=[AccountEntity(entity_id="acct-1", username="alice")])
        hint = EntitySet(hosts=[HostEntity(entity_id="host-1", hostname="PC-01")])
        merged = merge_entity_sets(llm=llm, source=hint).entities
        assert len(merged.accounts) == 1
        assert merged.accounts[0].username == "alice"
        assert len(merged.hosts) == 1
        assert merged.hosts[0].hostname == "PC-01"

    def test_merge_skips_duplicate_semantic_identity(self):
        source = EntitySet(
            accounts=[
                AccountEntity(
                    entity_id="acct-1",
                    username="alice",
                    attributes={"provenance": "source"},
                )
            ]
        )
        llm = EntitySet(
            accounts=[
                AccountEntity(
                    entity_id="acct-2",
                    username="alice",
                    attributes={"provenance": "llm"},
                )
            ]
        )
        merged = merge_entity_sets(source=source, llm=llm).entities
        assert len(merged.accounts) == 1
        assert merged.accounts[0].entity_id == "acct-1"

    def test_merge_does_not_mutate_inputs(self):
        llm = EntitySet(accounts=[AccountEntity(entity_id="acct-1", username="alice")])
        hint = EntitySet()
        original_len = len(llm.accounts)
        merge_entity_sets(llm=llm, source=hint)
        assert len(llm.accounts) == original_len


# --------------------------------------------------------------------------- #
# Tests: ISSUE-114 — no pre-evidence FP shortcut hook
# --------------------------------------------------------------------------- #


class TestPreEvidenceFpRemoved:
    @pytest.mark.asyncio
    async def test_triage_does_not_write_close_as_fp_from_scenario(self):
        """Scenario/fixture names must not produce pre-evidence close_as_fp."""
        fp_memory = _MockBoundWorkingMemory(writer_name="FalsePositiveMatcher")
        agent_memory = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await agent_memory.write(
            "evt-001",
            "source_snapshot",
            {
                "scenario": "account_anomaly_fp",
                "title": "Bulk login by ops account during change window",
            },
        )
        agent = TriageAgent(working_memory=agent_memory)
        agent.working_memory = agent_memory
        result = await agent.execute(_make_input("evt-001"))
        assert isinstance(result, TriageResult)
        fp_match = await fp_memory.read("evt-001", "false_positive_match")
        assert fp_match is None or fp_match.get("recommendation") != "close_as_fp"


# --------------------------------------------------------------------------- #
# Tests: TriageAgent — main scenarios
# --------------------------------------------------------------------------- #


class TestTriageAgentBasic:
    @pytest.mark.asyncio
    async def test_no_llm_client_uses_regex_fallback(self):
        """Agent without llm_client → degraded regex extraction."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)
        # No llm_client — should not be provided.
        assert agent.llm_client is None

        input_ = _make_input(
            raw_event_summary=(
                "User zhangsan on host PC-FIN-023 executed powershell.exe and "
                "uploaded data from 45.153.12.88 to 203.0.113.88 (evil.example.com)"
            ),
        )
        result = await agent._run(input_)
        assert isinstance(result, TriageResult)
        assert result.degraded is True
        assert result.event_type == EventType.DATA_EXFILTRATION  # 'upload' keyword
        # All four entity types required by acceptance criteria #1 must be
        # extracted from a representative data-exfiltration alert text.
        assert len(result.entities.accounts) >= 1, "Should extract account 'zhangsan'"
        assert len(result.entities.hosts) >= 1, "Should extract host 'PC-FIN-023'"
        assert len(result.entities.ips) >= 1, "Should extract IP 203.0.113.88"
        assert len(result.entities.domains) >= 1, "Should extract domain 'evil.example.com'"
        # ISSUE-032 acceptance #2: main scenario severity high + need_investigation.
        assert result.severity == Severity.HIGH
        assert result.need_investigation is True
        # External IPs in IoC list (including Issue example IP).
        assert "203.0.113.88" in result.ioc_list
        assert "45.153.12.88" in result.ioc_list

    @pytest.mark.asyncio
    async def test_map_event_type_from_raw_alert_snapshot_file_fallback(self):
        """File fallback alert_type comes from raw_alert_snapshot when snapshot has none."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await wm.write(
            "evt-fb",
            "source_snapshot",
            {
                "creation_source_ref": {"source_object_id": "file-alert-1"},
                "raw_alert_snapshot": {
                    "payload_hash": "abc123",
                    "primary_entity": "zhangsan",
                    "raw": {"alert_type": "malicious_process"},
                },
            },
        )
        agent = TriageAgent(working_memory=wm)
        input_ = _make_input(
            "evt-fb",
            raw_event_summary="benign text without event-type keywords",
        )
        result = await agent._run(input_)
        assert result.event_type == EventType.MALICIOUS_PROCESS

    @pytest.mark.asyncio
    async def test_human_classification_override_wins_over_heuristic_keywords(self):
        """ISSUE-209: reinvestigate must keep analyst event_type in triage_result."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await wm.write(
            "evt-human-override",
            "classification_override",
            {
                "source": "human",
                "event_type": "insider_threat",
                "reason": "analyst override",
                "operator": "analyst-1",
            },
        )
        agent = TriageAgent(working_memory=wm)
        input_ = _make_input(
            "evt-human-override",
            raw_event_summary=(
                "User zhangsan uploaded confidential data to 203.0.113.88 (evil.example.com)"
            ),
        )
        result = await agent._run(input_)
        assert result.event_type == EventType.INSIDER_THREAT
        assert "human classification override" in (result.decision_summary or "")
        stored = await wm.read("evt-human-override", "triage_result")
        assert isinstance(stored, dict)
        assert stored.get("event_type") == "insider_threat"
        assert "event_type_from_heuristic" not in (stored.get("degradation_reasons") or [])

    @pytest.mark.asyncio
    async def test_human_override_falls_back_to_orm_snapshot_when_wm_missing(self):
        """ISSUE-211: WM miss must not drop durable human PATCH (snapshot fallback)."""
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from app.services.classification_source import OrmEventTypeRewriteOutcome

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        # No classification_override in WM — simulates failed context write after PATCH.
        event_service = AsyncMock()
        event_service.get_event = AsyncMock(
            return_value=SimpleNamespace(
                event_id="evt-211-human-snap",
                event_type=EventType.INSIDER_THREAT,
                event_context_snapshot={
                    "classification_override": {
                        "source": "human",
                        "event_type": "insider_threat",
                        "reason": "analyst override",
                        "operator": "analyst-1",
                    }
                },
            )
        )
        event_service.rewrite_event_type_from_triage = AsyncMock(
            return_value=OrmEventTypeRewriteOutcome.NOOP
        )
        agent = TriageAgent(working_memory=wm, event_service=event_service)
        result = await agent._run(
            _make_input(
                "evt-211-human-snap",
                raw_event_summary=(
                    "User zhangsan uploaded confidential data to 203.0.113.88 (evil.example.com)"
                ),
            )
        )
        assert result.event_type == EventType.INSIDER_THREAT
        assert "human classification override" in (result.decision_summary or "")
        event_service.get_event.assert_awaited()
        event_service.rewrite_event_type_from_triage.assert_awaited_once()
        assert (
            event_service.rewrite_event_type_from_triage.await_args.kwargs["event_type"]
            is EventType.INSIDER_THREAT
        )

    @pytest.mark.asyncio
    async def test_single_login_failure_is_low(self):
        """Single login failure → account_anomaly → low severity."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(
            raw_event_summary="User svc-backup failed to login 1 time from 10.50.1.10",
        )
        result = await agent._run(input_)
        assert result.severity == Severity.LOW
        assert result.need_investigation is False

    @pytest.mark.asyncio
    async def test_writes_triage_result_to_event_context(self):
        """TriageResult is persisted via working_memory.write."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="Host compromise detected")
        result = await agent._run(input_)

        stored = await wm.read(input_.event_id, "triage_result")
        assert stored is not None
        assert stored["event_type"] == result.event_type.value

    @pytest.mark.asyncio
    async def test_hint_entities_are_merged(self):
        """Hint entities from input are merged into extracted entities."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        hint = EntitySet(
            accounts=[AccountEntity(entity_id="hint-acct-1", username="pre_known_user")],
        )
        input_ = _make_input(
            raw_event_summary="Suspicious activity detected",
            hint_entities=hint,
        )
        result = await agent._run(input_)
        assert any(e.entity_id == "hint-acct-1" for e in result.entities.accounts)


# --------------------------------------------------------------------------- #
# Tests: TriageAgent — LLM path
# --------------------------------------------------------------------------- #


class TestTriageAgentLLM:
    @pytest.mark.asyncio
    async def test_llm_response_parsed_correctly(self):
        """LLM returns valid TriageLLMResponse → entities extracted."""
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_entities = EntitySet(
            accounts=[AccountEntity(entity_id="acct-1", username="testuser")],
            ips=[IPEntity(entity_id="ip-1", address="8.8.8.8")],
        )
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.MALICIOUS_PROCESS,
                entities=llm_entities,
                decision_summary="Test reasoning",
            ),
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(raw_event_summary="powershell.exe executed")
        result = await agent._run(input_)
        assert result.event_type == EventType.MALICIOUS_PROCESS
        assert len(result.entities.accounts) == 1
        assert result.entities.accounts[0].username == "testuser"
        assert "Test reasoning" in result.decision_summary
        assert result.degraded is False

    @pytest.mark.asyncio
    async def test_llm_chat_raises_llm_error_triggers_fallback(self):
        """LLM chat() raises LLMError → degraded regex fallback."""
        llm_client = _MockLLMClient(raise_error=LLMError("LLM unavailable"))

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(
            raw_event_summary="User admin connected to 203.0.113.88",
        )
        result = await agent._run(input_)
        assert result.degraded is True
        assert "203.0.113.88" in result.ioc_list  # regex extracted IP

    @pytest.mark.asyncio
    async def test_llm_timeout_triggers_regex_fallback(self):
        """LLM chat() raises TimeoutError → degraded regex fallback.

        TimeoutError (Python 3.11+, inherits from OSError) is NOT a
        ShadowTraceError subclass.  The agent must catch it separately
        and fall back to regex so the main triage pipeline does not fail.
        """
        llm_client = _MockLLMClient(raise_error=TimeoutError("LLM timed out"))

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(
            raw_event_summary="User zhangsan on PC-FIN-023 uploaded to 203.0.113.88",
        )
        result = await agent._run(input_)
        assert result.degraded is True, (
            "TimeoutError should trigger regex fallback (degraded=True), not crash the agent"
        )
        assert len(result.entities.ips) >= 1
        assert "203.0.113.88" in result.ioc_list
        # LLM client should have been called (and then timed out).
        assert len(llm_client.chat_calls) == 1

    @pytest.mark.asyncio
    async def test_llm_soft_time_limit_propagates_not_regex_fallback(self) -> None:
        """ISSUE-314: SoftTimeLimitExceeded must not become regex-degraded success."""
        from celery.exceptions import SoftTimeLimitExceeded

        llm_client = _MockLLMClient(raise_error=SoftTimeLimitExceeded())
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)
        input_ = _make_input(
            raw_event_summary="User admin connected to 10.0.0.1",
        )
        with pytest.raises(SoftTimeLimitExceeded):
            await agent._run(input_)
        assert len(llm_client.chat_calls) == 1

    @pytest.mark.asyncio
    async def test_source_other_upgrades_via_heuristic_with_audit(self):
        """ISSUE-197: source alert_type=other + export keywords → data_exfiltration."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        degraded_flags = _MockDegradedFlags()
        await wm.write(
            "evt-197-heuristic",
            "source_snapshot",
            {"alert_type": "other", "creation_source_ref": {"source_object_id": "inc-1"}},
        )
        agent = TriageAgent(working_memory=wm, degraded_flags=degraded_flags)
        input_ = _make_input(
            "evt-197-heuristic",
            raw_event_summary=(
                "Correlated medium alerts across schema-export monitors and network volume."
            ),
        )
        result = await agent._run(input_)
        assert result.event_type is EventType.DATA_EXFILTRATION
        assert "event_type_from_heuristic" in result.degradation_reasons
        assert (
            "evt-197-heuristic",
            "event_type_from_heuristic",
            "data_exfiltration",
            "TriageAgent",
        ) in degraded_flags.calls

    @pytest.mark.asyncio
    async def test_explicit_source_type_not_overridden_by_llm_fallback(self, monkeypatch):
        """ISSUE-197: concrete source type must remain authoritative."""
        from app.core.config import get_settings

        monkeypatch.setenv("TRIAGE_LLM_EVENT_TYPE_FALLBACK", "true")
        get_settings.cache_clear()

        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=EntitySet(
                    accounts=[AccountEntity(entity_id="acct-1", username="alice")],
                ),
                decision_summary="LLM guessed exfil",
            ),
            model_name="mock",
        )
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await wm.write(
            "evt-197-source-wins",
            "source_snapshot",
            {"alert_type": "malicious_process"},
        )
        agent = TriageAgent(llm_client=_MockLLMClient(response=llm_response), working_memory=wm)
        result = await agent._run(
            _make_input(
                "evt-197-source-wins",
                raw_event_summary="benign summary without classification keywords",
            )
        )
        assert result.event_type is EventType.MALICIOUS_PROCESS
        assert "event_type_from_llm_fallback" not in result.degradation_reasons

    @pytest.mark.asyncio
    async def test_llm_event_type_fallback_when_enabled(self, monkeypatch):
        """ISSUE-197: optional LLM fallback applies only after source+heuristic OTHER."""
        from app.core.config import get_settings

        monkeypatch.setenv("TRIAGE_LLM_EVENT_TYPE_FALLBACK", "true")
        get_settings.cache_clear()

        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=EntitySet(
                    accounts=[AccountEntity(entity_id="acct-1", username="alice")],
                ),
                decision_summary="LLM classified exfil",
            ),
            model_name="mock",
        )
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        degraded_flags = _MockDegradedFlags()
        await wm.write(
            "evt-197-llm-fallback",
            "source_snapshot",
            {"alert_type": "other"},
        )
        agent = TriageAgent(
            llm_client=_MockLLMClient(response=llm_response),
            working_memory=wm,
            degraded_flags=degraded_flags,
        )
        result = await agent._run(
            _make_input(
                "evt-197-llm-fallback",
                raw_event_summary="ambiguous correlated alerts during maintenance window",
            )
        )
        assert result.event_type is EventType.DATA_EXFILTRATION
        assert "event_type_from_llm_fallback" in result.degradation_reasons
        assert (
            "evt-197-llm-fallback",
            "event_type_from_llm_fallback",
            "data_exfiltration",
            "TriageAgent",
        ) in degraded_flags.calls

    @pytest.mark.asyncio
    async def test_triage_calls_orm_rewrite_after_successful_write(self, monkeypatch):
        """ISSUE-211: after durable triage_result, rewrite ORM list event_type."""
        from unittest.mock import AsyncMock

        from app.core.config import get_settings

        monkeypatch.setenv("TRIAGE_LLM_EVENT_TYPE_FALLBACK", "true")
        get_settings.cache_clear()

        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse
        from app.services.classification_source import OrmEventTypeRewriteOutcome

        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=EntitySet(
                    accounts=[AccountEntity(entity_id="acct-1", username="alice")],
                ),
                decision_summary="LLM classified exfil",
            ),
            model_name="mock",
        )
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await wm.write(
            "evt-211-rewrite",
            "source_snapshot",
            {"alert_type": "other"},
        )
        event_service = AsyncMock()
        event_service.rewrite_event_type_from_triage = AsyncMock(
            return_value=OrmEventTypeRewriteOutcome.APPLIED
        )
        agent = TriageAgent(
            llm_client=_MockLLMClient(response=llm_response),
            working_memory=wm,
            degraded_flags=_MockDegradedFlags(),
            event_service=event_service,
        )
        result = await agent._run(
            _make_input(
                "evt-211-rewrite",
                raw_event_summary="ambiguous correlated alerts during maintenance window",
            )
        )
        assert result.event_type is EventType.DATA_EXFILTRATION
        assert "triage_result" in wm._store
        event_service.rewrite_event_type_from_triage.assert_awaited_once()
        call_kwargs = event_service.rewrite_event_type_from_triage.await_args
        assert call_kwargs.args[0] == "evt-211-rewrite"
        assert call_kwargs.kwargs["event_type"] is EventType.DATA_EXFILTRATION
        assert call_kwargs.kwargs["operator"] == "TriageAgent"
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_triage_skips_orm_rewrite_when_context_write_fails(self):
        """ISSUE-211: do not rewrite ORM if triage_result was not durably written."""
        from unittest.mock import AsyncMock

        wm = _FailingWriteMockWM(
            writer_name="TriageAgent",
            fail_key="triage_result",
            fail_error=DependencyUnavailableError("Redis down"),
        )
        event_service = AsyncMock()
        event_service.rewrite_event_type_from_triage = AsyncMock()
        agent = TriageAgent(
            working_memory=wm,
            event_service=event_service,
        )
        result = await agent._run(_make_input("evt-211-no-rewrite"))
        assert result.degraded is True
        event_service.rewrite_event_type_from_triage.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_llm_event_type_fallback_disabled_by_default(self, monkeypatch):
        """ISSUE-197: LLM event_type is ignored unless TRIAGE_LLM_EVENT_TYPE_FALLBACK=true."""
        from app.core.config import get_settings

        monkeypatch.delenv("TRIAGE_LLM_EVENT_TYPE_FALLBACK", raising=False)
        get_settings.cache_clear()

        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=EntitySet(
                    accounts=[AccountEntity(entity_id="acct-1", username="alice")],
                ),
                decision_summary="LLM classified exfil",
            ),
            model_name="mock",
        )
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        degraded_flags = _MockDegradedFlags()
        await wm.write(
            "evt-197-llm-off",
            "source_snapshot",
            {"alert_type": "other"},
        )
        agent = TriageAgent(
            llm_client=_MockLLMClient(response=llm_response),
            working_memory=wm,
            degraded_flags=degraded_flags,
        )
        result = await agent._run(
            _make_input(
                "evt-197-llm-off",
                raw_event_summary="ambiguous correlated alerts during maintenance window",
            )
        )
        assert result.event_type is EventType.OTHER
        assert "event_type_from_llm_fallback" not in result.degradation_reasons
        assert degraded_flags.calls == []

    @pytest.mark.asyncio
    async def test_empty_source_snapshot_no_crash(self):
        """Agent handles missing source_snapshot gracefully."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)
        # source_snapshot is not written → read returns None.

        input_ = _make_input(raw_event_summary="Some alert")
        result = await agent._run(input_)
        assert result.event_type == EventType.OTHER  # no keywords matched

    @pytest.mark.asyncio
    async def test_empty_alert_with_llm_client_returns_empty_entities(self):
        """Empty alert + LLM client present → empty EntitySet, no crash.

        When ``llm_client`` is configured (not None) but the alert text is
        empty, ``build_triage_messages("")`` would raise ``ValueError`` which
        is not a ``ShadowTraceError``.  The agent must short-circuit before
        the LLM call and return an empty ``EntitySet`` with ``degraded=False``
        (LLM did not fail — there is just nothing to extract).
        """
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.OTHER,
                entities=EntitySet(),
                reasoning="",
            ),
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(raw_event_summary="")
        result = await agent._run(input_)

        # Must not crash; should return empty EntitySet, degraded=False.
        assert isinstance(result, TriageResult)
        assert result.entities == EntitySet()
        assert result.degraded is False
        # LLM should NOT have been called (empty input short-circuit).
        assert len(llm_client.chat_calls) == 0


# --------------------------------------------------------------------------- #
# Tests: TriageAgent — degraded scenarios
# --------------------------------------------------------------------------- #


class TestTriageAgentDegraded:
    @pytest.mark.asyncio
    async def test_no_working_memory_no_crash(self):
        """Agent without working_memory still produces a result."""
        agent = TriageAgent()  # no working_memory at all
        input_ = _make_input(raw_event_summary="Test alert")
        result = await agent._run(input_)
        assert isinstance(result, TriageResult)
        assert result.event_type is not None

    @pytest.mark.asyncio
    async def test_regex_fallback_extracts_accounts(self):
        """Regex fallback extracts account/usernames from alert text."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(
            raw_event_summary="Account jdoe failed authentication on host WEB-SERVER-01",
        )
        result = await agent._run(input_)
        # Should extract at least hostname "WEB-SERVER-01"
        assert len(result.entities.hosts) >= 1
        assert any("WEB" in (h.hostname or "") for h in result.entities.hosts)

    @pytest.mark.asyncio
    async def test_triage_result_has_required_fields(self):
        """TriageResult is complete with all required fields."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="User admin logged in from 192.168.1.1")
        result = await agent._run(input_)
        assert result.event_type is not None
        assert result.severity is not None
        assert isinstance(result.need_investigation, bool)
        assert isinstance(result.entities, EntitySet)
        assert isinstance(result.ioc_list, list)
        assert isinstance(result.degraded, bool)


# --------------------------------------------------------------------------- #
# Tests: SEVERITY_RULES structure
# --------------------------------------------------------------------------- #


class TestSeverityRules:
    def test_rules_have_required_keys(self):
        """SEVERITY_RULES must have high, critical, low keys."""
        assert "high" in SEVERITY_RULES
        assert "critical" in SEVERITY_RULES
        assert "low" in SEVERITY_RULES

    def test_critical_severity_can_be_produced(self):
        """SEVERITY_RULES critical path is exercised."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="lateral movement from 10.0.0.1 detected",
        )
        assert severity == Severity.CRITICAL
        assert need is True

    def test_severity_rules_are_tuples(self):
        """Each rule is a list of (key, value) tuples."""
        for _level, rules in SEVERITY_RULES.items():
            assert isinstance(rules, list)
            for rule in rules:
                assert isinstance(rule, tuple)
                assert len(rule) == 2
                assert isinstance(rule[0], str)
                assert isinstance(rule[1], str)


# --------------------------------------------------------------------------- #
# Tests: TriageAgent — pre_triage_hooks alias
# --------------------------------------------------------------------------- #


class TestTriageAgentHooks:
    def test_pre_triage_hooks_is_alias_of_pre_hooks(self):
        agent = TriageAgent()
        assert agent.pre_triage_hooks is agent.pre_hooks
        assert agent.post_triage_hooks is agent.post_hooks

    def test_fp_hook_installed_when_fp_matcher_provided(self):
        """When fp_matcher is provided, vector FP hook is auto-installed post-triage."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        wm._memory = MagicMock()
        wm._memory.for_writer.return_value = _MockBoundWorkingMemory(
            writer_name="FalsePositiveMatcher",
        )
        fp_matcher = MagicMock()

        agent = TriageAgent(working_memory=wm, fp_matcher=fp_matcher)
        assert len(agent.pre_triage_hooks) == 0
        assert len(agent.post_triage_hooks) == 1
        from app.services.false_positive_matcher import FalsePositiveMatcherHook

        assert isinstance(agent.post_triage_hooks[0], FalsePositiveMatcherHook)


# --------------------------------------------------------------------------- #
# Tests: TriageAgentInput / TriageResult contract
# --------------------------------------------------------------------------- #


class TestTriageAgentContract:
    def test_agent_name_is_triage_agent(self):
        assert TriageAgent.agent_name == "triage_agent"

    def test_agent_name_in_io_mapping(self):
        from app.models.agent_io import AGENT_INPUT_BY_NAME

        assert AGENT_INPUT_BY_NAME.get("triage_agent") is TriageAgentInput

    def test_triage_result_extra_forbid(self):
        """TriageResult rejects extra fields."""
        with pytest.raises(pydantic.ValidationError):
            TriageResult.model_validate(
                {
                    "event_type": "other",
                    "severity": "low",
                    "need_investigation": False,
                    "unknown_field": "should_reject",
                }
            )


# --------------------------------------------------------------------------- #
# Tests: Golden response compatibility
# --------------------------------------------------------------------------- #


class TestGoldenResponse:
    def test_golden_response_parses_as_triage_llm_response(self):
        """The golden default.json must validate as TriageLLMResponse."""
        import json

        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import default_golden_root

        golden_path = default_golden_root() / "triage_extract" / "default.json"
        assert golden_path.is_file(), f"Golden file missing: {golden_path}"

        payload = json.loads(golden_path.read_text("utf-8"))
        content = payload.get("content", payload)
        assert isinstance(content, dict), "Golden content must be a dict"

        # Should parse without error.
        parsed = TriageLLMResponse.model_validate(content)
        assert parsed.event_type == EventType.OTHER
        assert isinstance(parsed.entities, EntitySet)
        assert isinstance(parsed.decision_summary, str)


# --------------------------------------------------------------------------- #
# Mock WM that raises on write (for transient-failure tests)
# --------------------------------------------------------------------------- #


class _FailingWriteMockWM:
    """Mock WM that raises on write for a specific key."""

    def __init__(
        self,
        writer_name: str = "TriageAgent",
        *,
        fail_key: str | None = None,
        fail_error: Exception | None = None,
    ) -> None:
        self.writer_name = writer_name
        self._store: dict[str, object] = {}
        self._fail_key = fail_key
        self._fail_error = fail_error or DependencyUnavailableError("wm unavailable")
        self._memory = self

    def for_writer(self, writer: str) -> _FailingWriteMockWM:
        from app.services.working_memory import normalize_writer

        return _FailingWriteMockWM(
            writer_name=normalize_writer(writer),
            fail_key=self._fail_key,
            fail_error=self._fail_error,
        )

    async def read(self, event_id: str, key: str) -> object:
        return self._store.get(key)

    async def write(self, event_id: str, key: str, value: object) -> None:
        if self._fail_key is not None and key == self._fail_key:
            raise self._fail_error
        self._store[key] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        pass

    async def read_scratchpad(self, event_id: str) -> list:
        return []


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #1 — transient write failure marks degraded
# --------------------------------------------------------------------------- #


class TestWriteTriageResultTransientFailure:
    @pytest.mark.asyncio
    async def test_transient_write_failure_marks_degraded(self):
        """When wm.write raises DependencyUnavailableError, result.degraded=True."""
        wm = _FailingWriteMockWM(
            writer_name="TriageAgent",
            fail_key="triage_result",
            fail_error=DependencyUnavailableError("Redis down"),
        )
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(
            raw_event_summary="Host compromise detected on server-01",
        )
        result = await agent._run(input_)
        assert result.degraded is True
        assert any(
            "triage_result persistence failed" in item for item in result.degradation_reasons
        )
        assert any("working memory unavailable" in item for item in result.degradation_reasons)

    @pytest.mark.asyncio
    async def test_retryable_shadowtrace_error_marks_degraded(self):
        """When wm.write raises a retryable ShadowTraceError, result.degraded=True."""
        from app.core.errors import ShadowTraceError

        wm = _FailingWriteMockWM(
            writer_name="TriageAgent",
            fail_key="triage_result",
            fail_error=ShadowTraceError(
                "DB timeout",
                error_code="db_timeout",
                retryable=True,
            ),
        )
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="Test alert")
        result = await agent._run(input_)
        assert result.degraded is True
        assert any(
            "triage_result persistence failed: db_timeout" in item
            for item in result.degradation_reasons
        )

    @pytest.mark.asyncio
    async def test_non_retryable_shadowtrace_error_raises(self):
        """Non-retryable ShadowTraceError propagates, not swallowed."""
        from app.core.errors import ShadowTraceError

        wm = _FailingWriteMockWM(
            writer_name="TriageAgent",
            fail_key="triage_result",
            fail_error=ShadowTraceError(
                "Schema mismatch",
                error_code="schema_error",
                retryable=False,
            ),
        )
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="Test alert")
        with pytest.raises(ShadowTraceError) as exc_info:
            await agent._run(input_)
        assert exc_info.value.error_code == "schema_error"


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #3 — account_anomaly keyword-based upgrade
# --------------------------------------------------------------------------- #


class TestAccountAnomalyUpgrade:
    def test_single_login_failure_is_low(self):
        """Plain single login failure → LOW (unchanged behavior)."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="User svc-backup failed to login 1 time",
        )
        assert severity == Severity.LOW
        assert need is False

    def test_bulk_account_anomaly_is_medium(self):
        """Bulk account creation → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Bulk account creation detected: 50 new users in 5 minutes",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_mass_account_anomaly_is_medium(self):
        """Mass login failures → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Mass login failures from multiple IPs detected",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_privilege_escalation_is_medium(self):
        """Privilege escalation → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Privilege escalation detected: user granted admin role",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_brute_force_is_medium(self):
        """Brute force attack → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Brute force attack on SSH port detected",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_password_spray_is_medium(self):
        """Password spray → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Password spray attack targeting O365 accounts",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_chinese_geo_anomaly_is_medium(self):
        """Chinese geo-anomaly description → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="检测到账号地域异常登录行为",
        )
        assert severity == Severity.MEDIUM
        assert need is True

    def test_impossible_travel_is_medium(self):
        """Impossible travel → MEDIUM."""
        severity, need = _apply_severity_rules(
            EventType.ACCOUNT_ANOMALY,
            alert_text="Impossible travel: login from Beijing then New York in 10 minutes",
        )
        assert severity == Severity.MEDIUM
        assert need is True


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #4 — agent_trace recording
# --------------------------------------------------------------------------- #


class TestTriageAgentTrace:
    @pytest.mark.asyncio
    async def test_triage_agent_records_agent_trace(self):
        """TriageAgent.execute() calls trace_service.log_trace."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        trace_service = MagicMock()
        trace_service.log_trace = MagicMock()

        agent = TriageAgent(working_memory=wm, trace_service=trace_service)

        input_ = _make_input(raw_event_summary="Host compromise detected")
        await agent.execute(input_)

        # trace_service.log_trace must have been called once.
        trace_service.log_trace.assert_called_once()
        call_kwargs = trace_service.log_trace.call_args.kwargs
        assert call_kwargs["event_id"] == input_.event_id
        assert call_kwargs["agent_name"] == "triage_agent"
        assert call_kwargs["status"] == "completed"

    @pytest.mark.asyncio
    async def test_no_trace_service_no_crash(self):
        """Agent without trace_service still executes without error."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)  # no trace_service

        input_ = _make_input(raw_event_summary="Test alert")
        result = await agent.execute(input_)
        assert isinstance(result, TriageResult)


# --------------------------------------------------------------------------- #
# Tests: Boundary / edge cases (from review recommendations)
# --------------------------------------------------------------------------- #


class TestTriageAgentBoundaries:
    @pytest.mark.asyncio
    async def test_empty_alert_returns_other_event_type(self):
        """Empty alert string → OTHER event type, no crash."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="")
        result = await agent._run(input_)
        assert result.event_type == EventType.OTHER
        assert isinstance(result.entities, EntitySet)

    @pytest.mark.asyncio
    async def test_very_long_alert_does_not_crash(self):
        """Extremely long alert text (>10000 chars) does not crash the agent."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        long_text = "Event: " + "suspicious activity " * 2000  # ~24000 chars
        input_ = _make_input(raw_event_summary=long_text)
        result = await agent._run(input_)
        assert isinstance(result, TriageResult)
        assert result.event_type is not None

    @pytest.mark.asyncio
    async def test_chinese_alert_entity_extraction(self):
        """All-Chinese alert with no English keywords → extracts via regex."""
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)

        # NOTE: IP regex uses \b which requires an ASCII word boundary;
        # Chinese characters are \w in Python 3 Unicode mode, so the IP
        # must be whitespace-separated from adjacent CJK text.
        input_ = _make_input(
            raw_event_summary=(
                "用户张三从主机 PC-FIN-023 执行了 powershell.exe "
                "并上传数据到 203.0.113.88 (evil.example.com)"
            ),
        )
        result = await agent._run(input_)
        assert isinstance(result, TriageResult)
        # Regex should still extract the external IP and domain.
        assert "203.0.113.88" in result.ioc_list
        assert "evil.example.com" in result.ioc_list

    def test_data_exfiltration_without_external_ip_is_medium_severity(self):
        """Data exfiltration WITHOUT external IP → MEDIUM (per ISSUE-032 spec)."""
        severity, need = _apply_severity_rules(
            EventType.DATA_EXFILTRATION,
            alert_text="Data exfiltration to internal server",
        )
        assert severity == Severity.MEDIUM
        assert need is True


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #2 — _read_source_snapshot GuardrailViolationError
# --------------------------------------------------------------------------- #


class TestReadSourceSnapshotGuardrail:
    @pytest.mark.asyncio
    async def test_read_source_snapshot_guardrail_raises(self):
        """GuardrailViolationError from wm.read must propagate, not be swallowed."""
        from app.core.errors import GuardrailViolationError

        class _GuardrailFailingWM:
            """WM whose read() always raises GuardrailViolationError."""

            def __init__(self) -> None:
                self.writer_name = "TriageAgent"
                self._memory = self

            def for_writer(self, writer: str) -> _GuardrailFailingWM:
                return _GuardrailFailingWM()

            async def read(self, event_id: str, key: str) -> object:
                raise GuardrailViolationError(
                    "FIELD_OWNERSHIP: source_snapshot missing TriageAgent",
                    error_code="working_memory_unauthorized_read",
                )

            async def write(self, event_id: str, key: str, value: object) -> None:
                pass

        wm = _GuardrailFailingWM()
        agent = TriageAgent(working_memory=wm)

        with pytest.raises(GuardrailViolationError) as exc_info:
            await agent._read_source_snapshot("evt-001")
        assert "unauthorized_read" in str(exc_info.value.error_code)


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #3 — LLM fallback model not degraded
# --------------------------------------------------------------------------- #


class TestLLMFallbackModel:
    @pytest.mark.asyncio
    async def test_llm_fallback_model_not_degraded(self):
        """LLM fallback model success → degraded=False (not regex fallback)."""
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_entities = EntitySet(
            accounts=[AccountEntity(entity_id="acct-1", username="fallback_user")],
        )
        # Simulate a response from a fallback model (fallback_level=1).
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.ACCOUNT_ANOMALY,
                entities=llm_entities,
                decision_summary="Fallback model reasoning",
            ),
            model_name="fallback-model",
            fallback_level=1,  # primary unavailable, fallback succeeded
        )
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(raw_event_summary="User svc-backup failed to login")
        result = await agent._run(input_)
        # Fallback model succeeded — NOT degraded (only regex fallback is degraded).
        assert result.degraded is False
        assert "Fallback model reasoning" in result.decision_summary


# --------------------------------------------------------------------------- #
# Tests: Should-Fix #4 — write failure records degraded flag
# --------------------------------------------------------------------------- #


class TestWriteFailureDegradedFlag:
    @pytest.mark.asyncio
    async def test_write_failure_records_degraded_flag(self):
        """When triage_result write fails, a triage_degraded flag is persisted."""
        wm = _FailingWriteMockWM(
            writer_name="TriageAgent",
            fail_key="triage_result",
            fail_error=DependencyUnavailableError("Redis down"),
        )
        agent = TriageAgent(working_memory=wm)

        input_ = _make_input(raw_event_summary="Test alert")
        result = await agent._run(input_)
        assert result.degraded is True

        # The triage_degraded flag should have been written (best-effort).
        degraded_flag = await wm.read(input_.event_id, "triage_degraded")
        assert degraded_flag is not None
        assert degraded_flag["degraded"] is True
        assert "triage_result persistence failed" in degraded_flag["reason"]


# --------------------------------------------------------------------------- #
# Tests: Nit #4 — build_triage_messages input validation
# --------------------------------------------------------------------------- #


class TestBuildTriageMessages:
    def test_build_triage_messages_empty_alert_raises(self):
        """Empty alert_text must raise ValueError."""
        from app.agents.prompts.triage_prompt import build_triage_messages

        with pytest.raises(ValueError, match="non-empty string"):
            build_triage_messages("")

    def test_build_triage_messages_none_alert_raises(self):
        """None alert_text must raise ValueError."""
        from app.agents.prompts.triage_prompt import build_triage_messages

        with pytest.raises(ValueError, match="non-empty string"):
            build_triage_messages(None)  # type: ignore[arg-type]

    def test_build_triage_messages_valid_input(self):
        """Valid input returns two messages (system + user)."""
        from app.agents.prompts.triage_prompt import build_triage_messages
        from app.models.agent_io import TriageStructuredPromptContext

        messages = build_triage_messages("Test alert text")
        assert len(messages) == 2
        assert messages[0].role == "system"
        assert messages[1].role == "user"
        assert "Test alert text" in messages[1].content

        grounded = build_triage_messages(
            "Test alert text",
            structured_context=TriageStructuredPromptContext(
                normalized_fields={"src_ip": "10.0.0.1"},
            ),
        )
        assert "normalized_src_ip: 10.0.0.1" in grounded[1].content


# --------------------------------------------------------------------------- #
# Tests: Nit #8 — Chinese alert account extraction
# --------------------------------------------------------------------------- #


class TestChineseAlertAccountExtraction:
    def test_chinese_account_extraction(self):
        """Chinese keyword '账号' triggers account extraction."""
        from app.agents.rules.entity_extraction_rules import extract_entities_regex

        result = extract_entities_regex("账号 zhangsan 从主机登录")
        assert "zhangsan" in result.accounts

    def test_chinese_user_extraction(self):
        """Chinese keyword '用户' triggers account extraction."""
        from app.agents.rules.entity_extraction_rules import extract_entities_regex

        result = extract_entities_regex("用户 lisi 执行了敏感操作")
        assert "lisi" in result.accounts

    def test_chinese_username_extraction(self):
        """Chinese keyword '用户名' triggers account extraction."""
        from app.agents.rules.entity_extraction_rules import extract_entities_regex

        result = extract_entities_regex("用户名 wangwu 登录失败")
        assert "wangwu" in result.accounts


# --------------------------------------------------------------------------- #
# Tests: _resolve_alert_type_from_snapshot
# --------------------------------------------------------------------------- #


class TestResolveAlertTypeFromSnapshot:
    def test_top_level_alert_type_preferred(self):
        snapshot = {
            "alert_type": "host_compromise",
            "raw_alert_snapshot": {"raw": {"alert_type": "malicious_process"}},
        }
        assert _resolve_alert_type_from_snapshot(snapshot) == "host_compromise"

    def test_raw_alert_snapshot_nested_raw_payload(self):
        snapshot = {
            "raw_alert_snapshot": {
                "payload_hash": "abc",
                "raw": {"alert_type": "data_exfiltration"},
            },
        }
        assert _resolve_alert_type_from_snapshot(snapshot) == "data_exfiltration"

    def test_raw_alert_snapshot_direct_alert_type(self):
        snapshot = {
            "raw_alert_snapshot": {"alert_type": "account_anomaly"},
        }
        assert _resolve_alert_type_from_snapshot(snapshot) == "account_anomaly"

    def test_missing_snapshot_returns_none(self):
        assert _resolve_alert_type_from_snapshot(None) is None
        assert _resolve_alert_type_from_snapshot({}) is None


# --------------------------------------------------------------------------- #
# Tests: _map_event_type coverage
# --------------------------------------------------------------------------- #


class TestMapEventTypeCoverage:
    def test_map_event_type_all_eight_exact(self):
        """All 8 EventType enum values are reachable via exact match."""
        for event_type in EventType:
            result = _map_event_type(event_type.value)
            assert result == event_type

    def test_map_event_type_fallback_priority_data_exfiltration(self):
        """'exfil'/'upload' keywords take priority (checked first)."""
        # 'upload' keyword triggers DATA_EXFILTRATION even with other keywords.
        result = _map_event_type(None, "upload and process executed with escalation")
        assert result == EventType.DATA_EXFILTRATION

    def test_map_event_type_fallback_priority_login(self):
        """Login failure keywords fire before 'process' keyword."""
        result = _map_event_type(None, "failed to login process alert")
        assert result == EventType.ACCOUNT_ANOMALY

    def test_map_event_type_escalation_matches(self):
        """Full word 'escalation' matches insider_threat (not partial 'escalat')."""
        result = _map_event_type(None, "privilege escalation detected")
        assert result == EventType.INSIDER_THREAT

    def test_map_event_type_de_escalation_does_not_match(self):
        """'de-escalation' does NOT match \bescalation\b (word-boundary check)."""
        result = _map_event_type(None, "de-escalation procedure completed")
        assert result == EventType.OTHER

    def test_heuristic_detects_schema_export_monitoring(self):
        assert (
            _heuristic_event_type(
                "Correlated alerts across schema-export monitors during maintenance."
            )
            is EventType.DATA_EXFILTRATION
        )

    def test_heuristic_ignores_benign_export_phrase(self):
        assert _heuristic_event_type("User exported audit log for compliance review") is None

    def test_source_authoritative_rejects_other(self):
        assert _source_event_type_authoritative("other") is None
        assert _source_event_type_authoritative("data_exfiltration") is EventType.DATA_EXFILTRATION


# --------------------------------------------------------------------------- #
# Tests: LLM response edge cases
# --------------------------------------------------------------------------- #


class TestLLMResponseEdgeCases:
    @pytest.mark.asyncio
    async def test_llm_parsed_wrong_type_triggers_fallback(self):
        """LLM response.parsed is a valid Pydantic model but wrong type → regex fallback."""
        from pydantic import BaseModel

        from app.core.llm.base import LLMResponse

        class _WrongModel(BaseModel):
            some_field: str = "unexpected"

        llm_response = LLMResponse(
            content="",
            parsed=_WrongModel(some_field="unexpected"),
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(
            raw_event_summary="User admin connected to 203.0.113.88",
        )
        result = await agent._run(input_)
        # Should have fallen back to regex.
        assert result.degraded is True
        assert "203.0.113.88" in result.ioc_list

    @pytest.mark.asyncio
    async def test_llm_response_parsed_none_triggers_fallback(self):
        """LLM response.parsed is None → regex fallback."""
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(
            content='{"event_type":"data_exfiltration"}',
            parsed=None,  # JSON parse failed
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        input_ = _make_input(
            raw_event_summary="Connection from 45.153.12.88 to evil.example.com",
        )
        result = await agent._run(input_)
        assert result.degraded is True
        assert "45.153.12.88" in result.ioc_list


# --------------------------------------------------------------------------- #
# Tests: ReDoS resistance
# --------------------------------------------------------------------------- #


class TestReDoSResistance:
    def test_regex_no_redos_on_long_input(self):
        """Extremely long alert text with edge-case patterns does not hang."""
        import time

        from app.agents.rules.entity_extraction_rules import extract_entities_regex

        # Simulate a very long input with repetitive near-match patterns.
        # Reduced from 5000× to 800× per segment — still exercises the regex
        # engine thoroughly but avoids OS-dependent timing noise.  True
        # catastrophic backtracking would show up even on 50× input as
        # multi-second hangs.
        long_text = "a." * 800 + " " + "b-" * 800 + " final.exe"
        start = time.monotonic()
        result = extract_entities_regex(long_text)
        elapsed = time.monotonic() - start
        # Should complete in well under 2 s (catastrophic backtracking → >10 s).
        assert elapsed < 2.0, f"Regex extraction took {elapsed:.1f}s — possible ReDoS"
        assert "final.exe" in result.processes


# --------------------------------------------------------------------------- #
# Tests: ISSUE-099 source-aware entity merge
# --------------------------------------------------------------------------- #


class TestTriageSourceEntityMerge:
    @pytest.mark.asyncio
    async def test_malicious_process_title_uses_source_hints_not_regex_phrase(self):
        """Title lacks hostname; structured source hints must win over regex noise."""
        from app.core.llm.base import LLMResponse

        llm_response = LLMResponse(content="", parsed=None, model_name="mock")
        llm_client = _MockLLMClient(response=llm_response)

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)

        ref = _source_ref()
        hint = EntitySet(
            hosts=[
                HostEntity(
                    entity_id="src-host-1",
                    hostname="DEV-WKS-012",
                    source_refs=[ref],
                )
            ],
            accounts=[
                AccountEntity(
                    entity_id="src-acct-1",
                    username="dev-user-012",
                    source_refs=[ref],
                )
            ],
            processes=[
                ProcessEntity(
                    entity_id="src-proc-1",
                    name="ransomware_stage.exe",
                    source_refs=[ref],
                )
            ],
        )
        title = "Malicious process spawned — ransomware-like behavior"
        input_ = _make_input(raw_event_summary=title, hint_entities=hint)
        result = await agent._run(input_)

        hostnames = {h.hostname for h in result.entities.hosts}
        assert "DEV-WKS-012" in hostnames
        assert "ransomware-like" not in hostnames
        assert result.entity_provenance_summary
        assert result.degraded is False
        assert "text_extraction_empty" in result.degradation_reasons
        assert isinstance(result.entity_conflicts, list)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "hostname,account,process",
        [
            ("DEV-WKS-012", "dev-user-012", "ransomware_stage.exe"),
            ("WKS-HOST-007", "svc-beacon-007", "beacon.exe"),
            ("JUMP-HOST-001", "ops-jump-001", "mstsc.exe"),
        ],
    )
    async def test_source_hints_merge_for_system_scenarios(
        self, hostname: str, account: str, process: str
    ):
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(working_memory=wm)
        hint = EntitySet(
            hosts=[HostEntity(entity_id="h1", hostname=hostname)],
            accounts=[AccountEntity(entity_id="a1", username=account)],
            processes=[ProcessEntity(entity_id="p1", name=process)],
        )
        input_ = _make_input(
            raw_event_summary="Security alert without embedded entity tokens",
            hint_entities=hint,
        )
        result = await agent._run(input_)
        assert any(h.hostname == hostname for h in result.entities.hosts)
        assert any(a.username == account for a in result.entities.accounts)
        assert any(p.name == process for p in result.entities.processes)

    @pytest.mark.asyncio
    async def test_source_priority_keeps_source_entity_id_when_llm_duplicates(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_entities = EntitySet(hosts=[HostEntity(entity_id="llm-host", hostname="DEV-WKS-012")])
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.MALICIOUS_PROCESS,
                entities=llm_entities,
                reasoning="",
            ),
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)
        ref = _source_ref()
        hint = EntitySet(
            hosts=[
                HostEntity(
                    entity_id="src-host-1",
                    hostname="DEV-WKS-012",
                    source_refs=[ref],
                )
            ],
        )
        input_ = _make_input(
            raw_event_summary="Malicious process spawned — ransomware-like behavior",
            hint_entities=hint,
        )
        result = await agent._run(input_)
        assert len(result.entities.hosts) == 1
        assert result.entities.hosts[0].entity_id == "src-host-1"
        assert result.entity_provenance_summary
        assert result.entity_provenance_summary[0].source_object_id == "INC-099"

    @pytest.mark.asyncio
    async def test_source_wins_over_llm_competing_hostname_with_conflict(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        llm_entities = EntitySet(hosts=[HostEntity(entity_id="llm-host", hostname="WKS-HOST-007")])
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.MALICIOUS_PROCESS,
                entities=llm_entities,
                reasoning="",
            ),
            model_name="mock",
        )
        llm_client = _MockLLMClient(response=llm_response)
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=llm_client, working_memory=wm)
        ref = _source_ref()
        hint = EntitySet(
            hosts=[
                HostEntity(
                    entity_id="src-host-1",
                    hostname="DEV-WKS-012",
                    source_refs=[ref],
                )
            ],
        )
        input_ = _make_input(
            raw_event_summary="Malicious process spawned — ransomware-like behavior",
            hint_entities=hint,
        )
        result = await agent._run(input_)
        assert len(result.entities.hosts) == 1
        assert result.entities.hosts[0].hostname == "DEV-WKS-012"
        assert len(result.entity_conflicts) == 1
        assert "entity conflict" in result.decision_summary.lower()

    @pytest.mark.asyncio
    async def test_account_anomaly_fp_without_source_hints_unchanged(self):
        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        await wm.write(
            "evt-fp",
            "source_snapshot",
            {
                "title": "Bulk login by ops account during change window",
                "alert_type": "account_anomaly",
            },
        )
        agent = TriageAgent(working_memory=wm)
        input_ = _make_input(
            event_id="evt-fp",
            raw_event_summary="Bulk login by ops account during change window",
        )
        result = await agent._run(input_)
        assert result.event_type == EventType.ACCOUNT_ANOMALY
        assert result.degraded is True
        assert not result.entity_provenance_summary

    @pytest.mark.asyncio
    async def test_llm_entities_from_structured_context_pass_validation_on_blurry_title(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse
        from app.models.agent_io import TriageStructuredPromptContext

        blurry = "Correlation: elevated session and volume signals on analytics segment"
        llm_entities = EntitySet(
            hosts=[HostEntity(entity_id="llm-host", hostname="SRV-DB-STG-02")],
            ips=[IPEntity(entity_id="llm-ip", address="198.51.100.44", scope="external")],
            accounts=[AccountEntity(entity_id="llm-acct", username="svc-analytics-47")],
            domains=[DomainEntity(entity_id="llm-dom", fqdn="storage-sync-cdn.example")],
        )
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=llm_entities,
                decision_summary="Structured fields used.",
            ),
            model_name="mock",
        )

        captured_messages: list[object] = []

        class _CapturingLLMClient:
            async def chat(self, messages, **kwargs):
                captured_messages.extend(messages)
                return llm_response

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=_CapturingLLMClient(), working_memory=wm)
        structured = TriageStructuredPromptContext(
            normalized_fields={
                "account": "svc-analytics-47",
                "hostname": "WKS-DATA-031",
                "secondary_host": "SRV-DB-STG-02",
                "src_ip": "198.51.100.44",
                "domain": "storage-sync-cdn.example",
            }
        )
        input_ = _make_input(
            raw_event_summary=blurry,
            structured_prompt_context=structured,
        )
        result = await agent._run(input_)

        user_content = captured_messages[1].content
        assert "normalized_src_ip: 198.51.100.44" in user_content
        assert "normalized_secondary_host: SRV-DB-STG-02" in user_content
        assert any(h.hostname == "SRV-DB-STG-02" for h in result.entities.hosts)
        assert "198.51.100.44" in {ip.address for ip in result.entities.ips}
        assert "svc-analytics-47" in {a.username for a in result.entities.accounts}
        assert "storage-sync-cdn.example" in {d.fqdn for d in result.entities.domains}
        assert result.degraded is False

    @pytest.mark.asyncio
    async def test_llm_non_high_conf_host_kept_when_appendix_grounds_corpus(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse
        from app.models.agent_io import TriageStructuredPromptContext

        blurry = "Correlation: elevated session and volume signals on analytics segment"
        llm_entities = EntitySet(
            hosts=[HostEntity(entity_id="llm-host", hostname="fileserver")],
        )
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=llm_entities,
                decision_summary="Copied fileserver from structured fields.",
            ),
            model_name="mock",
        )

        class _CapturingLLMClient:
            async def chat(self, messages, **kwargs):
                del messages, kwargs
                return llm_response

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=_CapturingLLMClient(), working_memory=wm)
        input_ = _make_input(
            raw_event_summary=blurry,
            structured_prompt_context=TriageStructuredPromptContext(
                normalized_fields={"hostname": "fileserver"},
            ),
        )
        result = await agent._run(input_)
        assert any(h.hostname == "fileserver" for h in result.entities.hosts)
        assert result.degraded is False

    @pytest.mark.asyncio
    async def test_llm_non_high_conf_host_rejected_without_corpus(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse

        blurry = "Correlation: elevated session and volume signals on analytics segment"
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=EntitySet(
                    hosts=[HostEntity(entity_id="llm-host", hostname="fileserver")],
                ),
                decision_summary="Guessed fileserver from title.",
            ),
            model_name="mock",
        )

        class _CapturingLLMClient:
            async def chat(self, messages, **kwargs):
                del messages, kwargs
                return llm_response

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=_CapturingLLMClient(), working_memory=wm)
        result = await agent._run(_make_input(raw_event_summary=blurry))
        assert all(h.hostname != "fileserver" for h in result.entities.hosts)
        assert int(result.entity_rejection_summary.get("total_rejected") or 0) >= 1

    @pytest.mark.asyncio
    async def test_llm_entity_absent_from_corpus_is_dropped_on_blurry_title(self):
        from app.agents.prompts.triage_prompt import TriageLLMResponse
        from app.core.llm.base import LLMResponse
        from app.models.agent_io import TriageStructuredPromptContext

        blurry = "Correlation: elevated session and volume signals on analytics segment"
        llm_entities = EntitySet(
            hosts=[
                HostEntity(entity_id="llm-host", hostname="fileserver"),
                HostEntity(entity_id="llm-phantom", hostname="intranetbox"),
            ],
        )
        llm_response = LLMResponse(
            content="",
            parsed=TriageLLMResponse(
                event_type=EventType.DATA_EXFILTRATION,
                entities=llm_entities,
                decision_summary="Invented intranetbox.",
            ),
            model_name="mock",
        )

        class _CapturingLLMClient:
            async def chat(self, messages, **kwargs):
                del messages, kwargs
                return llm_response

        wm = _MockBoundWorkingMemory(writer_name="TriageAgent")
        agent = TriageAgent(llm_client=_CapturingLLMClient(), working_memory=wm)
        input_ = _make_input(
            raw_event_summary=blurry,
            structured_prompt_context=TriageStructuredPromptContext(
                normalized_fields={"hostname": "fileserver"},
            ),
        )
        result = await agent._run(input_)
        hostnames = {h.hostname for h in result.entities.hosts}
        assert "fileserver" in hostnames
        assert "intranetbox" not in hostnames
        assert int(result.entity_rejection_summary.get("total_rejected") or 0) >= 1


class TestTriageDecisionBasisProjection:
    def test_decision_basis_includes_entity_audit_fields(self):
        from app.services.agent_trace_service import TraceProjection

        ref = _source_ref(source_object_id="INC-trace")
        result = TriageResult(
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            need_investigation=True,
            entity_provenance_summary=[
                {
                    "source_kind": ref.source_kind.value,
                    "source_object_id": ref.source_object_id,
                    "connector_id": ref.connector_id,
                    "entity_category": "hosts",
                }
            ],
            degradation_reasons=["text_extraction_empty"],
            entity_rejection_summary={
                "rejection_counts": {"phrase_without_host_context": 2},
                "total_rejected": 2,
            },
        )
        basis = TraceProjection.decision_basis(result.model_dump(mode="json"))
        assert basis["entity_provenance_summary"]
        assert basis["degradation_reasons"] == ["text_extraction_empty"]
        assert basis["entity_rejection_summary"]["total_rejected"] == 2
        assert (
            basis["entity_rejection_summary"]["rejection_counts"]["phrase_without_host_context"]
            == 2
        )
