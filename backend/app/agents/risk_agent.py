"""RiskAgent: dual-path six-dimension risk scoring (ISSUE-035)."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.agents.base import BaseAgent
from app.agents.confidence_calibration import DEFAULT_TEMPERATURE, calibrate_confidence
from app.agents.prompts.risk_prompt import (
    FACTOR_NAMES,
    RiskScoreLLMResponse,
    build_risk_messages,
)
from app.agents.risk_llm_admissibility import classify_llm_risk_response
from app.agents.risk_scoring_engine import (
    FACTOR_WEIGHTS,
    RiskScoringEngine,
    apply_evidence_limited_adjustments,
    augment_factors_for_evidence_limited,
    severity_from_score,
)
from app.agents.triage_risk_consistency import (
    TRIAGE_RISK_INCONSISTENCY_FLAG,
    should_flag_triage_risk_inconsistency,
)
from app.agents.verdict_resolver import VerdictResolver
from app.core.errors import LLMError
from app.core.llm.prompt_quality import STRUCTURED_PROMPT_TIMEOUT_SECONDS
from app.core.llm.scenario_context import resolve_llm_scenario_id
from app.models.agent_io import (
    LlmAdmissibility,
    RiskAgentInput,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
    TriageResult,
)
from app.models.enums import FinalVerdict
from app.services.risk_verdict_projection import (
    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
)

logger = logging.getLogger(__name__)

LLM_WEIGHT = 0.6
RULE_WEIGHT = 0.4


class RiskAgent(BaseAgent[RiskAgentInput, RiskAssessment]):
    """Six-dimension risk scoring with LLM + rule merge and verdict resolution."""

    agent_name = "risk_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        event_service: Any | None = None,
        scoring_engine: RiskScoringEngine | None = None,
        verdict_resolver: VerdictResolver | None = None,
        calibration_temperature: float = DEFAULT_TEMPERATURE,
        scenario_id: str | None = None,
        degraded_flags: Any | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self.event_service = event_service
        self.scoring_engine = scoring_engine or RiskScoringEngine()
        self.verdict_resolver = verdict_resolver or VerdictResolver()
        self.calibration_temperature = float(calibration_temperature)
        self.scenario_id = scenario_id
        self.degraded_flags = degraded_flags
        self.last_verdict: FinalVerdict | None = None
        self.last_raw_confidence: float | None = None

    async def _run(self, input: RiskAgentInput) -> RiskAssessment:
        fp_match = await self._read_optional(input.event_id, "false_positive_match")
        fp_adjudication = await self._read_optional(input.event_id, "fp_adjudication")
        source_snapshot = await self._read_optional(input.event_id, "source_snapshot")
        if not isinstance(fp_match, dict):
            fp_match = None
        if not isinstance(fp_adjudication, dict):
            fp_adjudication = None
        if not isinstance(source_snapshot, dict):
            source_snapshot = None

        rule_scores = self.scoring_engine.score(
            triage_result=input.triage_result,
            evidence_output=input.evidence_output,
            rag_output=input.rag_output,
            graph_output=input.graph_output,
        )

        llm_scores: dict[str, tuple[float, str]] | None = None
        raw_confidence = float(input.evidence_output.overall_confidence)
        scoring_mode = ScoringMode.RULE_ONLY
        llm_admissibility = (
            LlmAdmissibility.NOT_USED if self.llm_client is None else LlmAdmissibility.INVALID
        )

        if self.llm_client is not None:
            try:
                llm_scores, llm_confidence, llm_admissibility = await self._score_with_llm(
                    input,
                    source_snapshot=source_snapshot,
                )
                if llm_admissibility is LlmAdmissibility.VALID and llm_scores is not None:
                    scoring_mode = ScoringMode.LLM_AND_RULE
                    raw_confidence = max(raw_confidence, llm_confidence)
                else:
                    llm_scores = None
                    scoring_mode = ScoringMode.RULE_ONLY
            except Exception as exc:
                logger.warning(
                    "RiskAgent LLM path failed; falling back to rule_only event=%s err=%s",
                    input.event_id,
                    exc,
                )
                llm_scores = None
                llm_admissibility = LlmAdmissibility.INVALID
                scoring_mode = ScoringMode.RULE_ONLY

        factors = self._merge_factors(rule_scores, llm_scores, scoring_mode)
        risk_score = int(round(sum(factor.weighted_score for factor in factors)))
        risk_score = max(0, min(100, risk_score))
        severity = severity_from_score(risk_score)

        self.last_raw_confidence = raw_confidence
        confidence = calibrate_confidence(
            raw_confidence,
            temperature=self.calibration_temperature,
        )

        adjustment = apply_evidence_limited_adjustments(
            risk_score=risk_score,
            confidence=confidence,
            evidence_output=input.evidence_output,
            source_snapshot=source_snapshot,
        )
        risk_score = adjustment.risk_score
        severity = adjustment.severity
        confidence = adjustment.confidence
        if adjustment.evidence_limited:
            factors = augment_factors_for_evidence_limited(
                factors,
                adjustment=adjustment,
            )

        possible_fp = bool(
            (fp_adjudication or {}).get("recommendation") == "close_as_fp"
            or (fp_match or {}).get("recommendation") in {"investigate_with_flag"}
        ) or (
            input.rag_output is not None
            and input.rag_output.fp_similarity is not None
            and input.rag_output.fp_similarity.max_score >= 0.7
        )

        # Build a provisional assessment for verdict resolution, then attach
        # structured demotion reason codes before persistence (ISSUE-241).
        # risk_score >= 70 still resolves to confirmed_threat first; evidence_limited
        # fail-soft demotion to none is intentional and must remain observable.
        provisional = RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            risk_factors=factors,
            possible_false_positive=possible_fp,
            scoring_mode=scoring_mode,
            evidence_limited=adjustment.evidence_limited,
            severity_floor_applied=adjustment.severity_floor_applied,
            source_risk_baseline=adjustment.source_risk_baseline,
            source_scale_unnormalized=adjustment.source_scale_unnormalized,
            high_source_evidence_limited=adjustment.high_source_evidence_limited,
            llm_admissibility=llm_admissibility,
            confidence_cap_version=adjustment.confidence_cap_version,
        )

        verdict = self.verdict_resolver.resolve(
            provisional,
            false_positive_match=fp_match,
            rag_output=input.rag_output,
            fp_adjudication=fp_adjudication,
        )
        reason_codes: list[str] = []
        if adjustment.evidence_limited and verdict is FinalVerdict.CONFIRMED_THREAT:
            verdict = FinalVerdict.NONE
            reason_codes.append(EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT)

        assessment = provisional.model_copy(update={"verdict_reason_codes": reason_codes})
        await self._write_context(input.event_id, assessment)
        await self._sync_security_event(input.event_id, assessment)

        self.last_verdict = verdict
        await self._persist_verdict(input.event_id, verdict, risk_score=assessment.risk_score)
        await self._maybe_flag_triage_risk_inconsistency(
            event_id=input.event_id,
            triage=input.triage_result,
            risk_score=assessment.risk_score,
            final_verdict=verdict,
        )
        return assessment

    async def _score_with_llm(
        self,
        input: RiskAgentInput,
        *,
        source_snapshot: dict[str, Any] | None = None,
    ) -> tuple[dict[str, tuple[float, str]] | None, float, LlmAdmissibility]:
        assert self.llm_client is not None
        rag_summary = None
        if input.rag_output is not None:
            rag_summary = {
                "attack_techniques": [
                    {
                        "technique_id": m.technique_id,
                        "tactics": list(m.tactics),
                        "match_confidence": m.match_confidence,
                    }
                    for m in input.rag_output.attack_techniques
                ],
                "fp_similarity": (
                    input.rag_output.fp_similarity.model_dump(mode="json")
                    if input.rag_output.fp_similarity is not None
                    else None
                ),
            }
        graph_summary = None
        if input.graph_output is not None and input.graph_output.summary is not None:
            graph_summary = {
                "degraded": input.graph_output.degraded,
                "degraded_reason": input.graph_output.degraded_reason,
                "features": [
                    {
                        "feature_id": feature.feature_id,
                        "feature_kind": feature.feature_kind,
                        "score_hint": feature.score_hint,
                        "evidence_ids": list(feature.evidence_ids),
                    }
                    for feature in input.graph_output.summary.features
                ],
            }

        messages = build_risk_messages(
            triage_result=input.triage_result,
            evidence_output=input.evidence_output,
            rag_summary=rag_summary,
            graph_summary=graph_summary,
            source_snapshot=source_snapshot,
        )
        response = await self.llm_client.chat(
            messages,
            event_id=input.event_id,
            agent_name=self.agent_name,
            prompt_key="risk_score",
            scenario_id=resolve_llm_scenario_id(
                override=self.scenario_id,
                source_snapshot=source_snapshot,
            ),
            json_mode=True,
            response_model=RiskScoreLLMResponse,
            timeout=STRUCTURED_PROMPT_TIMEOUT_SECONDS,
            max_tokens=2048,
        )
        if isinstance(response.parsed, RiskScoreLLMResponse):
            wire = response.parsed
        else:
            data = json.loads(response.content)
            if not isinstance(data, dict):
                raise LLMError("risk_score LLM response is not an object")
            wire = RiskScoreLLMResponse.model_validate(data)

        scores: dict[str, tuple[float, str]] = {}
        for name in FACTOR_NAMES:
            entry = wire.factors.get(name)
            if entry is None or entry.score is None:
                continue
            score = max(0.0, min(100.0, float(entry.score)))
            reason = entry.reason or "llm"
            scores[name] = (score, reason)

        if len(scores) < len(FACTOR_NAMES):
            raise LLMError(
                "risk_score LLM response missing required factors",
                details={"present": sorted(scores)},
            )

        conf = max(0.0, min(1.0, float(wire.raw_confidence)))
        admissibility = classify_llm_risk_response(response)
        if admissibility is not LlmAdmissibility.VALID:
            logger.info(
                "RiskAgent LLM output inadmissible event=%s admissibility=%s",
                input.event_id,
                admissibility.value,
            )
            return None, conf, admissibility
        return scores, conf, admissibility

    def _merge_factors(
        self,
        rule_scores: dict[str, tuple[float, str]],
        llm_scores: dict[str, tuple[float, str]] | None,
        scoring_mode: ScoringMode,
    ) -> list[RiskFactor]:
        factors: list[RiskFactor] = []
        for name in FACTOR_NAMES:
            weight = FACTOR_WEIGHTS[name]
            rule_score, rule_reason = rule_scores[name]
            if scoring_mode is ScoringMode.LLM_AND_RULE and llm_scores is not None:
                llm_score, llm_reason = llm_scores[name]
                merged = LLM_WEIGHT * llm_score + RULE_WEIGHT * rule_score
                reasoning = (
                    f"llm({llm_score:.0f}): {llm_reason}; rule({rule_score:.0f}): {rule_reason}"
                )
            else:
                merged = rule_score
                reasoning = f"rule({rule_score:.0f}): {rule_reason}"
            merged = max(0.0, min(100.0, merged))
            factors.append(
                RiskFactor(
                    factor_name=name,
                    weight=weight,
                    raw_score=merged,
                    weighted_score=merged * weight,
                    reasoning=reasoning,
                )
            )
        return factors

    async def _read_optional(self, event_id: str, key: str) -> Any:
        if self.working_memory is None:
            return None
        try:
            return await self.working_memory.read(event_id, key)
        except Exception:
            logger.debug("optional WM read failed key=%s", key, exc_info=True)
            return None

    async def _write_context(self, event_id: str, assessment: RiskAssessment) -> None:
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "risk_assessment",
                assessment.model_dump(mode="json"),
            )
        except Exception:
            logger.warning(
                "failed to write risk_assessment to working memory event=%s",
                event_id,
                exc_info=True,
            )

    async def _sync_security_event(
        self,
        event_id: str,
        assessment: RiskAssessment,
    ) -> None:
        if self.event_service is None:
            return
        updater = getattr(self.event_service, "update_risk_fields", None)
        if updater is None:
            logger.debug("event_service lacks update_risk_fields; skip DB risk sync")
            return
        try:
            await updater(
                event_id,
                risk_score=assessment.risk_score,
                severity=assessment.severity,
                confidence=assessment.confidence,
                factor_names=[f.factor_name for f in assessment.risk_factors],
                risk_assessment=assessment.model_dump(mode="json"),
            )
        except Exception:
            logger.warning(
                "failed to sync risk fields to security_event event=%s",
                event_id,
                exc_info=True,
            )
            raise

    async def _persist_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        risk_score: int,
    ) -> None:
        if self.event_service is None:
            return
        try:
            await self.event_service.set_final_verdict(
                event_id,
                verdict,
                operator="RiskAgent",
            )
        except Exception:
            logger.warning(
                "set_final_verdict failed event=%s verdict=%s risk_score=%s",
                event_id,
                verdict.value,
                risk_score,
                exc_info=True,
            )
            if (
                verdict in {FinalVerdict.CONFIRMED_THREAT, FinalVerdict.FALSE_POSITIVE}
                or risk_score >= 70
            ):
                raise

    async def _maybe_flag_triage_risk_inconsistency(
        self,
        *,
        event_id: str,
        triage: TriageResult,
        risk_score: int,
        final_verdict: FinalVerdict,
    ) -> None:
        if not should_flag_triage_risk_inconsistency(
            triage=triage,
            risk_score=risk_score,
            final_verdict=final_verdict,
        ):
            return
        if self.degraded_flags is None:
            return
        try:
            await self.degraded_flags.set_flag(
                event_id,
                TRIAGE_RISK_INCONSISTENCY_FLAG,
                True,
                writer="RiskAgent",
            )
        except Exception:
            logger.warning(
                "Failed to persist degraded flag %s for event=%s",
                TRIAGE_RISK_INCONSISTENCY_FLAG,
                event_id,
                exc_info=True,
            )
