"""RiskAgent: dual-path six-dimension risk scoring (ISSUE-035)."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.agents.base import BaseAgent
from app.agents.confidence_calibration import DEFAULT_TEMPERATURE, calibrate_confidence
from app.agents.prompts.risk_prompt import FACTOR_NAMES, build_risk_messages
from app.agents.risk_scoring_engine import FACTOR_WEIGHTS, RiskScoringEngine, severity_from_score
from app.agents.verdict_resolver import VerdictResolver
from app.core.errors import LLMError
from app.models.agent_io import (
    RiskAgentInput,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
)
from app.models.enums import FinalVerdict

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
        self.last_verdict: FinalVerdict | None = None
        self.last_raw_confidence: float | None = None

    async def _run(self, input: RiskAgentInput) -> RiskAssessment:
        storyline = await self._read_optional(input.event_id, "storyline")
        fp_match = await self._read_optional(input.event_id, "false_positive_match")
        if not isinstance(fp_match, dict):
            fp_match = None
        if not isinstance(storyline, dict):
            storyline = None

        rule_scores = self.scoring_engine.score(
            triage_result=input.triage_result,
            evidence_output=input.evidence_output,
            rag_output=input.rag_output,
            storyline=storyline,
        )

        llm_scores: dict[str, tuple[float, str]] | None = None
        raw_confidence = float(input.evidence_output.overall_confidence)
        scoring_mode = ScoringMode.RULE_ONLY

        if self.llm_client is not None:
            try:
                llm_scores, llm_confidence = await self._score_with_llm(input, storyline)
                if llm_scores:
                    scoring_mode = ScoringMode.LLM_AND_RULE
                    raw_confidence = max(raw_confidence, llm_confidence)
            except Exception as exc:
                logger.warning(
                    "RiskAgent LLM path failed; falling back to rule_only event=%s err=%s",
                    input.event_id,
                    exc,
                )
                llm_scores = None
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

        possible_fp = bool(
            (fp_match or {}).get("recommendation") in {"close_as_fp", "investigate_with_flag"}
        ) or (
            input.rag_output is not None
            and input.rag_output.fp_similarity is not None
            and input.rag_output.fp_similarity.max_score >= 0.7
        )

        assessment = RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            risk_factors=factors,
            possible_false_positive=possible_fp,
            scoring_mode=scoring_mode,
        )

        await self._write_context(input.event_id, assessment)
        await self._sync_security_event(input.event_id, assessment)

        verdict = self.verdict_resolver.resolve(
            assessment,
            false_positive_match=fp_match,
            rag_output=input.rag_output,
        )
        self.last_verdict = verdict
        await self._persist_verdict(input.event_id, verdict, risk_score=assessment.risk_score)
        return assessment

    async def _score_with_llm(
        self,
        input: RiskAgentInput,
        storyline: dict[str, Any] | None,
    ) -> tuple[dict[str, tuple[float, str]], float]:
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
        storyline_summary = None
        if storyline is not None:
            storyline_summary = str(storyline.get("narrative_summary") or "")[:500]

        messages = build_risk_messages(
            triage_result=input.triage_result,
            evidence_output=input.evidence_output,
            rag_summary=rag_summary,
            storyline_summary=storyline_summary,
        )
        response = await self.llm_client.chat(
            messages,
            event_id=input.event_id,
            agent_name=self.agent_name,
            prompt_key="risk_score",
            scenario_id=self.scenario_id,
            json_mode=True,
        )
        payload = response.parsed
        if payload is not None and hasattr(payload, "model_dump"):
            data = payload.model_dump(mode="json")
        else:
            data = json.loads(response.content)
        if not isinstance(data, dict):
            raise LLMError("risk_score LLM response is not an object")

        factors_raw = data.get("factors") or {}
        if not isinstance(factors_raw, dict):
            raise LLMError("risk_score LLM factors must be an object")

        scores: dict[str, tuple[float, str]] = {}
        for name in FACTOR_NAMES:
            entry = factors_raw.get(name) or {}
            if not isinstance(entry, dict):
                continue
            raw_score = entry.get("score")
            if raw_score is None:
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            score = max(0.0, min(100.0, score))
            reason = str(entry.get("reason") or entry.get("reasoning") or "llm")
            scores[name] = (score, reason)

        if len(scores) < len(FACTOR_NAMES):
            raise LLMError(
                "risk_score LLM response missing required factors",
                details={"present": sorted(scores)},
            )

        try:
            conf = float(data.get("raw_confidence", 0.75))
        except (TypeError, ValueError):
            conf = 0.75
        conf = max(0.0, min(1.0, conf))
        return scores, conf

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
