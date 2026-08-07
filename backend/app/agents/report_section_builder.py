"""Deterministic 15-section report builder (ISSUE-036)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.agents.triage_risk_consistency import (
    INCONSISTENCY_DISCLOSURE_HEADER,
    should_flag_triage_risk_inconsistency,
)
from app.models.action import Action, ImpactAssessment
from app.models.agent_io import (
    EvidenceOutput,
    ReportPhaseStatus,
    ResponsePlan,
    RiskAssessment,
    TriageResult,
    VerificationResult,
)
from app.models.detection_context_snapshot import DetectionContextSnapshot
from app.models.enums import ActionCategory, FinalVerdict, Severity
from app.models.evidence import EvidenceGap
from app.models.report import ReportSection

PLACEHOLDER_NO_ACTIONS = "暂无处置动作"
PLACEHOLDER_NO_VERIFICATION = "暂无验证结果"
# ISSUE-205: explicit chapter wording by phase-execution state. These replace
# the silent PLACEHOLDER_NO_* fallbacks whenever the unified report input
# builder (app/services/report_input_builder.py) supplies a phase status.
NOT_EXECUTED_ACTIONS = "本调查未执行处置"
NOT_EXECUTED_VERIFICATION = "本调查未执行验证"
# Phase ran but no quotable data — aligned with ISSUE-212's
# ``incomplete_placeholder`` contract: never masquerade as an empty result.
INCOMPLETE_ACTIONS_PLACEHOLDER = "incomplete_placeholder：处置阶段已执行，但缺少可引用的处置记录"
INCOMPLETE_VERIFICATION_PLACEHOLDER = (
    "incomplete_placeholder：验证阶段已执行，但缺少可引用的验证记录"
)
# Backing data exists but the backfill read failed — chapter is degraded.
UNAVAILABLE_ACTIONS = "处置数据不可用：读取已有处置记录失败，本章节标记 degraded"
UNAVAILABLE_VERIFICATION = "验证数据不可用：读取已有验证记录失败，本章节标记 degraded"
PLACEHOLDER_LOW_RISK_NO_EVIDENCE = "低危快结案：未执行证据采集"
INVESTIGATION_LIMITATION_HEADER = (
    "调查限制：证据采集未完成或结果为空；以下内容引用来源摘要与缺口记录，非推断性攻击还原。"
)
SOURCE_SUMMARY_LABEL = "来源摘要（非证据）"

SECTION_SPECS: tuple[tuple[str, str], ...] = (
    ("overview", "事件概述"),
    ("severity_level", "严重级别"),
    ("risk_scoring", "风险评分"),
    ("involved_accounts", "涉及账号"),
    ("involved_assets", "涉及资产"),
    ("involved_processes", "涉及进程"),
    ("involved_files", "涉及文件"),
    ("involved_external_addresses", "涉及外部地址"),
    ("evidence_chain", "证据链"),
    ("attack_storyline", "攻击故事线"),
    ("attack_mapping", "攻击映射"),
    ("executed_actions", "已执行处置"),
    ("verification_results", "验证结果"),
    ("recommendations", "处置建议"),
    ("appendix_index", "附录索引"),
)

SECTION_KEYS: tuple[str, ...] = tuple(key for key, _ in SECTION_SPECS)
SECTION_TITLES: dict[str, str] = dict(SECTION_SPECS)


def _fmt_ts(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    return value.isoformat()


def _bullet(lines: list[str], empty: str) -> str:
    cleaned = [line.strip() for line in lines if line and str(line).strip()]
    if not cleaned:
        return empty
    return "\n".join(f"- {line}" for line in cleaned)


def _source_summary_lines(source_snapshot: dict[str, Any] | None) -> list[str]:
    if not isinstance(source_snapshot, dict):
        return []
    lines: list[str] = []
    for key in ("title", "alert_type", "description", "severity"):
        value = source_snapshot.get(key)
        if value not in (None, ""):
            lines.append(f"{key}={_truncate_field(value)}")
    normalized = source_snapshot.get("normalized")
    if isinstance(normalized, dict):
        for key in ("title", "description", "alert_type"):
            value = normalized.get(key)
            if value not in (None, ""):
                lines.append(f"normalized.{key}={_truncate_field(value)}")
    return lines


def _truncate_field(value: Any, *, max_chars: int = 240) -> str:
    text = str(value).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _format_evidence_gaps(gaps: list[EvidenceGap]) -> list[str]:
    lines: list[str] = []
    for gap in gaps:
        detail = ""
        if gap.detail:
            detail = f" | detail={_truncate_field(gap.detail)}"
        lines.append(f"gap: {gap.missing_source.value} | reason={gap.reason}{detail}")
    return lines


def _use_low_risk_no_evidence_placeholder(
    *,
    risk_assessment: RiskAssessment,
    evidence_output: EvidenceOutput,
) -> bool:
    return (
        risk_assessment.severity is Severity.LOW
        and not risk_assessment.evidence_limited
        and not evidence_output.gaps
        and not evidence_output.evidence_list
    )


class ReportSectionBuilder:
    """Build the locked 15-section skeleton from EventContext facts."""

    def build(
        self,
        *,
        event_id: str,
        evidence_output: EvidenceOutput,
        risk_assessment: RiskAssessment,
        triage_result: TriageResult | None = None,
        response_plan: ResponsePlan | None = None,
        verification_result: VerificationResult | None = None,
        response_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED,
        verification_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED,
        rag_output: dict[str, Any] | None = None,
        final_verdict: FinalVerdict = FinalVerdict.NONE,
        false_positive_match: dict[str, Any] | None = None,
        fp_adjudication: dict[str, Any] | None = None,
        content_sha256: str | None = None,
        escalated: bool = False,
        replan_count: int = 0,
        impact_assessments: list[ImpactAssessment] | list[dict[str, Any]] | None = None,
        source_snapshot: dict[str, Any] | None = None,
        triage_degraded: dict[str, Any] | None = None,
        detection_context_snapshot: DetectionContextSnapshot | None = None,
    ) -> list[ReportSection]:
        # Prefer triage entities; otherwise derive labels from evidence raw/related.
        account_lines, asset_lines, process_lines, file_lines, external_lines = self._entity_lines(
            triage_result, evidence_output
        )
        response_actions = self._response_actions(response_plan)

        overview = self._overview(
            event_id=event_id,
            triage_result=triage_result,
            risk_assessment=risk_assessment,
            final_verdict=final_verdict,
            evidence_output=evidence_output,
            false_positive_match=false_positive_match,
            fp_adjudication=fp_adjudication,
            escalated=escalated,
            replan_count=replan_count,
            source_snapshot=source_snapshot,
            triage_degraded=triage_degraded,
            detection_context_snapshot=detection_context_snapshot,
        )
        severity_level = (
            f"severity={risk_assessment.severity.value}\n"
            f"risk_score={risk_assessment.risk_score}\n"
            f"confidence={risk_assessment.confidence:.4f}\n"
            f"possible_false_positive={risk_assessment.possible_false_positive}\n"
            f"scoring_mode={risk_assessment.scoring_mode.value}\n"
            f"evidence_limited={risk_assessment.evidence_limited}\n"
            f"severity_floor_applied={risk_assessment.severity_floor_applied}\n"
            f"high_source_evidence_limited={risk_assessment.high_source_evidence_limited}\n"
            f"source_risk_baseline={risk_assessment.source_risk_baseline}\n"
            f"source_scale_unnormalized={risk_assessment.source_scale_unnormalized}\n"
            f"final_verdict={final_verdict.value}"
        )
        risk_scoring = self._risk_scoring(risk_assessment)
        evidence_chain = self._evidence_chain(
            evidence_output,
            risk_assessment=risk_assessment,
            source_snapshot=source_snapshot,
        )
        storyline = self._attack_storyline(
            evidence_output,
            source_snapshot=source_snapshot,
            risk_assessment=risk_assessment,
        )
        attack_mapping = self._attack_mapping(
            evidence_output,
            rag_output,
            detection_context_snapshot=detection_context_snapshot,
        )
        executed = self._executed_actions(response_actions, response_phase_status)
        verification = self._verification_results(verification_result, verification_phase_status)
        recommendations = self._recommendations(
            risk_assessment=risk_assessment,
            response_actions=response_actions,
            final_verdict=final_verdict,
            false_positive_match=false_positive_match,
            fp_adjudication=fp_adjudication,
            escalated=escalated,
            replan_count=replan_count,
            impact_assessments=impact_assessments,
        )
        appendix = self._appendix(
            event_id=event_id,
            evidence_output=evidence_output,
            response_actions=response_actions,
            content_sha256=content_sha256,
            detection_context_snapshot=detection_context_snapshot,
        )

        contents: dict[str, str] = {
            "overview": overview,
            "severity_level": severity_level,
            "risk_scoring": risk_scoring,
            "involved_accounts": _bullet(account_lines, "暂无涉及账号"),
            "involved_assets": _bullet(asset_lines, "暂无涉及资产"),
            "involved_processes": _bullet(process_lines, "暂无涉及进程"),
            "involved_files": _bullet(file_lines, "暂无涉及文件"),
            "involved_external_addresses": _bullet(external_lines, "暂无涉及外部地址"),
            "evidence_chain": evidence_chain,
            "attack_storyline": storyline,
            "attack_mapping": attack_mapping,
            "executed_actions": executed,
            "verification_results": verification,
            "recommendations": recommendations,
            "appendix_index": appendix,
        }
        data_by_key: dict[str, dict[str, Any]] = {
            "risk_scoring": {
                "risk_score": risk_assessment.risk_score,
                "factors": [
                    {
                        "factor_name": f.factor_name,
                        "weight": f.weight,
                        "raw_score": f.raw_score,
                        "weighted_score": f.weighted_score,
                    }
                    for f in risk_assessment.risk_factors
                ],
            },
            "executed_actions": {
                "response_action_count": len(response_actions),
                "action_ids": [a.action_id for a in response_actions],
                **(
                    {"degraded": True}
                    if response_phase_status is ReportPhaseStatus.UNAVAILABLE
                    else {}
                ),
            },
            "verification_results": {
                "overall_status": (
                    verification_result.overall_status.value
                    if verification_result is not None
                    else None
                ),
                **(
                    {"degraded": True}
                    if verification_phase_status is ReportPhaseStatus.UNAVAILABLE
                    else {}
                ),
            },
            "appendix_index": {
                "content_sha256": content_sha256,
                "evidence_count": len(evidence_output.evidence_list),
                "response_action_count": len(response_actions),
                "detection_context_snapshot_id": (
                    detection_context_snapshot.snapshot_id
                    if detection_context_snapshot is not None
                    else None
                ),
            },
        }

        sections: list[ReportSection] = []
        for key, title in SECTION_SPECS:
            sections.append(
                ReportSection(
                    key=key,
                    title=title,
                    content=contents[key],
                    data=data_by_key.get(key, {}),
                )
            )
        return sections

    def default_title(self, triage_result: TriageResult | None, event_id: str) -> str:
        if triage_result is not None:
            return f"调查报告 · {triage_result.event_type.value} · {event_id}"
        return f"调查报告 · {event_id}"

    def default_summary(
        self,
        *,
        risk_assessment: RiskAssessment,
        final_verdict: FinalVerdict,
        triage_result: TriageResult | None,
    ) -> str:
        event_type = triage_result.event_type.value if triage_result else "unknown"
        return (
            f"event_type={event_type}; severity={risk_assessment.severity.value}; "
            f"risk_score={risk_assessment.risk_score}; verdict={final_verdict.value}"
        )

    def _entity_lines(
        self,
        triage_result: TriageResult | None,
        evidence_output: EvidenceOutput,
    ) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
        accounts: list[str] = []
        assets: list[str] = []
        processes: list[str] = []
        files: list[str] = []
        externals: list[str] = []

        if triage_result is not None:
            for acc in triage_result.entities.accounts:
                accounts.append(acc.username or acc.entity_id)
            for host in triage_result.entities.hosts:
                label = host.hostname or host.ip or host.entity_id
                assets.append(label)
            for proc in triage_result.entities.processes:
                processes.append(proc.name or proc.entity_id)
            for file_ent in triage_result.entities.files:
                files.append(file_ent.path or file_ent.name or file_ent.entity_id)
            for ip in triage_result.entities.ips:
                if ip.scope == "external" or ip.scope == "unknown":
                    externals.append(ip.address or ip.entity_id)
            for domain in triage_result.entities.domains:
                externals.append(domain.fqdn or domain.entity_id)
            for ioc in triage_result.ioc_list:
                if ioc not in externals:
                    externals.append(ioc)

        # Supplement from evidence when triage entities are sparse.
        for item in evidence_output.evidence_list:
            raw = item.raw_data or {}
            if isinstance(raw, dict):
                if raw.get("account"):
                    accounts.append(str(raw["account"]))
                if raw.get("hostname"):
                    assets.append(str(raw["hostname"]))
                if raw.get("process_name") or raw.get("process"):
                    processes.append(str(raw.get("process_name") or raw.get("process")))
                if raw.get("file_path") or raw.get("path"):
                    files.append(str(raw.get("file_path") or raw.get("path")))
                if raw.get("dst_ip"):
                    externals.append(str(raw["dst_ip"]))
                if raw.get("indicator"):
                    externals.append(str(raw["indicator"]))
            for related in item.related_entities:
                text = str(related)
                if text.startswith("PC-") or "FIN" in text:
                    assets.append(text)

        def _uniq(values: list[str]) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for value in values:
                key = value.strip()
                if not key or key in seen:
                    continue
                seen.add(key)
                out.append(key)
            return out

        return (
            _uniq(accounts),
            _uniq(assets),
            _uniq(processes),
            _uniq(files),
            _uniq(externals),
        )

    def _overview(
        self,
        *,
        event_id: str,
        triage_result: TriageResult | None,
        risk_assessment: RiskAssessment,
        final_verdict: FinalVerdict,
        evidence_output: EvidenceOutput,
        false_positive_match: dict[str, Any] | None = None,
        fp_adjudication: dict[str, Any] | None = None,
        escalated: bool = False,
        replan_count: int = 0,
        source_snapshot: dict[str, Any] | None = None,
        triage_degraded: dict[str, Any] | None = None,
        detection_context_snapshot: DetectionContextSnapshot | None = None,
    ) -> str:
        event_type = triage_result.event_type.value if triage_result else "unknown"
        reasoning = (triage_result.reasoning if triage_result else "") or ""
        lines = [
            f"event_id: {event_id}",
            f"event_type: {event_type}",
            f"severity: {risk_assessment.severity.value}",
            f"risk_score: {risk_assessment.risk_score}",
            f"final_verdict: {final_verdict.value}",
            f"evidence_count: {len(evidence_output.evidence_list)}",
            f"collection_status: {evidence_output.collection_status.value}",
            f"evidence_limited: {risk_assessment.evidence_limited}",
        ]
        if detection_context_snapshot is not None:
            lines.extend(
                [
                    f"detection_context_snapshot_id: {detection_context_snapshot.snapshot_id}",
                    f"detection_context_revision: {detection_context_snapshot.revision}",
                    f"detection_context_hash: {detection_context_snapshot.content_hash}",
                    f"detection_promotion_id: {detection_context_snapshot.promotion_id}",
                    f"detection_matched_value: {detection_context_snapshot.scores.matched_value}",
                    f"detection_operator: {detection_context_snapshot.scores.operator}",
                ]
            )
            if detection_context_snapshot.scores.detection_score is not None:
                lines.append(
                    f"detection_score: {detection_context_snapshot.scores.detection_score:.4f}"
                )
        if triage_result is not None and triage_result.degraded:
            lines.append("triage_degraded: true")
            for reason in triage_result.degradation_reasons:
                lines.append(f"triage_degradation_reason: {reason}")
        elif isinstance(triage_degraded, dict) and triage_degraded.get("degraded"):
            lines.append("triage_degraded: true")
            for reason in triage_degraded.get("degradation_reasons") or []:
                lines.append(f"triage_degradation_reason: {reason}")
        if triage_result is not None and triage_result.entity_rejection_summary:
            summary = triage_result.entity_rejection_summary
            total_rejected = summary.get("total_rejected")
            if total_rejected is not None:
                lines.append(f"entity_rejection_total: {total_rejected}")
            rejection_counts = summary.get("rejection_counts")
            if isinstance(rejection_counts, dict) and rejection_counts:
                formatted = ", ".join(f"{key}={value}" for key, value in rejection_counts.items())
                lines.append(f"entity_rejection_counts: {formatted}")
        lines.extend(
            self._fp_basis_lines(
                false_positive_match=false_positive_match,
                fp_adjudication=fp_adjudication,
            )
        )
        if escalated:
            lines.append(
                "human_escalation: 本事件已完成 "
                f"{replan_count} 轮重规划仍未能通过验证，已标记 escalated=true，"
                "需安全运营人员接管后续调查与处置。"
            )
        if reasoning:
            lines.append(f"triage_reasoning: {reasoning}")
        if triage_result is not None and should_flag_triage_risk_inconsistency(
            triage=triage_result,
            risk_score=risk_assessment.risk_score,
            final_verdict=final_verdict,
        ):
            lines.append("triage_risk_inconsistency: true")
            lines.append(INCONSISTENCY_DISCLOSURE_HEADER)
        if not evidence_output.evidence_list:
            lines.append(INVESTIGATION_LIMITATION_HEADER)
            source_lines = _source_summary_lines(source_snapshot)
            if source_lines:
                lines.append(f"{SOURCE_SUMMARY_LABEL}:")
                lines.extend(f"- {line}" for line in source_lines)
            gap_lines = _format_evidence_gaps(evidence_output.gaps)
            if gap_lines:
                lines.append("evidence_gaps:")
                lines.extend(f"- {line}" for line in gap_lines)
            elif _use_low_risk_no_evidence_placeholder(
                risk_assessment=risk_assessment,
                evidence_output=evidence_output,
            ):
                lines.append(PLACEHOLDER_LOW_RISK_NO_EVIDENCE)
        return "\n".join(lines)

    def _fp_basis_lines(
        self,
        *,
        false_positive_match: dict[str, Any] | None = None,
        fp_adjudication: dict[str, Any] | None = None,
    ) -> list[str]:
        if (
            isinstance(fp_adjudication, dict)
            and fp_adjudication.get("recommendation") == "close_as_fp"
        ):
            lines: list[str] = ["fp_decision: post_evidence_close_as_fp"]
            window_id = fp_adjudication.get("matched_window_id")
            if window_id:
                lines.append(f"fp_matched_window_id: {window_id}")
            evidence_ids = fp_adjudication.get("supporting_evidence_ids") or []
            if evidence_ids:
                lines.append(f"fp_supporting_evidence_ids: {','.join(evidence_ids)}")
            matched = fp_adjudication.get("matched_conditions") or []
            if matched:
                lines.append(f"fp_matched_conditions: {','.join(matched)}")
            score = fp_adjudication.get("max_score")
            if score is not None:
                lines.append(f"fp_adjudication_score: {score}")
            return lines

        if not isinstance(false_positive_match, dict):
            return []
        lines = []
        case_id = false_positive_match.get("matched_case_id")
        if case_id:
            lines.append(f"fp_matched_case_id: {case_id}")
        pattern = false_positive_match.get("matched_pattern") or false_positive_match.get(
            "matched_rule"
        )
        if pattern:
            lines.append(f"fp_matched_pattern: {pattern}")
        source = false_positive_match.get("source")
        if source:
            lines.append(f"fp_match_source: {source}")
        score = false_positive_match.get("max_score")
        if score is not None:
            lines.append(f"fp_max_score: {score}")
        return lines

    def _risk_scoring(self, risk_assessment: RiskAssessment) -> str:
        llm_adm = (
            risk_assessment.llm_admissibility.value
            if risk_assessment.llm_admissibility is not None
            else None
        )
        lines = [
            f"total_score={risk_assessment.risk_score}",
            f"severity={risk_assessment.severity.value}",
            f"scoring_mode={risk_assessment.scoring_mode.value}",
            f"evidence_limited={risk_assessment.evidence_limited}",
            f"severity_floor_applied={risk_assessment.severity_floor_applied}",
            f"high_source_evidence_limited={risk_assessment.high_source_evidence_limited}",
            f"source_risk_baseline={risk_assessment.source_risk_baseline}",
            f"source_scale_unnormalized={risk_assessment.source_scale_unnormalized}",
            f"llm_admissibility={llm_adm}",
            f"confidence_cap_version={risk_assessment.confidence_cap_version}",
            (
                "verdict_reason_codes="
                + (
                    ",".join(risk_assessment.verdict_reason_codes)
                    if risk_assessment.verdict_reason_codes
                    else "none"
                )
            ),
            "six_dimension_breakdown:",
        ]
        if risk_assessment.evidence_limited:
            baseline = risk_assessment.source_risk_baseline
            if baseline is not None and baseline != risk_assessment.risk_score:
                lines.append(
                    "score_divergence: "
                    f"final_score={risk_assessment.risk_score} "
                    f"source_baseline={baseline} "
                    "(evidence_limited floor/cap applied)"
                )
            elif baseline is not None:
                lines.append(
                    "score_alignment: "
                    f"final_score={risk_assessment.risk_score} "
                    f"source_baseline={baseline}"
                )
            cap_note = (
                f"confidence_cap_version={risk_assessment.confidence_cap_version}"
                if risk_assessment.confidence_cap_version
                else "confidence_cap_version=none"
            )
            lines.append(
                "evidence_limited_note: threat signal retained while evidence "
                f"collection failed or returned empty; {cap_note}. "
                "Do not equate risk_score>=70 with confirmed_threat when "
                "verdict_reason_codes include evidence_limited demotion."
            )
        for factor in risk_assessment.risk_factors:
            lines.append(
                f"- {factor.factor_name}: raw={factor.raw_score:.1f} "
                f"weight={factor.weight:.2f} weighted={factor.weighted_score:.1f} "
                f"| {factor.reasoning}"
            )
        if len(risk_assessment.risk_factors) < 6:
            lines.append("- note: fewer than six factors present in assessment")
        return "\n".join(lines)

    def _evidence_chain(
        self,
        evidence_output: EvidenceOutput,
        *,
        risk_assessment: RiskAssessment,
        source_snapshot: dict[str, Any] | None = None,
    ) -> str:
        if not evidence_output.evidence_list:
            lines: list[str] = [INVESTIGATION_LIMITATION_HEADER]
            source_lines = _source_summary_lines(source_snapshot)
            if source_lines:
                lines.append(f"{SOURCE_SUMMARY_LABEL}:")
                lines.extend(f"- {line}" for line in source_lines)
            gap_lines = _format_evidence_gaps(evidence_output.gaps)
            if gap_lines:
                lines.append("evidence_gaps:")
                lines.extend(f"- {line}" for line in gap_lines)
            elif _use_low_risk_no_evidence_placeholder(
                risk_assessment=risk_assessment,
                evidence_output=evidence_output,
            ):
                lines.append(PLACEHOLDER_LOW_RISK_NO_EVIDENCE)
            return "\n".join(lines)
        lines = []
        # Stable sort: missing timestamps first, then chronological.
        ordered = sorted(
            evidence_output.evidence_list,
            key=lambda e: (
                e.timestamp is None,
                e.timestamp or datetime(1970, 1, 1),
            ),
        )
        for item in ordered:
            lines.append(
                f"{_fmt_ts(item.timestamp)} | evidence_id={item.evidence_id} | "
                f"{item.source.value} | {item.evidence_type} | "
                f"conf={item.confidence:.2f} | {item.description}"
            )
        if evidence_output.conflicts:
            lines.append(f"conflicts={len(evidence_output.conflicts)}")
        gap_lines = _format_evidence_gaps(evidence_output.gaps)
        if gap_lines:
            lines.append("evidence_gaps:")
            lines.extend(f"- {line}" for line in gap_lines)
        return "\n".join(lines)

    def _attack_storyline(
        self,
        evidence_output: EvidenceOutput,
        *,
        source_snapshot: dict[str, Any] | None = None,
        risk_assessment: RiskAssessment | None = None,
    ) -> str:
        """Fallback storyline from evidence timeline (StorylineService is post-report)."""
        if not evidence_output.evidence_list:
            lines = [
                INVESTIGATION_LIMITATION_HEADER,
                "attack_storyline_limitation: 无 evidence_id 可引用，不推断攻击阶段。",
            ]
            source_lines = _source_summary_lines(source_snapshot)
            if source_lines:
                lines.append(f"{SOURCE_SUMMARY_LABEL}:")
                lines.extend(f"- {line}" for line in source_lines)
            gap_lines = _format_evidence_gaps(evidence_output.gaps)
            if gap_lines:
                lines.append("evidence_gaps:")
                lines.extend(f"- {line}" for line in gap_lines)
            elif risk_assessment is not None and _use_low_risk_no_evidence_placeholder(
                risk_assessment=risk_assessment,
                evidence_output=evidence_output,
            ):
                lines.append(PLACEHOLDER_LOW_RISK_NO_EVIDENCE)
            return "\n".join(lines)
        # Stable sort: missing timestamps first, then chronological.
        ordered = sorted(
            evidence_output.evidence_list,
            key=lambda e: (
                e.timestamp is None,
                e.timestamp or datetime(1970, 1, 1),
            ),
        )
        lines = ["证据时间线（StorylineService 后置，此处使用证据兜底）："]
        for idx, item in enumerate(ordered, start=1):
            tech = f" [{item.mitre_technique}]" if item.mitre_technique else ""
            lines.append(
                f"{idx}. {_fmt_ts(item.timestamp)} | evidence_id={item.evidence_id} — "
                f"{item.description}{tech}"
            )
        return "\n".join(lines)

    def _attack_mapping(
        self,
        evidence_output: EvidenceOutput,
        rag_output: dict[str, Any] | None,
        *,
        detection_context_snapshot: DetectionContextSnapshot | None = None,
    ) -> str:
        if detection_context_snapshot is not None and detection_context_snapshot.attack_refs:
            snapshot_techniques = [
                (
                    f"{ref.technique_id} {ref.technique_name}".strip()
                    if ref.technique_name
                    else ref.technique_id
                )
                for ref in detection_context_snapshot.attack_refs
            ]
            return _bullet(snapshot_techniques, "暂无 ATT&CK 技术映射")

        techniques: list[str] = []
        for item in evidence_output.evidence_list:
            if item.mitre_technique:
                techniques.append(item.mitre_technique)
        if isinstance(rag_output, dict):
            for match in rag_output.get("attack_techniques") or []:
                if isinstance(match, dict) and match.get("technique_id"):
                    name = match.get("technique_name") or ""
                    techniques.append(f"{match['technique_id']} {name}".strip())
        techniques = list(dict.fromkeys(techniques))
        if not techniques:
            return "暂无 ATT&CK 技术映射"
        return _bullet(techniques, "暂无 ATT&CK 技术映射")

    def _response_actions(self, response_plan: ResponsePlan | None) -> list[Action]:
        if response_plan is None:
            return []
        # Count disposition by ActionCategory.RESPONSE — never hard-code tool names.
        return [
            action
            for action in response_plan.actions
            if action.action_category is ActionCategory.RESPONSE
        ]

    def _executed_actions(
        self,
        response_actions: list[Action],
        response_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED,
    ) -> str:
        if response_actions:
            lines: list[str] = []
            for action in response_actions:
                wb = (
                    action.writeback_status.value if action.writeback_status is not None else "null"
                )
                effect = action.effect_verification_status or "unset"
                lines.append(
                    f"{action.action_id} | {action.action_name} | tool={action.tool_name} | "
                    f"status={action.status.value} | effect_verification={effect} | "
                    f"writeback_status={wb} | target={action.target or '-'}"
                )
            return "\n".join(lines)
        # ISSUE-205: no quotable RESPONSE actions — wording depends on whether
        # the response phase ran at all. Never reuse 「暂无处置动作」, which
        # would masquerade as an executed-but-empty result.
        if response_phase_status is ReportPhaseStatus.UNAVAILABLE:
            return UNAVAILABLE_ACTIONS
        if response_phase_status in (
            ReportPhaseStatus.EXECUTED,
            ReportPhaseStatus.INCOMPLETE,
        ):
            return INCOMPLETE_ACTIONS_PLACEHOLDER
        return NOT_EXECUTED_ACTIONS

    def _verification_results(
        self,
        verification_result: VerificationResult | None,
        verification_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED,
    ) -> str:
        if verification_result is not None and verification_result.results:
            lines = [
                f"overall_status={verification_result.overall_status.value}",
                f"verification_phase={verification_result.verification_phase.value}",
            ]
            for item in verification_result.results:
                wb = item.writeback_status.value if item.writeback_status is not None else "null"
                receipt = ",".join(item.writeback_ids) if item.writeback_ids else "-"
                lines.append(
                    f"{item.action_id} | effect={item.effect_status.value} | "
                    f"writeback_status={wb} | readiness={item.writeback_readiness.value} | "
                    f"receipt_refs={receipt} | detail={item.detail or '-'}"
                )
            return "\n".join(lines)
        # ISSUE-205: distinguish "phase never ran" from degraded reads and
        # incomplete data — see _executed_actions for the same contract.
        if verification_phase_status is ReportPhaseStatus.UNAVAILABLE:
            return UNAVAILABLE_VERIFICATION
        if verification_phase_status in (
            ReportPhaseStatus.EXECUTED,
            ReportPhaseStatus.INCOMPLETE,
        ):
            return INCOMPLETE_VERIFICATION_PLACEHOLDER
        return NOT_EXECUTED_VERIFICATION

    def _impact_assessment_hints(
        self,
        response_actions: list[Action],
        impact_assessments: list[ImpactAssessment] | list[dict[str, Any]] | None,
    ) -> list[str]:
        if not impact_assessments or not response_actions:
            return []

        by_action_id: dict[str, dict[str, Any]] = {}
        for item in impact_assessments:
            if isinstance(item, ImpactAssessment):
                payload = item.model_dump(mode="json")
            elif isinstance(item, dict):
                payload = item
            else:
                continue
            action_id = payload.get("action_id")
            if isinstance(action_id, str) and action_id:
                by_action_id[action_id] = payload

        hints: list[str] = []
        for action in response_actions:
            raw = by_action_id.get(action.action_id)
            if raw is None:
                continue
            payload = raw
            level = action.action_level.value if action.action_level else ""
            disruption = str(payload.get("business_disruption", "")).lower()
            score = payload.get("impact_score", 0)
            if level in {"l4", "l5"} and disruption == "high":
                target = action.target or "-"
                hints.append(
                    "高影响处置复核："
                    f"{action.tool_name}（target={target}）"
                    f" impact_score={score}、business_disruption=high，"
                    "建议人工复核后再执行。"
                )
            if len(hints) >= 2:
                break
        return hints

    def _recommendations(
        self,
        *,
        risk_assessment: RiskAssessment,
        response_actions: list[Action],
        final_verdict: FinalVerdict,
        false_positive_match: dict[str, Any] | None = None,
        fp_adjudication: dict[str, Any] | None = None,
        escalated: bool = False,
        replan_count: int = 0,
        impact_assessments: list[ImpactAssessment] | list[dict[str, Any]] | None = None,
    ) -> str:
        tips: list[str] = []
        tips.extend(self._impact_assessment_hints(response_actions, impact_assessments))
        if escalated:
            tips.append(
                "人工升级：自动重规划已达上限（"
                f"replan_count={replan_count}，escalated=true），"
                "请安全运营人员复核失败动作、决定是否人工处置或关闭事件。"
            )
        if risk_assessment.severity in {Severity.HIGH, Severity.CRITICAL}:
            tips.append("对高价值主机执行隔离或进程阻断，并复核外联阻断生效。")
            tips.append("冻结涉事账号会话并强制改密，排查横向移动痕迹。")
            tips.append("保全敏感文件访问与外传日志，评估数据泄露范围。")
        elif final_verdict in {
            FinalVerdict.FALSE_POSITIVE,
            FinalVerdict.POSSIBLE_FALSE_POSITIVE,
        }:
            if (
                isinstance(fp_adjudication, dict)
                and fp_adjudication.get("recommendation") == "close_as_fp"
            ):
                window_id = fp_adjudication.get("matched_window_id")
                if window_id:
                    tips.append(
                        f"误报依据：post-evidence 裁决匹配变更窗口「{window_id}」，"
                        "建议沉淀为检测白名单。"
                    )
                else:
                    tips.append(
                        "误报依据：post-evidence 裁决确认授权变更窗口，建议沉淀为检测白名单。"
                    )
            else:
                fp_pattern = None
                if isinstance(false_positive_match, dict):
                    fp_pattern = false_positive_match.get("matched_pattern")
                    if fp_pattern is None:
                        fp_pattern = false_positive_match.get("matched_rule")
                if fp_pattern:
                    tips.append(f"误报依据：匹配已知模式「{fp_pattern}」，建议沉淀为检测白名单。")
                else:
                    tips.append("按误报案例沉淀规则，降低同类告警噪音。")
            tips.append("复核检测阈值与基线，避免重复误报。")
            tips.append("保留审计记录后关闭事件，并同步来源处置状态。")
        else:
            tips.append("持续观察账号与主机行为，补充缺失证据源。")
            tips.append("核对威胁情报命中与资产重要性后再决定升级。")
            tips.append("若风险上升，按 playbook 启动处置与写回闭环。")
        if not response_actions:
            tips.append("当前无 RESPONSE 处置动作；确认 disposition_policy 后再规划。")
        tips.append("报告仅存 ShadowTrace 本地，禁止写入 DispositionCommand。")
        # Keep 3–5 recommendations (impact hints may consume slots first).
        return "\n".join(f"{idx}. {tip}" for idx, tip in enumerate(tips[:5], start=1))

    def _appendix(
        self,
        *,
        event_id: str,
        evidence_output: EvidenceOutput,
        response_actions: list[Action],
        content_sha256: str | None,
        detection_context_snapshot: DetectionContextSnapshot | None = None,
    ) -> str:
        lines = [
            f"event_id={event_id}",
            f"evidence_ids={','.join(e.evidence_id for e in evidence_output.evidence_list) or '-'}",
            f"response_action_ids={','.join(a.action_id for a in response_actions) or '-'}",
            f"success_sources={','.join(evidence_output.success_sources) or '-'}",
            f"failed_sources={','.join(evidence_output.failed_sources) or '-'}",
        ]
        if detection_context_snapshot is not None:
            lines.extend(
                [
                    f"detection_context_snapshot_id={detection_context_snapshot.snapshot_id}",
                    f"detection_context_revision={detection_context_snapshot.revision}",
                    f"detection_context_hash={detection_context_snapshot.content_hash}",
                    f"detection_promotion_id={detection_context_snapshot.promotion_id}",
                    f"detection_promotion_link_revision={detection_context_snapshot.promotion_link_revision}",
                ]
            )
        if content_sha256:
            lines.append(f"content_sha256={content_sha256}")
        return "\n".join(lines)
