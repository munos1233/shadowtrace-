"""ISSUE-350 live reasoning card unit tests (independent of --require-closed)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"


def _load_module(path: Path, name: str):
    scripts_dir = str(SCRIPTS)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def quality_mod():
    return _load_module(SCRIPTS / "strict_llm_quality.py", "strict_llm_quality_under_test")


def _success_calls(*, model_name: str = "glm-4") -> list[dict[str, str]]:
    return [
        {"prompt_key": "triage_extract", "status": "success", "model_name": model_name},
        {"prompt_key": "plan_generate", "status": "success", "model_name": model_name},
        {"prompt_key": "risk_score", "status": "success", "model_name": model_name},
        {"prompt_key": "response_plan", "status": "success", "model_name": model_name},
    ]


def _exfil_success_kwargs(**overrides):
    payload = {
        "event_id": "evt-exfil-ok",
        "event_type": "data_exfiltration",
        "final_verdict": "confirmed_threat",
        "scenario_id": "insider_data_exfiltration",
        "response_plan_generated_by": "llm",
        "llm_calls": [
            *_success_calls(),
            {"prompt_key": "storyline_generate", "status": "success", "model_name": "glm-4"},
            {"prompt_key": "report_generate", "status": "success", "model_name": "glm-4"},
        ],
        "storyline_generated_by": "llm",
        "storyline_phase_count": 4,
        "report_quality": "complete",
    }
    payload.update(overrides)
    return payload


def test_all_timeout_fails_live_card(quality_mod) -> None:
    calls = [
        {"prompt_key": key, "status": "llm_timeout", "error_class": "timeout"}
        for key in quality_mod.CORE_PROMPT_KEYS
    ]
    with pytest.raises(RuntimeError, match="all_timeout=True"):
        quality_mod.evaluate_llm_quality(
            event_id="evt-timeout",
            event_type="suspicious_domain",
            final_verdict="none",
            scenario_id="suspicious_domain_access",
            response_plan_generated_by="template",
            llm_calls=calls,
        )


def test_template_exfil_confirmed_threat_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="generated_by=template"):
        quality_mod.evaluate_llm_quality(
            event_id="evt-exfil",
            event_type="data_exfiltration",
            final_verdict="confirmed_threat",
            scenario_id="insider_data_exfiltration",
            response_plan_generated_by="template",
            llm_calls=_success_calls(),
        )


def test_plumbing_template_on_domain_none_still_passes_live_llm_success(quality_mod) -> None:
    summary = quality_mod.evaluate_llm_quality(
        event_id="evt-domain",
        event_type="suspicious_domain",
        final_verdict="none",
        scenario_id="suspicious_domain_access",
        response_plan_generated_by="template",
        llm_calls=_success_calls(),
    )
    assert summary["ok"] is True
    assert summary["health_window_consulted"] is False
    assert summary["certification_card"] == "live_reasoning"


def test_llm_success_on_exfil_passes(quality_mod) -> None:
    summary = quality_mod.evaluate_llm_quality(**_exfil_success_kwargs())
    assert summary["ok"] is True
    assert summary["storyline_generated_by"] == "llm"
    assert summary["report_quality"] == "complete"


def test_mock_model_success_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="mock-model"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(llm_calls=_success_calls(model_name="mock-model"))
        )


def test_missing_model_name_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="missing"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(
                llm_calls=[
                    {"prompt_key": "triage_extract", "status": "success"},
                    {"prompt_key": "plan_generate", "status": "success", "model_name": "glm-4"},
                    {"prompt_key": "risk_score", "status": "success", "model_name": "glm-4"},
                    {"prompt_key": "response_plan", "status": "success", "model_name": "glm-4"},
                    {"prompt_key": "report_generate", "status": "success", "model_name": "glm-4"},
                ]
            )
        )


def test_insider_threat_event_type_is_exfil_like(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="generated_by=template"):
        quality_mod.evaluate_llm_quality(
            event_id="evt-insider-type",
            event_type="insider_threat",
            final_verdict="confirmed_threat",
            scenario_id=None,
            response_plan_generated_by="template",
            llm_calls=_success_calls(),
        )


def test_gate_tokens_in_trace_title_fail_live_card(quality_mod) -> None:
    found = quality_mod._response_strategy_from_trace(
        [
            {
                "entry_type": "agent_execution",
                "actor": "response_agent",
                "title": (
                    "response_agent 完成响应方案：response_plan actions=4 "
                    "plan_id=pln-1 generated_by=llm gates=entity_coverage_merge"
                ),
                "detail": {},
            }
        ]
    )
    assert "entity_coverage_merge" in found
    with pytest.raises(RuntimeError, match="entity_coverage_merge"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(
                response_plan_generated_by="llm",
                response_plan_strategy=found,
            )
        )


def test_domain_containment_missing_fails_even_if_generated_by_llm(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="domain_containment_missing"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(
                response_plan_generated_by="llm",
                response_plan_strategy=(
                    "domain_containment_missing: EntitySet domains lack block_domain"
                ),
            )
        )


def test_coverage_merge_note_fails_even_if_generated_by_llm(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="entity_coverage_merge"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(
                response_plan_generated_by="llm",
                response_plan_strategy="containment_quality_gate: entity_coverage_merge",
            )
        )


def test_rule_storyline_on_exfil_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="storyline was not adopted"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(storyline_generated_by="rule", storyline_phase_count=4)
        )


def test_incomplete_report_on_exfil_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="report_quality"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(report_quality="incomplete_placeholder")
        )


def test_degraded_template_report_on_exfil_fails_live_card(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="degraded_template"):
        quality_mod.evaluate_llm_quality(
            **_exfil_success_kwargs(report_quality="degraded_template")
        )


def test_quality_module_never_mentions_health_endpoint(quality_mod) -> None:
    source = Path(quality_mod.__file__).read_text(encoding="utf-8")
    assert "/health" in source
    assert "Never consults GET /health" in source or "never uses GET /health" in source.lower()
    assert 'get_json("/api/v1/health' not in source
    assert "get_json('/api/v1/health" not in source


def test_generated_by_from_response_agent_trace_title(quality_mod) -> None:
    found = quality_mod._generated_by_from_trace(
        [
            {
                "entry_type": "agent_execution",
                "actor": "response_agent",
                "title": (
                    "response_agent 完成响应方案：response_plan actions=3 "
                    "plan_id=pln-1 generated_by=template"
                ),
                "detail": {},
            }
        ]
    )
    assert found == "template"


def test_missing_generated_by_on_exfil_confirmed_threat_fails(quality_mod) -> None:
    with pytest.raises(RuntimeError, match="could not observe"):
        quality_mod.evaluate_llm_quality(
            event_id="evt-exfil-missing",
            event_type="data_exfiltration",
            final_verdict="confirmed_threat",
            scenario_id="insider_data_exfiltration",
            response_plan_generated_by=None,
            llm_calls=_success_calls(),
        )


def test_live_reasoning_nightly_workflow_is_independent_and_fail_closed() -> None:
    workflow = REPO_ROOT / ".github" / "workflows" / "live-reasoning-nightly.yml"
    ci = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert workflow.is_file()
    text = workflow.read_text(encoding="utf-8")
    assert "EVAL_REQUIRE_LLM_QUALITY" in text or "--require-llm-quality" in text
    assert "EVAL_REQUIRE_CLOSED" in text or "--require-closed" in text
    assert "fail-closed" in text
    assert "secrets.LLM_API_KEY" in text
    assert "insider_data_exfiltration" in text
    assert "live-glm-eval" in text
    assert "CERTIFICATION_CARD=live_reasoning" in text
    assert "make up-demo" not in text
    assert "adversarial-closure-gates" not in text
    assert "up-live-reasoning" in text
    ci_text = ci.read_text(encoding="utf-8")
    assert "live-glm-eval" not in ci_text
    assert "live-reasoning-nightly.yml" not in ci_text
