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


def _success_calls() -> list[dict[str, str]]:
    return [
        {"prompt_key": "triage_extract", "status": "success"},
        {"prompt_key": "plan_generate", "status": "success"},
        {"prompt_key": "risk_score", "status": "success"},
        {"prompt_key": "response_plan", "status": "success"},
    ]


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
    summary = quality_mod.evaluate_llm_quality(
        event_id="evt-exfil-ok",
        event_type="data_exfiltration",
        final_verdict="confirmed_threat",
        scenario_id="insider_data_exfiltration",
        response_plan_generated_by="llm",
        llm_calls=_success_calls(),
    )
    assert summary["ok"] is True


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
