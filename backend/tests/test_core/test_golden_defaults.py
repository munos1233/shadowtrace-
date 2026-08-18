"""ISSUE-201: Mock LLM default golden cross-prompt consistency."""

from __future__ import annotations

import json

import pytest

from app.agents.prompts.risk_prompt import FACTOR_NAMES
from app.core.llm.base import default_golden_root

_DEMO_MARKERS = ("zhangsan", "pc-fin-023", "203.0.113.88")
_CONFLICTING_TRIAGE_PHRASES = (
    "no clear threat pattern",
    "no threat pattern detected",
    "likely not a threat",
)
_CONFIRMED_THREAT_THRESHOLD = 70


def _load_golden(prompt_key: str, filename: str = "default.json") -> dict:
    path = default_golden_root() / prompt_key / filename
    assert path.is_file(), f"missing golden file: {path}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _average_risk_score(content: dict) -> float:
    factors = content.get("factors") or {}
    scores: list[float] = []
    for name in FACTOR_NAMES:
        entry = factors.get(name) or {}
        if isinstance(entry, dict) and entry.get("score") is not None:
            scores.append(float(entry["score"]))
    assert len(scores) == len(FACTOR_NAMES)
    return sum(scores) / len(scores)


def test_default_goldens_avoid_demo_persona_markers() -> None:
    for prompt_key in ("risk_score", "response_plan", "report_generate", "storyline_generate"):
        payload = _load_golden(prompt_key)
        content = payload.get("content", payload)
        blob = json.dumps(content, ensure_ascii=False).lower()
        for marker in _DEMO_MARKERS:
            assert marker not in blob, (
                f"{prompt_key}/default.json must not contain demo marker {marker!r}"
            )


def test_default_risk_score_is_conservative() -> None:
    content = _load_golden("risk_score").get("content", {})
    assert isinstance(content, dict)
    average = _average_risk_score(content)
    assert average < _CONFIRMED_THREAT_THRESHOLD


def test_default_triage_and_risk_defaults_are_not_confirmed_threat_pair() -> None:
    triage_content = _load_golden("triage_extract").get("content", {})
    risk_content = _load_golden("risk_score").get("content", {})
    assert isinstance(triage_content, dict)
    assert isinstance(risk_content, dict)

    summary = str(triage_content.get("decision_summary") or "").lower()
    weak_triage = triage_content.get("event_type") == "other" or any(
        phrase in summary for phrase in _CONFLICTING_TRIAGE_PHRASES
    )
    high_risk = _average_risk_score(risk_content) >= _CONFIRMED_THREAT_THRESHOLD
    assert not (weak_triage and high_risk), (
        "default triage/risk must not simulate confirmed-threat conflict"
    )


def test_default_event_qa_and_storyline_are_neutral() -> None:
    for prompt_key in ("event_qa", "storyline_generate"):
        content = _load_golden(prompt_key).get("content", {})
        blob = json.dumps(content, ensure_ascii=False).lower()
        for marker in _DEMO_MARKERS:
            assert marker not in blob, f"{prompt_key}/default.json must not contain {marker!r}"
        assert "no clear threat pattern" not in blob


def test_insider_scenario_goldens_preserve_demo_regression_pack() -> None:
    risk_content = _load_golden("risk_score", "insider_data_exfiltration.json").get("content", {})
    assert isinstance(risk_content, dict)
    assert _average_risk_score(risk_content) >= _CONFIRMED_THREAT_THRESHOLD

    report_content = _load_golden("report_generate", "insider_data_exfiltration.json").get(
        "content", {}
    )
    blob = json.dumps(report_content, ensure_ascii=False).lower()
    assert "zhangsan" in blob
    assert "pc-fin-023" in blob


@pytest.mark.parametrize(
    "scenario_file",
    ["malicious_process.json", "insider_privilege_abuse.json"],
)
def test_threat_scenario_risk_goldens_restore_confirmed_threat_band(scenario_file: str) -> None:
    """ISSUE-229: threat packs must not fall through to neutral default.json."""
    risk_content = _load_golden("risk_score", scenario_file).get("content", {})
    assert isinstance(risk_content, dict)
    assert _average_risk_score(risk_content) >= _CONFIRMED_THREAT_THRESHOLD
    blob = json.dumps(risk_content, ensure_ascii=False).lower()
    for marker in _DEMO_MARKERS:
        assert marker not in blob, f"{scenario_file} must not reuse insider demo markers"


def test_insider_scenario_goldens_are_internally_consistent() -> None:
    triage_content = _load_golden("triage_extract", "insider_data_exfiltration.json").get(
        "content", {}
    )
    risk_content = _load_golden("risk_score", "insider_data_exfiltration.json").get("content", {})
    assert isinstance(triage_content, dict)
    assert isinstance(risk_content, dict)

    summary = str(triage_content.get("decision_summary") or "").lower()
    weak_triage = triage_content.get("event_type") == "other" or any(
        phrase in summary for phrase in _CONFLICTING_TRIAGE_PHRASES
    )
    high_risk = _average_risk_score(risk_content) >= _CONFIRMED_THREAT_THRESHOLD
    assert not (weak_triage and high_risk), "insider scenario pack must not repeat default conflict"
    assert triage_content.get("event_type") == "data_exfiltration"


@pytest.mark.parametrize(
    "prompt_key",
    [
        "triage_extract",
        "risk_score",
        "response_plan",
        "report_generate",
    ],
)
def test_adversarial_scenario_golden_exists(prompt_key: str) -> None:
    path = default_golden_root() / prompt_key / "adversarial_credential_db_staging_exfil.json"
    assert path.is_file(), f"missing adversarial golden for {prompt_key}"


def test_report_generate_goldens_forbid_legacy_incomplete_markers() -> None:
    """ISSUE-212: mock goldens must not reuse 「暂无处置动作/暂无验证结果」."""
    root = default_golden_root() / "report_generate"
    forbidden = ("暂无处置动作", "暂无验证结果")
    files = sorted(root.glob("*.json"))
    assert files, f"missing report_generate goldens under {root}"
    for path in files:
        blob = path.read_text(encoding="utf-8")
        for marker in forbidden:
            assert marker not in blob, f"{path.name} still contains {marker!r}"


def test_adversarial_report_golden_recommends_dest_not_vpn_src() -> None:
    payload = _load_golden("report_generate", "adversarial_credential_db_staging_exfil.json")
    sections = payload["content"]["sections"]
    recommendations = sections["recommendations"]
    assert "198.51.100.44" not in recommendations
    assert "198.51.100.77" in recommendations
    assert "storage-sync-cdn.example" in recommendations
