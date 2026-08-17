"""ISSUE-350: Mock plumbing CI card vs Live reasoning card."""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.agents.prompts.response_prompt import ResponsePlanLLMResponse

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GOLDEN_RESPONSE_PLAN = (
    REPO_ROOT
    / "backend"
    / "app"
    / "core"
    / "llm"
    / "golden"
    / "response_plan"
    / "adversarial_credential_db_staging_exfil.json"
)
ADVERSARIAL_README = REPO_ROOT / "backend" / "tests" / "adversarial" / "README.md"
AUDIT_REPORT_DOC = REPO_ROOT / "审计报告.md"


def _closure_gates_job_block(text: str) -> str:
    match = re.search(
        r"(?m)^  backend-closure-gates:\n(?:.*\n)*?(?=^  [A-Za-z0-9_-]+:|\Z)",
        text,
    )
    assert match is not None, "backend-closure-gates job missing from ci.yml"
    return match.group(0)


def test_ci_closure_gates_check_name_is_mock_plumbing() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    block = _closure_gates_job_block(text)
    assert "name: backend-closure-gates-mock" in block
    assert "LLM_MODE: mock" in block
    assert "ISSUE-350" in block
    # Job id stays stable for needs:; Checks display name carries Mock.
    assert re.search(r"(?m)^  backend-closure-gates:\n", text)
    assert not re.search(r"(?m)^  backend-closure-gates-mock:\n", text)


def test_adversarial_golden_response_plan_covers_entityset_hosts() -> None:
    """After ISSUE-328, golden isolate must not stay WKS-only (long-term fork)."""
    payload = json.loads(GOLDEN_RESPONSE_PLAN.read_text(encoding="utf-8"))
    wire = ResponsePlanLLMResponse.model_validate(payload["content"])
    isolate_targets = {item.target for item in wire.actions if item.tool_name == "isolate_host"}
    tool_names = {item.tool_name for item in wire.actions}
    assert "WKS-DATA-031" in isolate_targets
    assert "SRV-DB-STG-02" in isolate_targets
    assert "BACKUP-SRV-01" not in isolate_targets
    assert {"disable_account", "block_ip", "create_ticket"} <= tool_names


def test_docs_do_not_treat_closure_gates_green_as_containment_proof() -> None:
    readme = ADVERSARIAL_README.read_text(encoding="utf-8")
    audit = AUDIT_REPORT_DOC.read_text(encoding="utf-8")
    assert "backend-closure-gates-mock" in readme
    assert "job id `backend-closure-gates`" in readme
    assert "Mock plumbing" in readme
    assert "Not a PR gate" in readme
    assert "--require-llm-quality" in readme
    assert "-m adversarial_audit" in readme and "-o addopts=" in readme
    assert "Local: default adversarial pytest" not in readme
    assert "llm_mode" in readme and "certification_card" in readme and "`summary`" in readme
    assert "backend-closure-gates-mock" in audit
    assert "绿 ≠ Live 研判" in audit or "非 Live 研判" in audit
    assert "遏制覆盖证明" in audit
    assert "job id `backend-closure-gates`" in audit
    assert "ID-Q-001" in audit
    assert "scripted pack" in audit or "scripted pack" in readme
