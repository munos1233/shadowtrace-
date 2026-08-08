"""CLI entry for detection shadow evaluation runs (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DEFAULT_DATASET = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"


def resolve_code_sha(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    env_sha = os.environ.get("EVAL_CODE_SHA", "").strip()
    if env_sha:
        return env_sha
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "0000000"


def cli_exit_code(
    *,
    artifact_status: str,
    gate_verdict: str | None,
    baseline_compare_failed: bool,
    allow_gate_fail: bool,
    required_scorer_error_count: int = 0,
) -> int:
    """Map evaluation outcomes to process exit codes (ISSUE-167 / #686, ISSUE-263).

    Required mode (default, no ``--allow-gate-fail``) exits non-zero when:

    - baseline structural drift is detected;
    - artifact status is not ``completed``;
    - gate verdict is ``fail`` or ``fail_closed``;
    - any required scorer raised an error.

    Observe mode (``--allow-gate-fail``) keeps the process exit code zero for gate
    and scorer failures so a non-blocking CI job can upload diagnostics without
    impersonating the required gate. Baseline drift still fails in observe mode.

    We use a CLI flag instead of ``threshold_manifest.required_gate: false``
    because lowering ``required_gate`` would emit ``fail`` rather than
    ``fail_closed`` (see ``app.evaluation.threshold``), breaking the pinned
    ``baseline_artifact.json`` contract while artifact semantics must stay stable.
    """
    if baseline_compare_failed:
        return 1
    if allow_gate_fail:
        return 0
    if required_scorer_error_count > 0:
        return 1
    if artifact_status != "completed":
        return 1
    if gate_verdict in {"fail", "fail_closed"}:
        return 1
    return 0


def format_evaluation_summary(*, artifact, threshold_path: Path | None) -> str:
    """Render a compact human-readable summary for CI step output."""
    gate = artifact.gate
    required_gate = None
    if threshold_path is not None and threshold_path.is_file():
        from app.evaluation.threshold import load_threshold_manifest

        required_gate = load_threshold_manifest(threshold_path).required_gate
    lines = [
        "### Detection evaluation",
        "",
        f"- **status**: `{artifact.status.value}`",
        f"- **gate_verdict**: `{gate.verdict.value if gate else 'none'}`",
        f"- **required_gate** (manifest): `{required_gate}`",
        f"- **pass_rate**: `{artifact.aggregates.pass_rate}`",
        f"- **required_scorer_error_count**: `{artifact.aggregates.required_scorer_error_count}`",
        f"- **artifact_hash**: `{artifact.artifact_hash}`",
    ]
    if gate and gate.diffs:
        lines.extend(["", "**Gate diffs:**", ""])
        for diff in gate.diffs[:10]:
            lines.append(f"- `{diff.field}`: {diff.reason}")
        if len(gate.diffs) > 10:
            lines.append(f"- … and {len(gate.diffs) - 10} more")
    return "\n".join(lines) + "\n"


def _apply_migrations(database_url: str) -> None:
    from alembic import command
    from alembic.config import Config

    os.environ["DATABASE_URL"] = database_url
    alembic_cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    command.upgrade(alembic_cfg, "head")


async def _resolve_manifest(
    truth_service,
    session_factory,
    dataset_dir: Path,
    *,
    tenant_id: str | None,
    skip_fixture_load: bool,
):
    from app.evaluation.fixture_loader import load_fixture_dataset, load_fixture_manifest

    if skip_fixture_load:
        raw = load_fixture_manifest(dataset_dir)
        resolved_tenant = tenant_id or str(raw.get("tenant_id", "")).strip()
        dataset_id = str(raw.get("dataset_id", "")).strip()
        dataset_version = str(raw.get("dataset_version", "")).strip()
        if not resolved_tenant or not dataset_id or not dataset_version:
            raise ValueError("manifest must include tenant_id, dataset_id, dataset_version")
        manifest = await truth_service.get_dataset_manifest(
            tenant_id=resolved_tenant,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
        )
        return manifest.case_count, manifest

    async with session_factory() as session:
        async with session.begin():
            truths, manifest = await load_fixture_dataset(
                truth_service,
                dataset_dir,
                tenant_id=tenant_id,
            )
    return len(truths), manifest


async def _run(args: argparse.Namespace) -> int:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.evaluation.detection.diff import diff_detection_against_baseline
    from app.evaluation.detection.fixture_loader import (
        load_detection_fixture_index,
        resolve_effective_cutoff_at,
    )
    from app.evaluation.detection.fixture_seeder import derive_all_candidate_refs
    from app.evaluation.detection.runner import run_fixture_detection_evaluation
    from app.evaluation.fixture_loader import load_fixture_manifest
    from app.models.detection_evaluation import DetectionEvaluationArtifact
    from app.models.evaluation_run import EvaluationReleaseRefs
    from app.services.evaluation_truth_service import EvaluationTruthService

    dataset_dir = Path(args.dataset_dir)
    threshold_path: Path | None
    if args.threshold_manifest:
        threshold_path = Path(args.threshold_manifest)
    else:
        candidate = dataset_dir / "threshold_manifest.json"
        threshold_path = candidate if candidate.is_file() else None

    raw_manifest = load_fixture_manifest(dataset_dir)
    cutoff_raw = raw_manifest.get("default_cutoff_at") or raw_manifest.get("cutoff_at")
    if not cutoff_raw:
        raise ValueError("manifest must include default_cutoff_at")
    cutoff_at = datetime.fromisoformat(str(cutoff_raw))

    engine = create_async_engine(args.database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    truth_service = EvaluationTruthService(session_factory)

    loaded_cases, manifest = await _resolve_manifest(
        truth_service,
        session_factory,
        dataset_dir,
        tenant_id=args.tenant_id,
        skip_fixture_load=args.skip_fixture_load,
    )

    fixture_index = load_detection_fixture_index(dataset_dir)
    if not fixture_index.by_case_id:
        raise ValueError("detection fixture index is empty; cases need detection_replay blocks")

    effective_cutoff_at = resolve_effective_cutoff_at(
        fixture_index,
        default_cutoff_at=cutoff_at,
    )
    candidate_refs_entries, candidate_set_hash = await derive_all_candidate_refs(
        session_factory,
        fixture_index,
    )
    candidate_refs = candidate_refs_entries[0]

    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=args.seed,
        code_sha=resolve_code_sha(args.code_sha),
        cutoff_at=cutoff_at,
        effective_cutoff_at=effective_cutoff_at,
        candidate_refs=candidate_refs,
        candidate_refs_entries=candidate_refs_entries,
        candidate_set_hash=candidate_set_hash,
        release_refs=EvaluationReleaseRefs(config_profile=args.config_profile),
        threshold_manifest_path=threshold_path,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "evaluation_id": artifact.evaluation_id,
                "status": artifact.status.value,
                "artifact_hash": artifact.artifact_hash,
                "case_count": artifact.aggregates.case_count,
                "pass_rate": artifact.aggregates.pass_rate,
                "gate_verdict": artifact.gate.verdict.value if artifact.gate else None,
                "tenant_safety_pass": artifact.tenant_safety.pass_count,
                "replay_fidelity": artifact.config.replay_fidelity,
                "candidate_set_hash": artifact.config.candidate_set_hash,
                "total_replay_duration_ms": artifact.resource_summary.total_replay_duration_ms,
                "quality_metrics": {
                    metric.metric_id: metric.value
                    for metric in (artifact.quality_report.metrics if artifact.quality_report else [])
                },
                "output": str(output_path),
                "loaded_cases": loaded_cases,
                "approval_note": artifact.approval_note,
            },
            indent=2,
        )
    )

    if args.compare_baseline is not None:
        baseline_payload = json.loads(args.compare_baseline.read_text(encoding="utf-8"))
        baseline = DetectionEvaluationArtifact.model_validate(baseline_payload)
        drift = diff_detection_against_baseline(baseline, artifact)
        if drift:
            print(
                json.dumps(
                    {
                        "baseline_compare": "failed",
                        "baseline_path": str(args.compare_baseline),
                        "diffs": [item.model_dump(mode="json") for item in drift],
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            await engine.dispose()
            return cli_exit_code(
                artifact_status=artifact.status.value,
                gate_verdict=artifact.gate.verdict.value if artifact.gate else None,
                baseline_compare_failed=True,
                allow_gate_fail=args.allow_gate_fail,
                required_scorer_error_count=artifact.aggregates.required_scorer_error_count,
            )
        print(
            json.dumps(
                {
                    "baseline_compare": "passed",
                    "baseline_path": str(args.compare_baseline),
                },
                indent=2,
            )
        )

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        Path(summary_path).write_text(
            format_evaluation_summary(artifact=artifact, threshold_path=threshold_path),
            encoding="utf-8",
        )

    await engine.dispose()
    return cli_exit_code(
        artifact_status=artifact.status.value,
        gate_verdict=artifact.gate.verdict.value if artifact.gate else None,
        baseline_compare_failed=False,
        allow_gate_fail=args.allow_gate_fail,
        required_scorer_error_count=artifact.aggregates.required_scorer_error_count,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run detection shadow evaluation pipeline.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET,
        help="Fixture dataset directory containing manifest.json and cases/",
    )
    parser.add_argument("--tenant-id", default=None, help="Override tenant id from manifest")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic replay seed")
    parser.add_argument("--code-sha", default=None, help="Pinned code SHA (defaults to git HEAD)")
    parser.add_argument(
        "--config-profile",
        default="mock_p0",
        help="Release config profile label stored in artifact",
    )
    parser.add_argument(
        "--threshold-manifest",
        type=Path,
        default=None,
        help="Threshold manifest path (defaults to dataset threshold_manifest.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "artifacts" / "evaluation" / "detection_latest_run.json",
        help="Artifact JSON output path",
    )
    parser.add_argument(
        "--database-url",
        default="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace",
        help="PostgreSQL URL for canonical truth persistence",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Apply Alembic migrations before loading fixtures (CI uses separate step)",
    )
    parser.add_argument(
        "--skip-fixture-load",
        action="store_true",
        help="Skip fixture persistence; read canonical truth already present in PostgreSQL",
    )
    parser.add_argument(
        "--compare-baseline",
        type=Path,
        default=None,
        help="Pinned baseline artifact JSON; fail when structural output drifts",
    )
    parser.add_argument(
        "--allow-gate-fail",
        action="store_true",
        help=(
            "Observe-only mode (non-blocking CI jobs): do not exit non-zero for "
            "gate fail/fail_closed, non-completed status, or required scorer errors. "
            "Baseline drift still fails. Required CI jobs must omit this flag."
        ),
    )
    args = parser.parse_args()

    if args.migrate:
        _apply_migrations(args.database_url)

    import asyncio

    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
