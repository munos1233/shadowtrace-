#!/usr/bin/env python3
"""Dynamic eval matrix orchestrator with fresh-stack isolation (ISSUE-301 / ISSUE-302).

Runs each scenario in an isolated Compose project with fresh volumes, explicit
event IDs, optional strict CLOSED profile, and guaranteed teardown.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

DEFAULT_SCENARIOS = (
    "insider_data_exfiltration",
    "account_anomaly_fp",
    "suspicious_domain_access",
)


def _compose_files() -> list[str]:
    return [
        str(_ROOT / "infra" / "docker-compose.yml"),
        str(_ROOT / "infra" / "docker-compose.eval.yml"),
    ]


def _compose_cmd(project: str) -> list[str]:
    cmd = ["docker", "compose", "--project-name", project]
    for compose_file in _compose_files():
        cmd.extend(["-f", compose_file])
    return cmd


def _run(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(
        cmd,
        cwd=str(_ROOT),
        env=merged,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def _compose_down(project: str) -> None:
    _run(
        _compose_cmd(project) + ["down", "-v", "--remove-orphans"],
        check=False,
    )


def _compose_up(project: str) -> None:
    _run(_compose_cmd(project) + ["up", "-d", "--build", "--wait", "--wait-timeout", "180"])


def _compose_exec(project: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return _run(_compose_cmd(project) + ["exec", "-T", "backend", *argv])


def _seed_scenario(project: str, scenario: str, seed: int) -> dict[str, Any]:
    proc = _compose_exec(
        project,
        [
            "python3",
            "scripts/seed_mock_xdr_and_ingest.py",
            "--scenario",
            scenario,
            "--seed",
            str(seed),
            "--mock-xdr-url",
            "http://mock-xdr:8100",
        ],
    )
    from dynamic_eval_full_loop import parse_seed_stdout

    summary = parse_seed_stdout(proc.stdout)
    summary["scenario_id"] = scenario
    return summary


def _run_full_loop(
    project: str,
    *,
    scenario: str,
    event_ids: list[str],
    require_closed: bool,
    seed: int,
) -> dict[str, Any]:
    argv = [
        "python3",
        "scripts/dynamic_eval_full_loop.py",
        "--seed-via-compose",
        "--scenario",
        scenario,
        "--base-url",
        "http://127.0.0.1:8000",
        "--token",
        os.environ.get("BOOTSTRAP_AUTH_TOKEN", "bootstrap-token"),
        "--max-events",
        str(len(event_ids)),
        "--json",
    ]
    if require_closed:
        argv.append("--require-closed")
    for event_id in event_ids:
        argv.extend(["--event-id", event_id])
    proc = _compose_exec(project, argv)
    return json.loads(proc.stdout)


def _select_event_ids(project: str, scenario: str) -> list[str]:
    proc = _compose_exec(
        project,
        [
            "python3",
            "-c",
            (
                "import json, urllib.request; "
                "req=urllib.request.Request("
                "'http://127.0.0.1:8000/api/v1/events?page=1&page_size=50', "
                "headers={'Authorization':'Bearer bootstrap-token'}); "
                "data=json.load(urllib.request.urlopen(req, timeout=30)); "
                "print(json.dumps([i['event_id'] for i in data.get('items', []) "
                f"if '{scenario}' in (i.get('title') or '').lower() or i.get('status')=='new']))"
            ),
        ],
    )
    ids = json.loads(proc.stdout.strip() or "[]")
    if not ids:
        raise RuntimeError(f"no event IDs discovered after seed for scenario={scenario}")
    return ids[:1]


def run_matrix(
    *,
    scenarios: list[str],
    fresh_volumes: bool,
    require_closed: bool,
    seed: int,
    artifact_root: Path,
) -> dict[str, Any]:
    artifact_root.mkdir(parents=True, exist_ok=True)
    matrix_result: dict[str, Any] = {
        "scenarios": [],
        "require_closed": require_closed,
        "fresh_volumes": fresh_volumes,
    }

    for scenario in scenarios:
        project = f"st-eval-{scenario[:24]}-{uuid.uuid4().hex[:8]}"
        scenario_dir = artifact_root / scenario
        scenario_dir.mkdir(parents=True, exist_ok=True)
        scenario_record: dict[str, Any] = {
            "scenario": scenario,
            "compose_project": project,
            "status": "failed",
        }
        try:
            if fresh_volumes:
                _compose_down(project)
            _compose_up(project)
            seed_summary = _seed_scenario(project, scenario, seed)
            event_ids = _select_event_ids(project, scenario)
            loop_result = _run_full_loop(
                project,
                scenario=scenario,
                event_ids=event_ids,
                require_closed=require_closed,
                seed=seed,
            )
            scenario_record.update(
                {
                    "status": "passed",
                    "seed_summary": seed_summary,
                    "event_ids": event_ids,
                    "loop_result": loop_result,
                }
            )
            (scenario_dir / "result.json").write_text(
                json.dumps(scenario_record, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            scenario_record["error"] = str(exc)
            (scenario_dir / "result.json").write_text(
                json.dumps(scenario_record, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            matrix_result["scenarios"].append(scenario_record)
            _compose_down(project)
            raise
        finally:
            _compose_down(project)
        matrix_result["scenarios"].append(scenario_record)

    (artifact_root / "matrix_summary.json").write_text(
        json.dumps(matrix_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return matrix_result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ISSUE-301 dynamic eval matrix runner")
    parser.add_argument(
        "--scenarios",
        default=",".join(DEFAULT_SCENARIOS),
        help="Comma-separated scenario ids",
    )
    parser.add_argument("--fresh-volumes", action="store_true", default=True)
    parser.add_argument("--no-fresh-volumes", action="store_false", dest="fresh_volumes")
    parser.add_argument("--require-closed", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--artifact-dir",
        default=str(_ROOT / "artifacts" / "dynamic_eval_matrix"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    scenarios = [s.strip() for s in str(args.scenarios).split(",") if s.strip()]
    if not scenarios:
        raise SystemExit("At least one scenario is required")

    def _handle_sigint(_signum: int, _frame: object) -> None:
        raise SystemExit(130)

    signal.signal(signal.SIGINT, _handle_sigint)

    result = run_matrix(
        scenarios=scenarios,
        fresh_volumes=bool(args.fresh_volumes),
        require_closed=bool(args.require_closed),
        seed=int(args.seed),
        artifact_root=Path(args.artifact_dir),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[dynamic-eval-matrix] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
