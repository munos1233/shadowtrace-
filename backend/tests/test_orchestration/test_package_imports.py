"""Cold-import guards for orchestration package cycles (#970)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_analysis_only_pipeline_cold_import() -> None:
    """``import app.services.analysis_only_pipeline`` must work without pytest preload."""
    backend_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.services.analysis_only_pipeline import run_rag_stage; "
            "assert callable(run_rag_stage)",
        ],
        cwd=backend_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
