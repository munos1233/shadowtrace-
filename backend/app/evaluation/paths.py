"""Path normalization for portable evaluation artifacts (ISSUE-105 / #608)."""

from __future__ import annotations

from pathlib import Path


def _resolve_repo_root() -> Path:
    """Locate the tree that contains ``data/evaluation``.

    Host checkouts live at ``<repo>/backend/app/evaluation/paths.py`` (parents[3]).
    The backend image copies ``backend/app`` to ``/app/app``, so parents[3] is
    ``/`` and the evaluation data is at ``/app/data/evaluation``.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "data" / "evaluation").is_dir():
            return parent
    return here.parents[3]


REPO_ROOT = _resolve_repo_root()


def repo_relative_manifest_path(path: Path, *, repo_root: Path | None = None) -> str:
    """Return a repo-relative POSIX path for cross-environment artifact comparison."""
    root = (repo_root or REPO_ROOT).resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.name


__all__ = ["REPO_ROOT", "repo_relative_manifest_path"]
