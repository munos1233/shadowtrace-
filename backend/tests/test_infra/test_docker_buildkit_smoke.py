"""BuildKit path smoke helpers (ISSUE-286)."""

from __future__ import annotations

from pathlib import Path


def _path_is_ascii(value: str) -> bool:
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def test_path_is_ascii_detects_cjk_segment() -> None:
    assert _path_is_ascii("/tmp/shadowtrace") is True
    assert _path_is_ascii("/tmp/shadowtrace-副本") is False


def test_repo_root_is_ascii() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    assert repo_root.is_dir()
    assert _path_is_ascii(str(repo_root)) is True


def test_smoke_script_exists() -> None:
    script = Path(__file__).resolve().parents[3] / "scripts" / "smoke_docker_buildkit_paths.py"
    assert script.is_file()
