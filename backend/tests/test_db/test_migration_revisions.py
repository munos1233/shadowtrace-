"""Static Alembic revision metadata gates (ISSUE-214)."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
VERSIONS_DIR = BACKEND_DIR / "migrations" / "versions"
SCRIPTS_DIR = BACKEND_DIR.parent / "scripts"


def _load_revision_width() -> int:
    widen_path = VERSIONS_DIR / "0032_alembic_version_widen.py"
    spec = importlib.util.spec_from_file_location("alembic_version_widen", widen_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return int(module.ALEMBIC_VERSION_NUM_WIDTH)


def _revision_ids() -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for path in sorted(VERSIONS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "revision"
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    revision = node.value.value
                    rows.append((revision, path.name, len(revision)))
    return rows


def test_all_revision_ids_fit_alembic_version_num_width() -> None:
    max_width = _load_revision_width()
    violations = [
        (revision, filename, length)
        for revision, filename, length in _revision_ids()
        if length > max_width
    ]
    assert not violations, (
        f"revision id(s) exceed alembic_version.version_num width ({max_width}): {violations}"
    )


def test_check_migration_revisions_script_passes() -> None:
    script = SCRIPTS_DIR / "check_migration_revisions.py"
    spec = importlib.util.spec_from_file_location("check_migration_revisions", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.main() == 0


def test_generate_report_migration_follows_version_widen() -> None:
    widen_path = VERSIONS_DIR / "0032_alembic_version_widen.py"
    report_path = VERSIONS_DIR / "0033_investigation_intent_generate_report.py"
    assert widen_path.is_file()
    assert report_path.is_file()

    def _down_revision(path: Path) -> str:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "down_revision"
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    return node.value.value
        raise AssertionError(f"down_revision missing in {path.name}")

    assert _down_revision(report_path) == "0032_alembic_version_widen"


def test_alembic_version_widen_downgrade_refuses_long_stamped_revision() -> None:
    """ISSUE-214: shrinking version_num must not silently truncate long revision ids."""
    widen_path = VERSIONS_DIR / "0032_alembic_version_widen.py"
    spec = importlib.util.spec_from_file_location("alembic_version_widen_test", widen_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class _Result:
        def scalar_one(self) -> int:
            return 41

    class _Bind:
        @staticmethod
        def execute(_stmt: object) -> _Result:
            return _Result()

    original_get_bind = module.op.get_bind
    try:
        module.op.get_bind = lambda: _Bind()  # type: ignore[assignment]
        try:
            module.downgrade()
            raise AssertionError("expected NotImplementedError")
        except NotImplementedError as exc:
            assert "41" in str(exc)
    finally:
        module.op.get_bind = original_get_bind
