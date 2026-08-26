"""Observability bind mounts must survive merge with infra/docker-compose.yml.

``make up-demo`` passes ``-f infra/docker-compose.yml`` then
``-f infra/observability/docker-compose.observability.yml``. Compose resolves
bare ``./file`` binds against the first file's directory (``infra/``), so
prometheus/otel configs must be rooted at ``OBSERVABILITY_CONFIG_DIR``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
MAKEFILE_PATH = REPO_ROOT / "Makefile"
OBS_COMPOSE_PATH = REPO_ROOT / "infra" / "observability" / "docker-compose.observability.yml"
OBS_DIR = REPO_ROOT / "infra" / "observability"


def test_makefile_demo_sets_observability_config_dir() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "OBSERVABILITY_CONFIG_DIR=" in text
    assert "infra/observability" in text


def test_observability_compose_bind_sources_use_config_dir() -> None:
    data = yaml.safe_load(OBS_COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    expected = {
        "otel-collector": ["otel-collector-config.yaml"],
        "prometheus": ["prometheus.yml"],
        "grafana": ["grafana-dashboard.json", "grafana-provisioning"],
    }
    for name, filenames in expected.items():
        volumes = services.get(name, {}).get("volumes") or []
        joined = "\n".join(str(item) for item in volumes)
        assert "OBSERVABILITY_CONFIG_DIR" in joined, (
            f"{name} volumes must interpolate OBSERVABILITY_CONFIG_DIR, got {volumes}"
        )
        for filename in filenames:
            assert filename in joined, f"{name} must bind {filename}"
            assert (OBS_DIR / filename).exists(), f"missing host config {OBS_DIR / filename}"
