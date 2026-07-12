"""Data generator framework tests (ISSUE-010)."""

from __future__ import annotations

import json
from pathlib import Path

from app.data_generators import (
    TELEMETRY_FILENAMES,
    NoiseGenerator,
    default_generators,
    write_telemetry_files,
)
from app.data_generators.base import TelemetryGenerator


def test_seven_fixed_filenames(tmp_path: Path) -> None:
    gens = default_generators(seed=123)
    assert len(gens) == 7
    written = write_telemetry_files(gens, tmp_path, count=5)
    names = {p.name for p in written}
    assert names == set(TELEMETRY_FILENAMES.values())
    for path in written:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data) == 5
        assert all("record_id" in row for row in data)


def test_generators_are_deterministic() -> None:
    a = default_generators(seed=7)
    b = default_generators(seed=7)
    for ga, gb in zip(a, b, strict=True):
        assert ga.generate(count=3) == gb.generate(count=3)


def test_noise_is_not_source_object(tmp_path: Path) -> None:
    noise = NoiseGenerator(seed=1)
    rows = noise.generate(count=4)
    assert all(r.get("is_noise") is True for r in rows)
    assert all(r.get("channel") for r in rows)
    # Noise filename is separate from the seven fixed Source-adjacent telemetry files
    assert noise.filename() == "noise_events.json"
    assert noise.filename() not in TELEMETRY_FILENAMES.values()


def test_generators_subclass_base() -> None:
    for gen in default_generators(seed=0):
        assert isinstance(gen, TelemetryGenerator)
