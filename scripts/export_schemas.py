"""Export JSON Schema for every core model into ``contracts/schemas/``.

Usage:
    python scripts/export_schemas.py [--out contracts/schemas]

Each model in ``app.models.MODEL_REGISTRY`` is written to
``{out}/{model_name}.json``. The schema-export test compares the model set to the
file set, so adding a model without exporting (or vice versa) fails CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a plain script from the repo root.
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.models import MODEL_REGISTRY  # noqa: E402

_DEFAULT_OUT = Path(__file__).resolve().parents[1] / "contracts" / "schemas"


def export_schemas(out_dir: Path) -> list[Path]:
    """Write one JSON Schema file per registered model; return written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in sorted(MODEL_REGISTRY.items()):
        schema = model.model_json_schema()
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="Export core model JSON Schemas.")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    written = export_schemas(args.out)
    print(f"Exported {len(written)} schemas to {args.out}")


if __name__ == "__main__":
    main()
