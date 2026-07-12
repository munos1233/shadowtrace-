"""Export the OpenAPI 3.1 document to ``contracts/openapi/openapi.json``.

Usage:
    python scripts/export_openapi.py [--out contracts/openapi/openapi.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.main import app  # noqa: E402

_DEFAULT_OUT = Path(__file__).resolve().parents[1] / "contracts" / "openapi" / "openapi.json"


def export_openapi(out_path: Path) -> Path:
    """Write the app's OpenAPI schema to ``out_path`` and return it."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()
    out_path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export OpenAPI document.")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    out = export_openapi(args.out)
    print(f"Exported OpenAPI to {out}")


if __name__ == "__main__":
    main()
