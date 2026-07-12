"""Run standalone MockXDRServer (ISSUE-010).

Usage:
    python scripts/run_mock_xdr.py [--host 127.0.0.1] [--port 8100]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import uvicorn  # noqa: E402

from app.mock_xdr.api import app  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("run_mock_xdr")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run MockXDRServer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8100)
    args = parser.parse_args(argv)
    logger.info(
        "starting MockXDRServer on http://%s:%s/mock-xdr/v1 (no credentials logged)",
        args.host,
        args.port,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
