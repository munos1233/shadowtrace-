"""Agent tests that share PostgreSQL fixtures (ISSUE-267 isolation)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.usefixtures("clean_state")
