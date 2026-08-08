"""DB migration tests share one PostgreSQL instance (ISSUE-267 isolation)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.usefixtures("clean_state")
