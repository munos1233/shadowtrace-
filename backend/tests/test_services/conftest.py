"""Shared fixtures for PostgreSQL-backed service tests (ISSUE-267)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.usefixtures("clean_state")
