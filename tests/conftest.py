"""Shared fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


@pytest.fixture
def fixed_now() -> datetime:
    """A fixed UTC time, so tests never depend on the real clock."""
    return datetime(2026, 11, 10, 9, 0, 0, tzinfo=UTC)
