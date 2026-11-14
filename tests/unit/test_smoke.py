from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

import gateway
import gatewayctl
from gateway.settings import Settings, SettingsError

pytestmark = pytest.mark.unit


def test_packages_import() -> None:
    assert gateway.__version__ == "0.1.0"
    assert gatewayctl.__doc__


def test_settings_defaults() -> None:
    s = Settings.from_env({})
    assert s.db_path == Path("gateway.db")
    assert s.log_level == "INFO"
    assert s.environment == "development"


def test_settings_read_values() -> None:
    s = Settings.from_env(
        {"GATEWAY_DB_PATH": "/tmp/x.db", "GATEWAY_LOG_LEVEL": "debug", "GATEWAY_ENV": "TEST"}  # noqa: S108
    )
    assert s.log_level == "DEBUG"
    assert s.environment == "test"


@pytest.mark.parametrize(
    "env",
    [{"GATEWAY_LOG_LEVEL": "LOUD"}, {"GATEWAY_ENV": "staging"}],
)
def test_invalid_settings_fail_closed(env: dict[str, str]) -> None:
    with pytest.raises(SettingsError):
        Settings.from_env(env)


def test_fixed_clock_fixture(fixed_now: datetime) -> None:
    assert fixed_now.isoformat() == "2026-11-10T09:00:00+00:00"
