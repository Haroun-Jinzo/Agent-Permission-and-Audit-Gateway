"""Configuration read from environment variables.

Invalid configuration raises an error at startup. A security gateway must not
start with a setting it does not understand.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
_ENVIRONMENTS = frozenset({"development", "test", "production"})


class SettingsError(ValueError):
    """A configuration value is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: Path
    log_level: str
    environment: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        log_level = source.get("GATEWAY_LOG_LEVEL", "INFO").upper()
        environment = source.get("GATEWAY_ENV", "development").lower()
        if log_level not in _LOG_LEVELS:
            raise SettingsError(f"GATEWAY_LOG_LEVEL must be one of {sorted(_LOG_LEVELS)}")
        if environment not in _ENVIRONMENTS:
            raise SettingsError(f"GATEWAY_ENV must be one of {sorted(_ENVIRONMENTS)}")
        return cls(
            db_path=Path(source.get("GATEWAY_DB_PATH", "gateway.db")),
            log_level=log_level,
            environment=environment,
        )
