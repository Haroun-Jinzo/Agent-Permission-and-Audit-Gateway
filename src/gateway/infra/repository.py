from __future__ import annotations

import sqlite3
from pathlib import Path


class AgentScopeError(RuntimeError):
    """Raised when an agent attempts to access a resource outside its scope."""
    pass

class Repository:
    def __init__(self, db_path: str | Path) -> None:
        self._connection = sqlite3.connect(db_path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self.run_migrations()

    def for_agent(self, agent_id: str) -> ScopedRepository:
        if not agent_id:
            raise AgentScopeError("agent scope is required")
        return ScopedRepository(self._connection, agent_id)

    def run_migrations(self) -> None:
        """Run database migrations to ensure the schema is up to date."""
        # Load and execute migrations/001_initial.sql here.
        migration_path = (Path(__file__).resolve().parent / "db" / "migrations" / "001_initial.sql")

        if not migration_path.is_file():
            raise RuntimeError(f"Migration file not found: {migration_path}")

        self._connection.executescript(migration_path.read_text(encoding="utf-8"))
        self._connection.commit()

class ScopedRepository:
    def __init__(self, connection: sqlite3.Connection, agent_id: str) -> None:
        self._connection = connection
        self._agent_id = agent_id

    def list_tasks(self) -> list[sqlite3.Row]:
        return list(
            self._connection.execute(
                "SELECT * FROM tasks WHERE agent_id = ?",
                (self._agent_id,),
            )
        )

    def get_approval(self, approval_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ? AND agent_id = ?",
            (approval_id, self._agent_id),
        ).fetchone()
