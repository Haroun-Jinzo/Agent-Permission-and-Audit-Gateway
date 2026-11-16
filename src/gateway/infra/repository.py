from __future__ import annotations

import sqlite3
from pathlib import Path

class AgentScopeError(RuntimeError):
    """Raised when an agent attempts to access a resource outside its scope."""
    pass


def connect_database(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        db_path,
        timeout=5.0,
        check_same_thread=True,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection

class Repository:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self.run_migrations()

    def run_migrations(self) -> None:
        """Run database migrations to ensure the schema is up to date."""
        # Load and execute migrations/001_initial.sql here.
        migration_path = (Path(__file__).resolve().parent / "db" / "migrations" / "001_initial.sql")

        if not migration_path.is_file():
            raise RuntimeError(f"Migration file not found: {migration_path}")
        
        with connect_database(self._db_path) as connection:
            connection.executescript(migration_path.read_text(encoding="utf-8"))

    def for_agent(self, agent_id: str) -> ScopedRepository:
        if not agent_id:
            raise AgentScopeError("agent scope is required")
        return ScopedRepository(self._db_path, agent_id)

class ScopedRepository:
    def __init__(self, db_path: Path, agent_id: str) -> None:
        self._db_path = db_path
        self._agent_id = agent_id

    def list_tasks(self) -> list[sqlite3.Row]:
        with connect_database(self._db_path) as connection:
            return list(
                connection.execute(
                    "SELECT * FROM tasks WHERE agent_id = ?",
                    (self._agent_id,),
                )
            )
    
    def get_approval(self, approval_id: str) -> sqlite3.Row | None:
        with connect_database(self._db_path) as connection:
            return connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ? AND agent_id = ?",
                (approval_id, self._agent_id),
            ).fetchone()