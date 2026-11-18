import sqlite3

import pytest

from gateway.evidence.audit import AuditWriter
from gateway.infra.repository import Repository, connect_database

NOW = "2026-11-10T09:00:00.000000Z"


@pytest.fixture
def writer(tmp_path) -> AuditWriter:
    db_path = tmp_path / "gateway.sqlite"
    Repository(db_path)
    return AuditWriter(db_path, "agent-a")


def test_changed_message_or_body_changes_hash(writer: AuditWriter) -> None:
    first = writer.append_intent(
        fields={"tool": "send_email"},
        timestamp=NOW,
    )
    second = writer.append(
        kind="OUTCOME",
        fields={"tool": "send_email"},
        timestamp=NOW,
    )

    assert second.seq == first.seq + 1
    assert second.prev_hash == first.entry_hash
    assert second.compute_hash() == second.entry_hash


def test_sensitive_fields_are_redacted(writer: AuditWriter) -> None:
    entry = writer.append(
        kind="INTENT",
        fields={
            "token": "secret-value",
            "nested": {"password": "pw"},
        },
        timestamp=NOW,
    )

    assert entry.body["token"] == "[REDACTED]"
    assert entry.body["nested"]["password"] == "[REDACTED]"
    assert "secret-value" not in entry.canonical_serialize().decode()


def execute_with_audit(
    writer: AuditWriter,
    execute_tool: object,
) -> None:
    writer.append_intent(
        fields={"tool": "send_email"},
        timestamp=NOW,
    )
    execute_tool()


def test_failed_intent_write_blocks_execution(
    writer: AuditWriter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def execute_tool() -> None:
        nonlocal called
        called = True

    def fail_append(*args: object, **kwargs: object) -> None:
        raise sqlite3.DatabaseError("audit unavailable")

    monkeypatch.setattr(writer, "append_intent", fail_append)

    with pytest.raises(sqlite3.DatabaseError):
        execute_with_audit(writer, execute_tool)

    assert called is False


def test_each_connection_enables_foreign_keys(tmp_path) -> None:
    db_path = tmp_path / "gateway.sqlite"
    Repository(db_path)

    with connect_database(db_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
