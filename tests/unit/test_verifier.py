from __future__ import annotations

import json

from gateway.evidence.audit import AuditWriter
from gateway.evidence.verifier import ChainVerifier
from gateway.infra.repository import Repository, connect_database

NOW = "2026-11-10T09:00:00.000000Z"
CHAIN_ID = "demo-agent"


def create_writer(tmp_path) -> tuple[AuditWriter, str]:
    db_path = tmp_path / "gateway.sqlite"
    Repository(db_path)

    writer = AuditWriter(db_path, CHAIN_ID)
    return writer, str(db_path)


def append_entries(writer: AuditWriter) -> None:
    writer.append_intent(
        fields={
            "task_id": "task-1",
            "tool": "send_email",
            "call_hash": "a" * 64,
            "decision": "BLOCK",
        },
        timestamp=NOW,
    )
    writer.append(
        kind="OUTCOME",
        fields={
            "task_id": "task-1",
            "tool": "send_email",
            "call_hash": "a" * 64,
            "outcome": "not_executed",
        },
        timestamp=NOW,
    )


def test_clean_chain_passes(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is True
    assert result.chain_id == CHAIN_ID
    assert result.checked_entries == 2
    assert result.broken_seq is None
    assert result.reason is None


def test_empty_chain_passes(tmp_path) -> None:
    _, db_path = create_writer(tmp_path)

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is True
    assert result.checked_entries == 0


def test_edited_entry_reports_first_broken_entry(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    with connect_database(db_path) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET body = replace(body, 'BLOCK', 'ALLOW')
            WHERE chain_id = ? AND seq = 1
            """,
            (CHAIN_ID,),
        )

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is False
    assert result.broken_seq == 1
    assert result.checked_entries == 0
    assert result.reason == ("calculated entry_hash does not match the stored entry_hash")


def test_noncanonical_body_is_rejected(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    with connect_database(db_path) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")

        row = connection.execute(
            """
            SELECT body
            FROM audit_entries
            WHERE chain_id = ? AND seq = 1
            """,
            (CHAIN_ID,),
        ).fetchone()

        body = json.loads(row["body"])
        noncanonical_body = json.dumps(
            body,
            indent=2,
            ensure_ascii=False,
        )

        connection.execute(
            """
            UPDATE audit_entries
            SET body = ?
            WHERE chain_id = ? AND seq = 1
            """,
            (noncanonical_body, CHAIN_ID),
        )

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is False
    assert result.broken_seq == 1
    assert result.checked_entries == 0
    assert result.reason == ("stored body is not canonical JSON")


def test_broken_previous_hash_is_rejected(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    with connect_database(db_path) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET prev_hash = ?
            WHERE chain_id = ? AND seq = 2
            """,
            ("0" * 64, CHAIN_ID),
        )

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is False
    assert result.broken_seq == 2
    assert result.checked_entries == 1
    assert result.reason == (
        "previous hash does not match the preceding entry"
    )


def test_broken_sequence_is_rejected(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    with connect_database(db_path) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET seq = 3
            WHERE chain_id = ? AND seq = 2
            """,
            (CHAIN_ID,),
        )

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is False
    assert result.broken_seq == 3
    assert result.checked_entries == 1
    assert result.reason == "expected sequence 2, but got 3"


def test_body_metadata_mismatch_is_rejected(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    with connect_database(db_path) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET kind = 'REJECTED'
            WHERE chain_id = ? AND seq = 1
            """,
            (CHAIN_ID,),
        )

    result = ChainVerifier(db_path, CHAIN_ID).verify_chain()

    assert result.valid is False
    assert result.broken_seq == 1
    assert result.checked_entries == 0
    assert result.reason == (
        "stored body does not match the other fields in the entry"
    )


def test_compare_with_anchor_uses_chain_verification_until_s09(tmp_path) -> None:
    writer, db_path = create_writer(tmp_path)
    append_entries(writer)

    result = ChainVerifier(db_path, CHAIN_ID).compare_with_anchor()

    assert result.valid is True
    assert result.checked_entries == 2