from __future__ import annotations

import json

from gateway.canonical import canonical_json
from gateway.evidence.anchor import AnchorPublisher
from gateway.evidence.audit import AuditWriter
from gateway.evidence.signing import Ed25519Signer
from gateway.evidence.verifier import ChainVerifier
from gateway.infra.repository import Repository, connect_database

CHAIN_ID = "demo-agent"
NOW = "2026-11-10T09:00:00.000000Z"
SEED = bytes(range(1, 33))


def create_published_chain(tmp_path) -> tuple[str, object, object]:
    db_path = tmp_path / "gateway.sqlite"
    anchor_store = tmp_path / "anchor-store"
    signer = Ed25519Signer.from_seed(SEED)

    Repository(db_path)
    writer = AuditWriter(db_path, CHAIN_ID)
    writer.append_intent(
        fields={
            "task_id": "task-1",
            "tool": "send_email",
            "call_hash": "a" * 64,
        },
        timestamp=NOW,
    )

    publisher = AnchorPublisher(db_path, CHAIN_ID, anchor_store, signer)
    publisher.publish(NOW)

    return str(db_path), anchor_store, signer


def test_publish_writes_external_anchor_and_sql_record(tmp_path) -> None:
    db_path, anchor_store, _ = create_published_chain(tmp_path)

    anchor_file = anchor_store / CHAIN_ID / "1.json"
    assert anchor_file.is_file()

    with connect_database(db_path) as connection:
        row = connection.execute(
            """
            SELECT chain_id, head_seq, head_hash, signature, anchor_ref
            FROM anchors
            WHERE chain_id = ? AND head_seq = 1
            """,
            (CHAIN_ID,),
        ).fetchone()

    assert row is not None
    assert row["chain_id"] == CHAIN_ID
    assert len(row["signature"]) == 128
    assert row["anchor_ref"] == str(anchor_file)


def test_published_anchor_signature_verifies(tmp_path) -> None:
    db_path, anchor_store, signer = create_published_chain(tmp_path)
    anchor_file = anchor_store / CHAIN_ID / "1.json"
    document_text = anchor_file.read_text(encoding="utf-8")
    document = json.loads(document_text)

    signed_body = {
        "v": document["v"],
        "chain_id": document["chain_id"],
        "head_seq": document["head_seq"],
        "head_hash": document["head_hash"],
        "anchored_at": document["anchored_at"],
    }
    message = b"gwanchor-v1\n" + canonical_json(signed_body)

    verifier = Ed25519Signer.from_public_bytes(signer.public_key_bytes)
    assert verifier.verify(message, bytes.fromhex(document["signature"]))

    result = ChainVerifier(
        db_path,
        CHAIN_ID,
        anchor_store,
        verifier,
    ).compare_with_anchor()
    assert result.valid is True


def test_publish_is_idempotent(tmp_path) -> None:
    db_path = tmp_path / "gateway.sqlite"
    anchor_store = tmp_path / "anchor-store"
    signer = Ed25519Signer.from_seed(SEED)

    Repository(db_path)
    writer = AuditWriter(db_path, CHAIN_ID)
    writer.append_intent(
        fields={"tool": "send_email"},
        timestamp=NOW,
    )

    publisher = AnchorPublisher(db_path, CHAIN_ID, anchor_store, signer)
    first = publisher.publish(NOW)
    second = publisher.publish(NOW)

    assert first == second

    with connect_database(db_path) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM anchors
            WHERE chain_id = ? AND head_seq = 1
            """,
            (CHAIN_ID,),
        ).fetchone()[0]

    assert count == 1
