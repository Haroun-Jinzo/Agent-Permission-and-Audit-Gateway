from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from gateway.canonical import canonical_json
from gateway.infra.repository import connect_database


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes:
        """Sign the exact message bytes."""


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    chain_id: str
    head_seq: int
    head_hash: str
    anchored_at: str
    signature: str
    anchor_ref: str


class AnchorPublisher:
    def __init__(
        self,
        db_path: str | Path,
        chain_id: str,
        anchor_store: str | Path,
        signer: Signer,
    ) -> None:
        if not chain_id:
            raise ValueError("chain_id is required")

        self.db_path = Path(db_path)
        self.chain_id = chain_id
        self.anchor_store = Path(anchor_store)
        self.signer = signer

    def publish(self, anchored_at: str) -> AnchorRecord:
        """Publish the current audit head to SQLite and the external anchor store."""
        with connect_database(self.db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")

            head = connection.execute(
                """
                SELECT head_seq, head_hash
                FROM audit_heads
                WHERE chain_id = ?
                """,
                (self.chain_id,),
            ).fetchone()

            if head is None:
                raise RuntimeError(f"No audit head exists for chain {self.chain_id}")

            head_seq = int(head["head_seq"])
            head_hash = str(head["head_hash"])

            existing = connection.execute(
                """
                SELECT head_hash, anchored_at, signature, anchor_ref
                FROM anchors
                WHERE chain_id = ? AND head_seq = ?
                """,
                (self.chain_id, head_seq),
            ).fetchone()

            if existing is not None:
                if str(existing["head_hash"]) != head_hash:
                    raise RuntimeError("Existing anchor conflicts with the current chain head")

                return AnchorRecord(
                    chain_id=self.chain_id,
                    head_seq=head_seq,
                    head_hash=head_hash,
                    anchored_at=str(existing["anchored_at"]),
                    signature=str(existing["signature"]),
                    anchor_ref=str(existing["anchor_ref"]),
                )

            anchor_body = {
                "v": 1,
                "chain_id": self.chain_id,
                "head_seq": head_seq,
                "head_hash": head_hash,
                "anchored_at": anchored_at,
            }
            signature_hex = self.signer.sign(b"gwanchor-v1\n" + canonical_json(anchor_body)).hex()

            if len(signature_hex) != 128:
                raise ValueError("Ed25519 signature must contain exactly 128 hex characters")

            document = {
                **anchor_body,
                "signature": signature_hex,
            }

            chain_folder = self.anchor_store / self.chain_id
            chain_folder.mkdir(parents=True, exist_ok=True)

            anchor_file = chain_folder / f"{head_seq}.json"
            temporary_file = chain_folder / f".{head_seq}.json.tmp"
            canonical_document = canonical_json(document)

            if anchor_file.exists():
                existing_document = anchor_file.read_bytes()
                if existing_document != canonical_document:
                    raise RuntimeError("Existing anchor file conflicts with the new anchor")
                anchor_ref = str(anchor_file)
            else:
                temporary_file.write_bytes(canonical_document)
                temporary_file.replace(anchor_file)
                anchor_ref = str(anchor_file)

            try:
                connection.execute(
                    """
                    INSERT INTO anchors (
                        chain_id,
                        head_seq,
                        head_hash,
                        anchored_at,
                        signature,
                        anchor_ref
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.chain_id,
                        head_seq,
                        head_hash,
                        anchored_at,
                        signature_hex,
                        anchor_ref,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError("An anchor already exists for this chain head") from exc

            return AnchorRecord(
                chain_id=self.chain_id,
                head_seq=head_seq,
                head_hash=head_hash,
                anchored_at=anchored_at,
                signature=signature_hex,
                anchor_ref=anchor_ref,
            )
