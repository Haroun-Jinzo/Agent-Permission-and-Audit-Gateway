from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from gateway.canonical import CanonicalError, canonical_json, entry_hash, genesis_hash
from gateway.infra.repository import connect_database


class PublicVerifier(Protocol):
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature for the exact message bytes."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    chain_id: str
    checked_entries: int
    broken_seq: int | None = None
    reason: str | None = None


class ChainVerifier:
    def __init__(
        self,
        db_path: str | Path,
        chain_id: str,
        anchor_store: str | Path | None = None,
        public_verifier: PublicVerifier | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.chain_id = chain_id
        self.anchor_store = Path(anchor_store) if anchor_store is not None else None
        self.public_verifier = public_verifier

    def verify_chain(self) -> VerificationResult:
        previous_hash = genesis_hash(self.chain_id)
        expected_seq = 1
        checked = 0

        with connect_database(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT chain_id, seq, ts, kind, body, prev_hash, entry_hash
                FROM audit_entries
                WHERE chain_id = ?
                ORDER BY seq""",
                (self.chain_id,),
            )

            for row in rows:
                seq = int(row["seq"])
                body_text = str(row["body"])

                if seq != expected_seq:
                    return self._failure(
                        checked,
                        seq,
                        f"expected sequence {expected_seq}, but got {seq}",
                    )

                if row["prev_hash"] != previous_hash:
                    return self._failure(
                        checked,
                        seq,
                        "previous hash does not match the preceding entry",
                    )

                try:
                    body: Any = json.loads(body_text)
                except json.JSONDecodeError as e:
                    return self._failure(
                        checked,
                        seq,
                        f"stored body is not valid JSON: {e}",
                    )

                try:
                    canonical_body = canonical_json(body)
                except CanonicalError as exc:
                    return self._failure(
                        checked,
                        seq,
                        f"stored body is not canonical JSON: {exc}",
                    )

                if canonical_body.decode("utf-8") != body_text:
                    return self._failure(
                        checked,
                        seq,
                        "stored body is not canonical JSON",
                    )

                if not isinstance(row["entry_hash"], str):
                    return self._failure(
                        checked,
                        seq,
                        "stored entry_hash is not a string",
                    )

                if (
                    body.get("chain_id") != self.chain_id
                    or body.get("seq") != seq
                    or body.get("ts") != row["ts"]
                    or body.get("kind") != row["kind"]
                ):
                    return self._failure(
                        checked,
                        seq,
                        "stored body does not match the other fields in the entry",
                    )

                calculated_hash = entry_hash(previous_hash, body)
                if calculated_hash != row["entry_hash"]:
                    return self._failure(
                        checked,
                        seq,
                        "calculated entry_hash does not match the stored entry_hash",
                    )

                previous_hash = calculated_hash
                expected_seq += 1
                checked += 1

        return VerificationResult(
            valid=True,
            chain_id=self.chain_id,
            checked_entries=checked,
        )

    def compare_with_anchor(
        self,
        anchor_store: str | Path | None = None,
        public_verifier: PublicVerifier | None = None,
    ) -> VerificationResult:
        """Verify the chain and compare its current head with a trusted external anchor."""
        internal = self.verify_chain()
        if not internal.valid:
            return internal

        store = Path(anchor_store) if anchor_store is not None else self.anchor_store
        verifier = public_verifier or self.public_verifier

        if store is None or verifier is None:
            return internal

        with connect_database(self.db_path) as connection:
            head = connection.execute(
                """
                SELECT head_seq, head_hash
                FROM audit_heads
                WHERE chain_id = ?
                """,
                (self.chain_id,),
            ).fetchone()

        if head is None:
            return self._failure(
                internal.checked_entries,
                0,
                "chain head is missing",
            )

        head_seq = int(head["head_seq"])
        head_hash = str(head["head_hash"])
        anchor_file = store / self.chain_id / f"{head_seq}.json"

        if not anchor_file.is_file():
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor file is missing",
            )

        try:
            anchor_text = anchor_file.read_text(encoding="utf-8")
            anchor: Any = json.loads(anchor_text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self._failure(
                internal.checked_entries,
                head_seq,
                f"trusted anchor is not valid JSON: {exc}",
            )

        if not isinstance(anchor, dict):
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor must be a JSON object",
            )

        try:
            canonical_anchor = canonical_json(anchor)
        except CanonicalError as exc:
            return self._failure(
                internal.checked_entries,
                head_seq,
                f"trusted anchor is not canonical JSON: {exc}",
            )

        if canonical_anchor.decode("utf-8") != anchor_text:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor is not canonical JSON",
            )

        required_fields = {
            "v",
            "chain_id",
            "head_seq",
            "head_hash",
            "anchored_at",
            "signature",
        }
        if not required_fields.issubset(anchor):
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor is missing required fields",
            )

        signed_body = {
            "v": anchor["v"],
            "chain_id": anchor["chain_id"],
            "head_seq": anchor["head_seq"],
            "head_hash": anchor["head_hash"],
            "anchored_at": anchor["anchored_at"],
        }

        try:
            signature = bytes.fromhex(str(anchor["signature"]))
        except ValueError:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor signature is invalid",
            )

        if len(signature) != 64:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor signature is invalid",
            )

        message = b"gwanchor-v1\n" + canonical_json(signed_body)
        if not verifier.verify(message, signature):
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor signature is invalid",
            )

        if anchor["chain_id"] != self.chain_id:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor belongs to a different chain",
            )

        if anchor["head_seq"] != head_seq:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor sequence differs from current chain head",
            )

        if anchor["head_hash"] != head_hash:
            return self._failure(
                internal.checked_entries,
                head_seq,
                "trusted anchor hash differs from current chain head",
            )

        return internal

    def _failure(self, checked: int, broken_seq: int, reason: str) -> VerificationResult:
        return VerificationResult(
            valid=False,
            chain_id=self.chain_id,
            checked_entries=checked,
            broken_seq=broken_seq,
            reason=reason,
        )
