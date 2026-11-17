from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.canonical import CanonicalError, canonical_json, entry_hash, genesis_hash
from gateway.infra.repository import connect_database

@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    chain_id: str
    checked_entries: int
    broken_seq: int | None = None
    reason: str | None = None

class ChainVerifier:
    def __init__(self, db_path: str | Path, chain_id: str) -> None:
        self.db_path = Path(db_path)
        self.chain_id = chain_id

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

    def compare_with_anchor(self) -> VerificationResult:
        """Stub for signed anchor validation in s09"""
        return self.verify_chain()
    
    def _failure(self, checked: int, broken_seq: int, reason: str) -> VerificationResult:
        return VerificationResult(
            valid=False,
            chain_id=self.chain_id,
            checked_entries=checked,
            broken_seq=broken_seq,
            reason=reason,
        )