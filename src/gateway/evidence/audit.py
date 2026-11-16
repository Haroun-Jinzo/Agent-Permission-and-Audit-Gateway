from __future__ import annotations

from pathlib import Path

from gateway.infra.repository import connect_database

import copy
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from gateway.canonical import canonical_json, entry_hash, genesis_hash

_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "credentials",
        "password",
        "secret",
        "secret_hash",
        "token",
    }
)

@dataclass(frozen=True, slots=True)
class AuditEntry:
    chain_id: str
    seq: int
    ts: str
    kind: str
    body: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def canonical_serialize(self) -> bytes:
        return canonical_json(self.body)


    def compute_hash(self) -> str:
        return entry_hash(self.prev_hash, self.body)

#check if the value is a dict, if so, redact sensitive keys, if it's a list, recursively redact each item, otherwise return the value as is
def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _REDACTED if key.lower() in _SENSITIVE_KEYS else redact(nested)
            for key, nested in value.items()
        }
    
    if isinstance(value, list):
        return [redact(nested) for nested in value]
    
    return copy.deepcopy(value)

class AuditWriter:
    def __init__(self, db_path: Path, agent_id: str) -> None:
        if not agent_id:
            raise ValueError("agent_id must be set")
        self._db_path = db_path
        self._agent_id = agent_id

    def append(
        self,
        *,
        kind: str,
        fields: dict[str, Any],
        timestamp: str,
    ) -> AuditEntry:
        body_fields = redact(fields)

        with connect_database(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Read audit_heads.
            # Insert audit_entries.
            # Update audit_heads.

            # Leaving the with block commits.
            head = connection.execute("""
                SELECT head_seq, head_hash
                FROM audit_heads
                WHERE chain_id = ?
                """, (self._agent_id,)).fetchone()

            if head is None:
                seq = 1
                previous_hash = genesis_hash(self._agent_id)
            else:
                seq = int(head["head_seq"]) + 1
                previous_hash = str(head["head_hash"])

            body = {
                "v": 1,
                "chain_id": self._agent_id,
                "seq": seq,
                "ts": timestamp,
                "kind": kind,
                **body_fields,
            }
            serialized_body = canonical_json(body).decode("utf-8")
            current_hash = entry_hash(previous_hash, body)

            connection.execute(
                """
                INSERT INTO audit_entries (
                    chain_id, seq, ts, kind, call_hash, approval_id, body,
                    prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self._agent_id, seq, timestamp, kind, body.get("call_hash"),
                body.get("approval_id"), serialized_body, previous_hash, current_hash),
            )

            connection.execute(
                """
                INSERT INTO audit_heads (chain_id, head_seq, head_hash, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(chain_id) DO UPDATE SET
                    head_seq = excluded.head_seq,
                    head_hash = excluded.head_hash,
                    updated_at = excluded.updated_at
                """,
                (self._agent_id, seq, current_hash, timestamp),
            )
        
        return AuditEntry(
            chain_id=self._agent_id,
            seq=seq,
            ts=timestamp,
            kind=kind,
            body=body,
            prev_hash=previous_hash,
            entry_hash=current_hash
        )

    def append_intent(
        self,
        *,
        fields: dict[str, Any],
        timestamp: str,
    ) -> AuditEntry:
        """ Append INTENT: callers must not execute if this raises."""
        return self.append(kind="INTENT", fields=fields, timestamp=timestamp,)