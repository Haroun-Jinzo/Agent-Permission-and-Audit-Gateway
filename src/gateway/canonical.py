import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    """Raised when a value cannot be represented in canonical JSON."""


def _reject_floats_and_null(value: Any) -> None:
    if value is None or isinstance(value, float):
        raise CanonicalError("floats and null are not allowed")

    if isinstance(value, dict):
        for key, nested_value in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalError("keys must be ASCII strings")
            _reject_floats_and_null(nested_value)
        return

    if isinstance(value, (list, tuple)):
        for nested_value in value:
            _reject_floats_and_null(nested_value)
        return

    if not isinstance(value, (str, int, bool)):
        raise CanonicalError("unsupported type")


def canonical_json(obj: Any) -> bytes:
    """Convert an object to deterministic canonical JSON bytes."""
    _reject_floats_and_null(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def call_hash(call: Any) -> str:
    """Compute the hash of a tool call object."""
    if not isinstance(call, dict):
        raise CanonicalError("call must be a dictionary")
    data = b"gwcall-v1\n" + canonical_json(call)
    return hashlib.sha256(data).hexdigest()


def genesis_hash(chain_id: str) -> str:
    """Compute the hash of an audit chain's identifier."""
    if not isinstance(chain_id, str):
        raise CanonicalError("chain_id must be a string")
    data = b"gwaudit-genesis-v1\n" + chain_id.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def entry_hash(previous_hash: str, body: Any) -> str:
    """Compute the hash of an audit entry linked to the previous hash."""
    if not isinstance(previous_hash, str):
        raise CanonicalError("previous_hash must be a string")
    data = b"gwaudit-v1\n" + previous_hash.encode("utf-8") + b"\n" + canonical_json(body)
    return hashlib.sha256(data).hexdigest()
