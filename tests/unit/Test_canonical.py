"""Tests T01 to T03: canonical JSON and the hashes built on it.

Two kinds of check:
  1. Published vectors (hard-coded): the exact answers from docs/data-model.md, section 10.9.
  2. A cross-check against the reference spec/vectors.py on thousands of random inputs.
Adjust the import below if your function names differ.
"""

from __future__ import annotations

import hashlib
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gateway.canonical import (
    CanonicalError,
    call_hash,
    canonical_json,
    entry_hash,
    genesis_hash,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------- the published vectors
CALL = {
    "agent_id": "demo-agent",
    "task_id": "task-1",
    "tool": "send_email",
    "arguments": {"to": "attacker@evil.example", "body": "hello"},
}
CALL_CANONICAL = (
    b'{"agent_id":"demo-agent","arguments":{"body":"hello","to":"attacker@evil.example"},'
    b'"task_id":"task-1","tool":"send_email"}'
)
CALL_HASH = "7f9b4913798426a3cca83230761db396c9e639704ed34ef677b541f7440b1764"
GENESIS = "2d97a56fcd84f228c0a60d986b1548b617f1e36cd1b0d957fde766caa6876583"

BODY_1 = {
    "v": 1,
    "chain_id": "demo-agent",
    "seq": 1,
    "ts": "2026-11-10T09:00:00.000000Z",
    "kind": "INTENT",
    "task_id": "task-1",
    "tool": "send_email",
    "call_hash": CALL_HASH,
    "decision": "BLOCK",
    "rule_ids": ["R-EXFIL-1"],
    "policy_version": "default-policy@3:ab12cd34ef56",
}
BODY_1_CANONICAL = (
    b'{"call_hash":"7f9b4913798426a3cca83230761db396c9e639704ed34ef677b541f7440b1764",'
    b'"chain_id":"demo-agent","decision":"BLOCK","kind":"INTENT",'
    b'"policy_version":"default-policy@3:ab12cd34ef56","rule_ids":["R-EXFIL-1"],"seq":1,'
    b'"task_id":"task-1","tool":"send_email","ts":"2026-11-10T09:00:00.000000Z","v":1}'
)
ENTRY_1_HASH = "053eb12b6acb1bb806add66a0b4e920d07abd200ea6078d3e086ffff45a21f82"

BODY_2 = {
    "v": 1,
    "chain_id": "demo-agent",
    "seq": 2,
    "ts": "2026-11-10T09:00:01.000000Z",
    "kind": "OUTCOME",
    "task_id": "task-1",
    "tool": "send_email",
    "call_hash": CALL_HASH,
    "outcome": "not_executed",
    "reason": "blocked_by_policy",
}
ENTRY_2_HASH = "28f7852f2bd2e42028cf102c313e3bb90c591d4e9b371c7f1b7170fc9f0c3dd8"


# ---------------------------------------------------------------- T01: canonical JSON rules
def test_keys_are_sorted_and_whitespace_removed() -> None:
    assert canonical_json({"b": 1, "a": [1, 2], "c": {"z": True, "y": "x"}}) == (
        b'{"a":[1,2],"b":1,"c":{"y":"x","z":true}}'
    )


def test_key_order_does_not_change_the_bytes() -> None:
    first = {"to": "bob@company.example", "subject": "Hi"}
    second = {"subject": "Hi", "to": "bob@company.example"}
    assert canonical_json(first) == canonical_json(second)


def test_list_order_is_preserved() -> None:
    assert canonical_json({"x": [3, 1, 2]}) == b'{"x":[3,1,2]}'


def test_booleans_are_written_as_json_booleans_not_numbers() -> None:
    assert canonical_json({"t": True, "f": False}) == b'{"f":false,"t":true}'


def test_non_ascii_text_is_written_as_utf8_not_escaped() -> None:
    assert canonical_json({"n": "é"}) == b'{"n":"\xc3\xa9"}'


@pytest.mark.parametrize(
    "bad",
    [
        {"n": 1.5},  # float
        {"n": 1.0},  # a float that looks like an integer
        {"n": None},  # null
        {"é": 1},  # key that is not ASCII
        {1: "a"},  # key that is not a string
        {"n": {1, 2}},  # a set is not JSON
        {"n": b"bytes"},  # bytes are not JSON
        {"outer": {"inner": [1, None]}},  # bad value hidden deep inside
    ],
)
def test_invalid_values_are_rejected(bad: object) -> None:
    with pytest.raises(CanonicalError):
        canonical_json(bad)


# ---------------------------------------------------------------- T02: call hash vector
def test_canonical_bytes_of_the_published_call() -> None:
    assert canonical_json(CALL) == CALL_CANONICAL


def test_call_hash_matches_the_published_vector() -> None:
    assert call_hash(CALL) == CALL_HASH


def test_call_hash_uses_the_domain_prefix() -> None:
    without_prefix = hashlib.sha256(CALL_CANONICAL).hexdigest()
    assert call_hash(CALL) != without_prefix


def test_call_hash_changes_when_one_argument_changes() -> None:
    changed = {**CALL, "arguments": {"to": "attacker@evil.example", "body": "hello!"}}
    assert call_hash(changed) != CALL_HASH


# ---------------------------------------------------------------- T03: audit hash vectors
def test_genesis_hash_matches_the_published_vector() -> None:
    assert genesis_hash("demo-agent") == GENESIS


def test_genesis_hash_is_bound_to_the_chain_id() -> None:
    assert genesis_hash("other-agent") != GENESIS


def test_canonical_bytes_of_entry_1() -> None:
    assert canonical_json(BODY_1) == BODY_1_CANONICAL


def test_entry_hashes_match_the_published_vectors() -> None:
    first = entry_hash(GENESIS, BODY_1)
    assert first == ENTRY_1_HASH
    assert entry_hash(first, BODY_2) == ENTRY_2_HASH


def test_changing_an_earlier_entry_changes_every_later_hash() -> None:
    tampered = {**BODY_1, "decision": "ALLOW"}
    tampered_first = entry_hash(GENESIS, tampered)
    assert tampered_first != ENTRY_1_HASH
    assert entry_hash(tampered_first, BODY_2) != ENTRY_2_HASH


# ---------------------------------------------------------------- cross-check with the reference
reference = pytest.importorskip("vectors")  # spec/vectors.py, skipped if it is not there yet

_keys = st.text(alphabet=string.ascii_letters + string.digits + "_-", min_size=1, max_size=8)
_leaves = st.one_of(
    st.text(max_size=20),  # any Unicode text, including accents and emoji
    st.integers(min_value=-(2**53), max_value=2**53),
    st.booleans(),
)
_json = st.recursive(
    _leaves,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(_keys, inner, max_size=4),
    ),
    max_leaves=12,
)


@given(value=st.dictionaries(_keys, _json, max_size=5))
def test_matches_the_reference_on_random_input(value: dict[str, object]) -> None:
    assert canonical_json(value) == reference.canon(value)


@given(value=st.dictionaries(_keys, _json, max_size=5))
def test_key_order_never_matters(value: dict[str, object]) -> None:
    reordered = dict(reversed(list(value.items())))
    assert canonical_json(value) == canonical_json(reordered)