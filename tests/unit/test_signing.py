from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.canonical import call_hash, canonical_json
from gateway.evidence.signing import Ed25519Signer


def test_approval_signature_vector_verifies() -> None:
    seed = bytes(range(1, 33))
    signer = Ed25519Signer.from_seed(seed)

    call = {
        "agent_id": "demo-agent",
        "task_id": "task-1",
        "tool": "send_email",
        "arguments": {"to": "attacker@evil.example", "body": "hello"},
    }
    body = {
        "v": 1,
        "approval_id": "appr-0001",
        "approver_id": "approver-1",
        "call_hash": call_hash(call),
        "decision": "approve",
    }
    message = b"gwapproval-v1\n" + canonical_json(body)
    signature = signer.sign(message)

    assert signer.verify(message, signature)


def test_changed_message_fails_verification() -> None:
    signer = Ed25519Signer.from_seed(bytes(range(1, 33)))
    message = b"gwapproval-v1\noriginal"
    signature = signer.sign(message)

    assert not signer.verify(b"gwapproval-v1\nchanged", signature)


def test_public_key_only_signer_can_verify() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    signer = Ed25519Signer(private_key=private)
    verifier = Ed25519Signer.from_public_bytes(signer.public_key_bytes)

    message = b"gwapproval-v1\nmessage"
    signature = signer.sign(message)

    assert verifier.verify(message, signature)
