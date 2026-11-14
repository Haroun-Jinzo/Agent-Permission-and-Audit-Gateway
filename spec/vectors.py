import json, hashlib, unicodedata

def canon(obj):
    def check(o):
        if isinstance(o, float) or o is None:
            raise ValueError("floats and null are not allowed")
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(k, str) or not k.isascii():
                    raise ValueError("keys must be ASCII strings")
                check(v)
        elif isinstance(o, (list, tuple)):
            for v in o: check(v)
        elif not isinstance(o, (str, int, bool)):
            raise ValueError("unsupported type")
    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha(b): return hashlib.sha256(b).hexdigest()

def call_hash(call):
    return sha(b"gwcall-v1\n" + canon(call))

def genesis(chain_id):
    return sha(b"gwaudit-genesis-v1\n" + chain_id.encode())

def entry_hash(prev_hash, body):
    return sha(b"gwaudit-v1\n" + prev_hash.encode() + b"\n" + canon(body))

if __name__ == "__main__":
    call = {"agent_id": "demo-agent", "task_id": "task-1", "tool": "send_email",
            "arguments": {"to": "attacker@evil.example", "body": "hello"}}
    ch = call_hash(call)
    print("canonical call:", canon(call).decode())
    print("call_hash:", ch)
    g = genesis("demo-agent")
    print("genesis prev_hash:", g)
    body1 = {"v": 1, "chain_id": "demo-agent", "seq": 1, "ts": "2026-11-10T09:00:00.000000Z",
             "kind": "INTENT", "task_id": "task-1", "tool": "send_email", "call_hash": ch,
             "decision": "BLOCK", "rule_ids": ["R-EXFIL-1"],
             "policy_version": "default-policy@3:ab12cd34ef56"}
    print("canonical body 1:", canon(body1).decode())
    h1 = entry_hash(g, body1)
    print("entry_hash 1:", h1)
    body2 = {"v": 1, "chain_id": "demo-agent", "seq": 2, "ts": "2026-11-10T09:00:01.000000Z",
             "kind": "OUTCOME", "task_id": "task-1", "tool": "send_email", "call_hash": ch,
             "outcome": "not_executed", "reason": "blocked_by_policy"}
    print("canonical body 2:", canon(body2).decode())
    h2 = entry_hash(h1, body2)
    print("entry_hash 2:", h2)

    # approval signature vector
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        seed = bytes(range(1, 33))
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        msgbody = {"v": 1, "approval_id": "appr-0001", "approver_id": "approver-1",
                   "call_hash": ch, "decision": "approve"}
        msg = b"gwapproval-v1\n" + canon(msgbody)
        sig = sk.sign(msg)
        print("approval message body:", canon(msgbody).decode())
        print("seed hex:", seed.hex())
        print("public key hex:", pk.hex())
        print("signature hex:", sig.hex())
        sk.public_key().verify(sig, msg)
        print("verify ok")
        # tamper check
        bad = {**msgbody, "decision": "reject"}
        try:
            sk.public_key().verify(sig, b"gwapproval-v1\n" + canon(bad)); print("TAMPER NOT DETECTED")
        except Exception: print("tamper detected")
    except ImportError as e:
        print("cryptography missing", e)
