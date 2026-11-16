from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

class Signer(Protocol):
    @property
    def public_key_bytes(self) -> bytes:
        ...
    
    def sign(self, message: bytes) -> bytes:
        ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        ...


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey | None = None,
                public_key: Ed25519PublicKey | None = None) -> None:

        if private_key is None and public_key is None:
            raise ValueError("Either private_key or public_key must be provided.")

        self._private_key = private_key
        self._public_key = (private_key.public_key() if private_key is not None else public_key)
    

    @classmethod
    def from_seed(cls, seed:bytes) -> Ed25519Signer:
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes long.")
        return cls(private_key=Ed25519PrivateKey.from_private_bytes(seed))
    
    @classmethod
    def from_public_bytes(cls, public_key_bytes: bytes) -> Ed25519Signer:
        if len(public_key_bytes) != 32:
            raise ValueError("Public key must be 32 bytes long.")
        return cls(public_key=Ed25519PublicKey.from_public_bytes(public_key_bytes))
    
    @property
    def public_key_bytes(self) -> bytes:
        if self._public_key is None:
            raise RuntimeError("Public key is not available.")
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        if self._private_key is None:
            raise RuntimeError("Private key is not available for signing.")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        if self._public_key is None:
            raise RuntimeError("Public key is not available for verification.")
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False