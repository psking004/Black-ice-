from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any


class SigningKeyUnavailable(RuntimeError):
    """Raised when a security-sensitive operation has no operator-provided signing key."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class EnvelopeSigner:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("BLACKICE_SIGNING_KEY must contain at least 32 bytes")
        self._key = key

    @classmethod
    def from_env(cls) -> EnvelopeSigner:
        value = os.environ.get("BLACKICE_SIGNING_KEY", "")
        if not value:
            raise SigningKeyUnavailable("BLACKICE_SIGNING_KEY is not configured")
        return cls(value.encode("utf-8"))

    def sign(self, envelope: dict[str, Any]) -> str:
        return hmac.new(self._key, canonical_json(envelope), hashlib.sha256).hexdigest()

    def verify(self, envelope: dict[str, Any], signature: str) -> bool:
        expected = self.sign(envelope)
        return hmac.compare_digest(expected, signature)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
