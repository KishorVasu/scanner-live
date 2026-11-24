"""Password hashing, TOTP, token handling and column encryption."""

import hashlib
import hmac
import os
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ph = PasswordHasher()  # argon2id with library defaults
_DUMMY_HASH = _ph.hash("timing-equaliser-not-a-password")
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-ish time: an unknown user still costs one argon2 verify."""
    try:
        return _ph.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Security Platform")


def verify_totp(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. Steps <= last_step are rejected (no replay)."""
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // totp.interval)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_for(session_token: str) -> str:
    """CSRF value derived from the HttpOnly session token (double-submit, no storage)."""
    return hmac.new(session_token.encode(), b"csrf", hashlib.sha256).hexdigest()


class Cipher:
    """AES-256-GCM for `_enc` columns; the context string is bound as associated data.

    ponytail: one master key. Add per-record data keys and key IDs when key rotation is needed.
    """

    VERSION = b"v1"

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        nonce = os.urandom(12)
        return self.VERSION + nonce + self._aes.encrypt(nonce, plaintext, context.encode())

    def decrypt(self, blob: bytes, context: str) -> bytes:
        if blob[:2] != self.VERSION:
            raise ValueError("unknown ciphertext version")
        return self._aes.decrypt(blob[2:14], blob[14:], context.encode())


def get_cipher() -> Cipher:
    from app.core.config import master_key

    return Cipher(master_key())
