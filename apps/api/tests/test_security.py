import time

import pyotp
import pytest
from cryptography.exceptions import InvalidTag

from app.core.security import Cipher, csrf_for, hash_password, verify_password, verify_totp


def test_argon2id():
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery")
    assert not verify_password(h, "wrong")
    assert not verify_password(None, "anything")
    assert not verify_password("not-a-hash", "x")


def test_totp_replay_and_window():
    secret = pyotp.random_base32()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    step = verify_totp(secret, code, None, now)
    assert step is not None
    assert verify_totp(secret, code, step, now) is None  # replay rejected
    assert verify_totp(secret, pyotp.TOTP(secret).at(now - 300), None, now) is None  # outside window
    assert verify_totp(secret, "12a456", None, now) is None


def test_cipher_binds_context():
    c = Cipher(b"k" * 32)
    blob = c.encrypt(b"secret", "users.totp:1")
    assert c.decrypt(blob, "users.totp:1") == b"secret"
    with pytest.raises(InvalidTag):
        c.decrypt(blob, "users.totp:2")
    with pytest.raises(ValueError):
        Cipher(b"short")


def test_csrf_derivation():
    assert csrf_for("a") == csrf_for("a") != csrf_for("b")
