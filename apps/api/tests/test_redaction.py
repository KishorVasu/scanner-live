"""T-R4 (unit part): known fake secrets never survive the redactor. Fake values are built at runtime."""

import io
import logging

from app.core.logging import JsonFormatter
from app.core.redaction import Redactor

R = Redactor(b"s" * 32)

FAKES = {
    "github-token": "ghp_" + "Ab1" * 12,
    "aws-access-key-id": "AKIA" + "Q7XZ" * 4,
    "anthropic-api-key": "sk-ant-" + "api03-" + "x9Y" * 10,
    "slack-token": "xoxb-" + "1234567890-abcdefghij",
    "stripe-key": "sk_live_" + "Zz9" * 8,
    "jwt": "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".c2lnbmF0dXJlc2lnbmF0dXJl",
}


def test_each_rule_redacts():
    for rule, value in FAKES.items():
        out = R.redact(f"before {value} after")
        assert value not in out, rule
        assert "[REDACTED:" in out and "before" in out and "after" in out


def test_private_key_block():
    head, tail = "PRIVATE " + "KEY-----", "-----END OPENSSH PRIVATE " + "KEY-----"  # split so repo scanners stay quiet
    key = "-----BEGIN OPENSSH " + head + "\n" + "b3BlbnNzaC1rZXktdjEAAAA\n" * 3 + tail
    assert "b3BlbnNzaC1rZXktdjEAAAA" not in R.redact(f"x\n{key}\ny")


def test_generic_assignment_and_url_credentials():
    out = R.redact('DB_PASSWORD="hunter2-very-secret" url=postgres://admin:pa55word@db:5432/x')
    assert "hunter2-very-secret" not in out
    assert "pa55word" not in out
    assert "DB_PASSWORD" in out and "@db:5432" in out


def test_high_entropy_but_not_hex_evidence():
    random_b64 = "Qm9Hk2Lr8XcVt5Zp1WnYs7Ja3Ue6Df0G"
    sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
    out = R.redact(f"blob {random_b64} commit {sha}")
    assert random_b64 not in out
    assert sha in out  # commit SHAs and digests are evidence, not secrets


def test_marker_is_stable_and_not_re_redacted():
    once = R.redact(f"token: {FAKES['github-token']}")
    assert R.redact(once) == once
    assert R.match_hash("abc") == R.match_hash("abc") != Redactor(b"t" * 32).match_hash("abc")


def test_redact_obj_nested():
    obj = {"a": [FAKES["aws-access-key-id"], {"b": FAKES["github-token"]}], "n": 3}
    out = R.redact_obj(obj)
    flat = str(out)
    assert FAKES["aws-access-key-id"] not in flat and FAKES["github-token"] not in flat
    assert out["n"] == 3


def test_review_gaps_are_closed():
    hex_pw = "9f" * 32
    cases = {
        "Authorization: Bearer abcdefghijklmnop1234": "abcdefghijklmnop1234",
        'secretKey: "abcdefgh123"': "abcdefgh123",
        "JWT_SECRET_KEY=abcdefgh123": "abcdefgh123",
        f"redis://:{hex_pw}@redis:6379/0": hex_pw,
        'password: "correct horse battery staple"': "horse battery staple",
    }
    for text, secret in cases.items():
        assert secret not in R.redact(text), text


def test_redact_obj_fails_closed_on_other_types():
    tok = FAKES["github-token"]
    out = R.redact_obj({"a": tok.encode(), "b": {tok}, "c": (1, None, True)})
    assert tok not in str(out)
    assert out["c"] == [1, None, True]


def test_evidence_kept():
    text = "author: dev@example.test commit 3d3c42e5aac5ba805825da76410c181273ba90b1 tokens_in=42"
    assert R.redact(text) == text


def test_log_formatter_redacts():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    log = logging.getLogger("t")
    log.addHandler(handler)
    log.warning("leaked %s", FAKES["github-token"])
    log.removeHandler(handler)
    assert FAKES["github-token"] not in stream.getvalue()
