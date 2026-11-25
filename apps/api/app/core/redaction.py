"""Secret redactor. Runs before every LLM call, log write, evidence write and report render (rule R4).

Over-redaction is acceptable; under-redaction is a bug.
"""

import hashlib
import hmac
import math
import re
from collections import Counter
from functools import lru_cache
from typing import Any

# Key names that mark a secret value: secret_key, secretKey, JWT_SECRET_KEY, db_password, x-api-key, ...
_KEY = (
    r"(?i)\b[\w\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
    r"[\w\-]*"
)

_KEY_NAME = re.compile(_KEY)

# Rules with a named group "v" redact only that group; others redact the whole match.
RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("url-credentials", re.compile(r"://(?P<v>[^/\s:@]*:[^/\s@]+)@")),  # empty user allowed (redis://:pw@)
    ("auth-header", re.compile(r"(?i)\b(?:bearer|basic|token)\s+(?P<v>[A-Za-z0-9._~+/=\-]{8,})")),
    # Quoted values are redacted to the closing quote, so passphrases with spaces are covered.
    ("generic-secret", re.compile(_KEY + r"[\"']?\s*[:=]\s*(?P<q>[\"'])(?P<v>[^\"'\n]{4,})(?P=q)")),
    ("generic-secret", re.compile(_KEY + r"[\"']?\s*[:=]\s*(?P<v>[^\s\"',;\[\]]{6,})")),
]

_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
_HEX = re.compile(r"[0-9a-fA-F\-]+")
ENTROPY_THRESHOLD = 4.0


_MARKER = re.compile(r"(\[REDACTED:[a-z0-9\-]+:[0-9a-f]{8}\])")


def _outside_markers(text: str, fn) -> str:
    """Apply fn only to text between existing markers, so a marker is never redacted again."""
    parts = _MARKER.split(text)
    return "".join(p if i % 2 else fn(p) for i, p in enumerate(parts))


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


class Redactor:
    def __init__(self, salt: bytes) -> None:
        self._salt = salt

    def match_hash(self, value: str) -> str:
        """Salted hash stored instead of a secret value."""
        return hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()

    def _marker(self, rule: str, value: str) -> str:
        return f"[REDACTED:{rule}:{self.match_hash(value)[:8]}]"

    def _value(self, key: str, v: Any) -> Any:
        # {"password": "hunter2xyz"}: the key-name rules need "key: value" in one string, so check the key here.
        if isinstance(v, str) and len(v) >= 4 and _KEY_NAME.fullmatch(key) and not v.startswith("[REDACTED:"):
            return self._marker("generic-secret", v)
        return self.redact_obj(v)

    def redact(self, text: str) -> str:
        for name, pattern in RULES:
            text = _outside_markers(text, lambda seg, p=pattern, n=name: p.sub(lambda m: self._replace(n, m), seg))
        return _outside_markers(text, lambda seg: _CANDIDATE.sub(self._entropy_replace, seg))

    def _replace(self, rule: str, m: re.Match[str]) -> str:
        if "v" not in m.re.groupindex:
            return self._marker(rule, m.group(0))
        whole, base = m.group(0), m.start()
        start, end = m.span("v")
        return whole[: start - base] + self._marker(rule, m.group("v")) + whole[end - base :]

    def _entropy_replace(self, m: re.Match[str]) -> str:
        tok = m.group(0)
        # Hex strings (commit SHAs, digests, UUIDs) are evidence, not secrets.
        if _HEX.fullmatch(tok):
            return tok
        mixed = any(c.isupper() for c in tok) and any(c.islower() for c in tok) and any(c.isdigit() for c in tok)
        if mixed and _entropy(tok) >= ENTROPY_THRESHOLD:
            return self._marker("high-entropy", tok)
        return tok

    def redact_obj(self, obj: Any) -> Any:
        """Redact a JSON-like value. Unknown types fail closed: they become redacted strings."""
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, (bytes, bytearray)):
            return self.redact(bytes(obj).decode("utf-8", errors="replace"))
        if isinstance(obj, dict):
            return {self.redact(str(k)): self._value(str(k), v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set, frozenset)):
            return [self.redact_obj(v) for v in obj]
        if hasattr(obj, "model_dump"):
            return self.redact_obj(obj.model_dump(mode="json"))
        return self.redact(str(obj))


@lru_cache
def get_redactor() -> Redactor:
    from app.core.config import redaction_salt

    return Redactor(redaction_salt())
