"""Normalised scanner output. Scanner reports are untrusted input: parsed strictly, size-capped, never executed."""

import hashlib
import re
from dataclasses import dataclass, field

MAX_REPORT_BYTES = 64 * 1024 * 1024
MOUNT_PREFIX = "/src/"  # scan-runner mounts the repository here (read-only)


class ReportError(Exception):
    """The report is missing, too large or unparseable: the job fails and nothing is resolved."""


@dataclass
class RawFinding:
    rule_id: str
    category: str  # dependency | code | secret | misconfiguration | integrity
    title: str
    severity: str  # critical | high | medium | low | informational
    confidence: str  # confirmed | high | medium | low | needs_verification
    evidence: str  # already redacted by the adapter where secrets are involved
    file_path: str | None = None
    line: int | None = None
    package: str | None = None
    package_version: str | None = None
    advisory_ids: list[str] = field(default_factory=list)
    match_hash: str | None = None
    commit_sha: str | None = None
    snippet: str | None = None  # code findings: used for a line-shift-stable fingerprint, not stored


@dataclass
class ParseResult:
    findings: list[RawFinding]
    coverage: dict  # {"all": bool, "paths": [...]}
    summary: dict


def rel_path(path: str | None) -> str | None:
    if not path:
        return None
    path = path.replace("\\", "/")
    return path[len(MOUNT_PREFIX):] if path.startswith(MOUNT_PREFIX) else path.lstrip("/")


def _norm_snippet(s: str | None) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def fingerprint(repository_id: str, scanner: str, f: RawFinding) -> str:
    """Stable identity of a finding (docs/DATABASE_SCHEMA.md §5). The scanner is part of every fingerprint so that
    "resolved" always means the same scanner stopped reporting it."""
    if f.category == "dependency":
        key = [f.package or "", (f.advisory_ids or [f.rule_id])[0], f.file_path or ""]
    elif f.category == "secret":
        key = [f.rule_id, f.file_path or "", f.match_hash or ""]
    elif f.category == "code":
        key = [f.rule_id, f.file_path or "", hashlib.sha256(_norm_snippet(f.snippet).encode()).hexdigest()]
    else:
        key = [f.rule_id, f.file_path or "", str(f.line or "")]
    return hashlib.sha256("\x1f".join([repository_id, scanner, f.category, *key]).encode()).hexdigest()


SEVERITY_WORDS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low",
                  "info": "informational", "informational": "informational", "error": "high", "warning": "medium",
                  "negligible": "low"}


def severity_from_word(word: str | None) -> tuple[str, bool]:
    """Returns (severity, known). Unknown severities become medium + needs_verification, never informational."""
    sev = SEVERITY_WORDS.get((word or "").strip().lower())
    return (sev, True) if sev else ("medium", False)


def severity_from_cvss(score: str | float | None) -> tuple[str, bool]:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium", False
    if s >= 9.0:
        return "critical", True
    if s >= 7.0:
        return "high", True
    if s >= 4.0:
        return "medium", True
    if s > 0:
        return "low", True
    return "informational", True
