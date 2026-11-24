"""One adapter per scanner: which exit codes mean "ran fine" and how to parse its JSON report.

Formats follow each tool's documented JSON output (OSV-Scanner v2, npm audit v7+ auditReportVersion 2, pip-audit
`-f json`, Gitleaks `--report-format json`, Semgrep `--json`, Trivy `--format json` SchemaVersion 2). Test fixtures
are synthetic; verify against real output when the pinned images exist.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass

from app.core.redaction import get_redactor
from app.scanners.base import (
    MAX_REPORT_BYTES,
    ParseResult,
    RawFinding,
    ReportError,
    rel_path,
    severity_from_cvss,
    severity_from_word,
)


def _load(report: bytes):
    if report is None or not report.strip():
        raise ReportError("empty report")
    if len(report) > MAX_REPORT_BYTES:
        raise ReportError("report too large")
    try:
        return json.loads(report)
    except ValueError as e:
        raise ReportError(f"invalid JSON: {e.msg}") from None


def _conf(known: bool, default: str = "high") -> str:
    return default if known else "needs_verification"


# ---------- OSV-Scanner v2 ----------

def parse_osv(report: bytes) -> ParseResult:
    data = _load(report)
    findings, paths = [], []
    for result in data.get("results") or []:
        source = rel_path((result.get("source") or {}).get("path"))
        if source:
            paths.append(source)
        for pkg in result.get("packages") or []:
            meta = pkg.get("package") or {}
            group_sev = {i: g.get("max_severity") for g in pkg.get("groups") or [] for i in g.get("ids") or []}
            for v in pkg.get("vulnerabilities") or []:
                vid = str(v.get("id"))
                sev, known = severity_from_cvss(group_sev.get(vid)) if group_sev.get(vid) else \
                    severity_from_word((v.get("database_specific") or {}).get("severity"))
                findings.append(RawFinding(
                    rule_id=vid, category="dependency", title=str(v.get("summary") or vid)[:500],
                    severity=sev, confidence=_conf(known), file_path=source, package=meta.get("name"),
                    package_version=meta.get("version"), advisory_ids=[vid, *[str(a) for a in v.get("aliases") or []]],
                    evidence=f"{meta.get('ecosystem')} {meta.get('name')}@{meta.get('version')} in {source}: {vid}"))
    return ParseResult(findings, {"all": False, "paths": paths}, {"findings": len(findings), "sources": len(paths)})


# ---------- npm audit (lockfile only) ----------

def parse_npm_audit(report: bytes, lockfile: str = "package-lock.json") -> ParseResult:
    data = _load(report)
    if data.get("auditReportVersion") != 2:
        raise ReportError("unsupported npm audit report version")
    findings = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        for via in v.get("via") or []:
            if not isinstance(via, dict):
                continue  # a string means "vulnerable through another package"; that package has its own entry
            url = str(via.get("url") or "")
            adv = url.rsplit("/", 1)[-1] if "/advisories/" in url else str(via.get("source"))
            sev, known = severity_from_word(via.get("severity"))
            findings.append(RawFinding(
                rule_id=adv, category="dependency", title=str(via.get("title") or adv)[:500], severity=sev,
                confidence=_conf(known), file_path=lockfile, package=name, package_version=None,
                advisory_ids=[adv], evidence=f"npm {name} {via.get('range', '')} ({'direct' if v.get('isDirect') else 'transitive'}): {adv}"))
    return ParseResult(findings, {"all": False, "paths": [lockfile]}, {"findings": len(findings)})


# ---------- pip-audit ----------

def parse_pip_audit(report: bytes, requirements: str = "requirements.txt") -> ParseResult:
    data = _load(report)
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        raise ReportError("unexpected pip-audit report shape")
    findings = []
    for d in deps:
        if d.get("skip_reason"):
            continue
        for v in d.get("vulns") or []:
            vid = str(v.get("id"))
            findings.append(RawFinding(
                rule_id=vid, category="dependency", title=str(v.get("description") or vid)[:500],
                severity="medium", confidence="needs_verification",  # pip-audit reports no severity; Phase 4 enriches
                file_path=requirements, package=d.get("name"), package_version=d.get("version"),
                advisory_ids=[vid, *[str(a) for a in v.get("aliases") or []]],
                evidence=f"PyPI {d.get('name')}@{d.get('version')}: {vid}; fixed in {', '.join(v.get('fix_versions') or []) or 'n/a'}"))
    skipped = [d.get("name") for d in deps if d.get("skip_reason")]
    return ParseResult(findings, {"all": False, "paths": [requirements]},
                       {"findings": len(findings), "skipped_packages": len(skipped),
                        "partial": bool(skipped)})


# ---------- Gitleaks ----------

def parse_gitleaks(report: bytes) -> ParseResult:
    data = _load(report)
    if not isinstance(data, list):
        raise ReportError("unexpected gitleaks report shape")
    r = get_redactor()
    findings = []
    for leak in data:
        secret = str(leak.get("Secret") or leak.get("Match") or "")
        path = rel_path(leak.get("File"))
        rule = str(leak.get("RuleID") or "unknown")
        findings.append(RawFinding(
            rule_id=rule, category="secret", title=str(leak.get("Description") or rule)[:500], severity="high",
            confidence="high", file_path=path, line=leak.get("StartLine"),
            commit_sha=(str(leak.get("Commit"))[:64] or None) if leak.get("Commit") else None,
            match_hash=r.match_hash(secret) if secret else None,
            # Rule R4: never the value. Rule, location, commit and a salted hash only.
            evidence=f"{rule} at {path}:{leak.get('StartLine')} commit {leak.get('Commit') or 'working tree'}"))
    return ParseResult(findings, {"all": True, "paths": []}, {"findings": len(findings)})


# ---------- Semgrep ----------

def parse_semgrep(report: bytes) -> ParseResult:
    data = _load(report)
    r = get_redactor()
    findings = []
    for res in data.get("results") or []:
        extra = res.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev, known = severity_from_word(extra.get("severity"))
        conf = str(meta.get("confidence") or "").lower()
        findings.append(RawFinding(
            rule_id=str(res.get("check_id")), category="code", title=str(extra.get("message") or res.get("check_id"))[:500],
            severity=sev, confidence=conf if conf in ("high", "medium", "low") and known else _conf(known, "medium"),
            file_path=rel_path(res.get("path")), line=(res.get("start") or {}).get("line"),
            snippet=extra.get("lines"),
            evidence=r.redact(f"{res.get('check_id')} at {rel_path(res.get('path'))}:{(res.get('start') or {}).get('line')}: "
                              f"{str(extra.get('lines') or '')[:500]}")))
    scanned = (data.get("paths") or {}).get("scanned")
    coverage = {"all": scanned is None, "paths": [rel_path(p) for p in scanned or []]}
    errors = data.get("errors") or []
    return ParseResult(findings, coverage, {"findings": len(findings), "errors": len(errors), "partial": bool(errors)})


# ---------- Trivy ----------

def parse_trivy(report: bytes) -> ParseResult:
    data = _load(report)
    if data.get("SchemaVersion") != 2:
        raise ReportError("unsupported Trivy schema version")
    findings, paths = [], []
    for res in data.get("Results") or []:
        target = rel_path(res.get("Target"))
        paths.append(target)
        for v in res.get("Vulnerabilities") or []:
            sev, known = severity_from_word(v.get("Severity"))
            vid = str(v.get("VulnerabilityID"))
            findings.append(RawFinding(
                rule_id=vid, category="dependency", title=str(v.get("Title") or vid)[:500], severity=sev,
                confidence=_conf(known), file_path=target, package=v.get("PkgName"),
                package_version=v.get("InstalledVersion"), advisory_ids=[vid],
                evidence=f"{res.get('Type')} {v.get('PkgName')}@{v.get('InstalledVersion')} in {target}: {vid}; "
                         f"fixed in {v.get('FixedVersion') or 'n/a'}"))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            sev, known = severity_from_word(m.get("Severity"))
            findings.append(RawFinding(
                rule_id=str(m.get("ID")), category="misconfiguration", title=str(m.get("Title") or m.get("ID"))[:500],
                severity=sev, confidence=_conf(known), file_path=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine"),
                evidence=f"{m.get('ID')} in {target}: {str(m.get('Message') or '')[:300]}"))
    return ParseResult(findings, {"all": False, "paths": paths}, {"findings": len(findings)})


@dataclass(frozen=True)
class Adapter:
    scanner: str
    ok_exit_codes: frozenset[int]  # exit codes meaning "ran to completion" (with or without findings)
    parse: Callable[[bytes], ParseResult]


ADAPTERS: dict[str, Adapter] = {
    "osv_scanner": Adapter("osv_scanner", frozenset({0, 1}), parse_osv),
    "npm_audit": Adapter("npm_audit", frozenset({0, 1}), parse_npm_audit),
    "pip_audit": Adapter("pip_audit", frozenset({0, 1}), parse_pip_audit),
    "gitleaks": Adapter("gitleaks", frozenset({0, 1}), parse_gitleaks),
    "semgrep": Adapter("semgrep", frozenset({0, 1}), parse_semgrep),
    "trivy": Adapter("trivy", frozenset({0}), parse_trivy),
}
