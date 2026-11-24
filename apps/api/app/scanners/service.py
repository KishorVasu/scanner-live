"""Scan jobs and the finding lifecycle (rules R11 and docs/DATABASE_SCHEMA.md §5).

- A job is deduplicated on repository + scanner + inventory hash while queued or running.
- A scheduled job whose inventory hash is unchanged since the last successful run is recorded as skipped_unchanged.
- A failed or partial job never resolves anything. Only a succeeded run of the same scanner whose coverage includes
  the finding's file, and which no longer reports it, resolves a finding.
- A finding seen again after resolution is reopened. Every detection adds an evidence row; nothing is discarded.
"""

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redaction import get_redactor
from app.db.registry import ProjectComponent, Repository, Severity
from app.db.scanning import (
    Confidence,
    FindingEvidence,
    FindingStatus,
    ScanJob,
    ScanResult,
    ScanStatus,
    ScanTrigger,
    Scanner,
    SecurityFinding,
)
from app.scanners.adapters import ADAPTERS
from app.scanners.base import ParseResult, RawFinding, ReportError, fingerprint

DEPENDENCY_SCANNERS = {Scanner.osv_scanner, Scanner.npm_audit, Scanner.pip_audit}
OPEN_STATES = (FindingStatus.open, FindingStatus.in_progress)


def _now() -> datetime:
    return datetime.now(UTC)


def inventory_hash_for(repo: Repository, scanner: Scanner) -> str:
    h = repo.manifest_hash if scanner in DEPENDENCY_SCANNERS else (repo.tree_hash or repo.manifest_hash)
    return h or "uninventoried"


async def create_job(db: AsyncSession, repo: Repository, scanner: Scanner, trigger: ScanTrigger,
                     requested_by_run_id: uuid.UUID | None = None) -> tuple[ScanJob, bool]:
    """Returns (job, created). An identical queued/running job is returned instead of a new one."""
    inv = inventory_hash_for(repo, scanner)
    if trigger == ScanTrigger.schedule:
        last_ok = await db.scalar(select(ScanJob).where(
            ScanJob.repository_id == repo.id, ScanJob.scanner == scanner, ScanJob.status == ScanStatus.succeeded)
            .order_by(ScanJob.finished_at.desc()).limit(1))
        if last_ok is not None and last_ok.inventory_hash == inv and inv != "uninventoried":
            job = ScanJob(repository_id=repo.id, scanner=scanner, trigger=trigger, inventory_hash=inv,
                          status=ScanStatus.skipped_unchanged, finished_at=_now())
            db.add(job)
            await db.flush()
            return job, True
    new_id = await db.scalar(
        pg_insert(ScanJob)
        .values(repository_id=repo.id, scanner=scanner, trigger=trigger, inventory_hash=inv,
                status=ScanStatus.queued, requested_by_run_id=requested_by_run_id)
        .on_conflict_do_nothing(index_elements=["repository_id", "scanner", "inventory_hash"],
                                index_where=text("status IN ('queued', 'running')"))
        .returning(ScanJob.id)
    )
    if new_id is not None:
        return await db.get(ScanJob, new_id), True
    existing = await db.scalar(select(ScanJob).where(
        ScanJob.repository_id == repo.id, ScanJob.scanner == scanner, ScanJob.inventory_hash == inv,
        ScanJob.status.in_([ScanStatus.queued, ScanStatus.running])))
    return existing, False


async def fail_job(db: AsyncSession, job: ScanJob, reason: str) -> ScanJob:
    """Record a failure. Findings are left exactly as they were (rule R11)."""
    job.status, job.error, job.finished_at = ScanStatus.failed, get_redactor().redact(reason)[:2000], _now()
    return job


def _store_report(job: ScanJob, report: bytes | None) -> tuple[str | None, str | None]:
    if not report:
        return None, None
    redacted = get_redactor().redact(report.decode("utf-8", errors="replace")).encode()
    digest = hashlib.sha256(redacted).hexdigest()
    report_dir = get_settings().report_dir
    if report_dir is None:
        return None, digest
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{job.id}.json"
    path.write_bytes(redacted)  # redacted copy only: Gitleaks and others may echo secret values
    return str(path), digest


async def complete_job(db: AsyncSession, job: ScanJob, *, exit_code: int | None, report: bytes | None,
                       error: str | None = None) -> ScanJob:
    adapter = ADAPTERS.get(job.scanner.value)
    if adapter is None:
        return await fail_job(db, job, f"no adapter for {job.scanner.value}")
    if error:
        return await fail_job(db, job, error)
    if exit_code not in adapter.ok_exit_codes:
        return await fail_job(db, job, f"scanner exited with {exit_code}")
    try:
        parsed = adapter.parse(report)
    except ReportError as e:
        return await fail_job(db, job, f"report rejected: {e}")
    path, digest = _store_report(job, report)
    return await ingest(db, job, parsed, raw_report_path=path, raw_report_sha256=digest)


async def ingest(db: AsyncSession, job: ScanJob, parsed: ParseResult, raw_report_path: str | None = None,
                 raw_report_sha256: str | None = None) -> ScanJob:
    repo = await db.get(Repository, job.repository_id)
    component = await db.get(ProjectComponent, repo.component_id)
    now = _now()
    partial = bool(parsed.summary.get("partial"))
    db.add(ScanResult(scan_job_id=job.id, raw_report_path=raw_report_path, raw_report_sha256=raw_report_sha256,
                      summary=parsed.summary, coverage=parsed.coverage))
    seen: set[str] = set()
    for raw in parsed.findings:
        fp = fingerprint(str(repo.id), job.scanner.value, raw)
        if fp in seen:
            continue
        seen.add(fp)
        finding = await db.scalar(select(SecurityFinding).where(SecurityFinding.fingerprint == fp).with_for_update())
        if finding is None:
            finding = SecurityFinding(
                fingerprint=fp, project_id=component.project_id, repository_id=repo.id, scanner=job.scanner,
                rule_id=raw.rule_id[:255], category=raw.category, title=raw.title[:500],
                severity=Severity(raw.severity), confidence=Confidence(raw.confidence), status=FindingStatus.open,
                file_path=raw.file_path, line=raw.line, package=raw.package, package_version=raw.package_version,
                advisory_ids=raw.advisory_ids or None, first_seen_at=now, last_seen_at=now)
            db.add(finding)
            await db.flush()
        else:
            finding.last_seen_at, finding.line = now, raw.line
            finding.severity = Severity(raw.severity)
            if finding.status == FindingStatus.resolved:  # it came back
                finding.status, finding.resolved_at, finding.resolved_by_scan_job_id = FindingStatus.open, None, None
        db.add(FindingEvidence(finding_id=finding.id, scan_job_id=job.id, evidence_redacted=get_redactor().redact(raw.evidence),
                               match_hash=raw.match_hash, commit_sha=raw.commit_sha, captured_at=now))

    if not partial:
        await _resolve_missing(db, job, repo.id, seen, parsed.coverage, now)
    job.status, job.finished_at = (ScanStatus.partial if partial else ScanStatus.succeeded), now
    return job


def _covered(path: str | None, coverage: dict) -> bool:
    return bool(coverage.get("all")) or (path is not None and path in set(coverage.get("paths") or []))


async def _resolve_missing(db, job: ScanJob, repo_id, seen: set[str], coverage: dict, now) -> None:
    for f in await db.scalars(select(SecurityFinding).where(
            SecurityFinding.repository_id == repo_id, SecurityFinding.scanner == job.scanner,
            SecurityFinding.status.in_(OPEN_STATES)).with_for_update()):
        if f.fingerprint not in seen and _covered(f.file_path, coverage):
            f.status, f.resolved_at, f.resolved_by_scan_job_id = FindingStatus.resolved, now, job.id


def to_raw(rule_id: str, category: str, title: str, severity: str, evidence: str, **kw) -> RawFinding:
    return RawFinding(rule_id=rule_id, category=category, title=title, severity=severity,
                      confidence=kw.pop("confidence", "high"), evidence=evidence, **kw)
