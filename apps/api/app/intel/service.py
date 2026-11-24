"""Deterministic advisory ingestion and inventory matching (no LLM).

`ingest` asks OSV which advisories affect the exact versions in every repository's dependency inventory, stores those
advisories (vendor facts verbatim), flags CISA KEV entries, fills missing CVSS from NVD, and returns the
(advisory, repository) pairs whose impact must be (re)decided. `facts_for` gathers the evidence `rules.decide` needs.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.intel import AdvisorySource, SecurityAdvisory
from app.db.registry import DependencyInventory, Repository
from app.db.scanning import FindingStatus, SecurityFinding
from app.intel import sources
from app.intel.rules import Facts

# Ecosystems OSV can match. Others (CocoaPods, Apple, GitHubActions) are covered by scanners only.
OSV_ECOSYSTEMS = frozenset({"npm", "PyPI", "Packagist", "Pub", "Maven", "Go", "RubyGems", "NuGet", "crates.io",
                            "SwiftURL"})
NVD_LOOKUPS_PER_RUN = 20  # NVD without an API key allows ~5 requests / 30 s


@dataclass
class IngestResult:
    queried: int
    advisories: int
    pairs: list[tuple[uuid.UUID, uuid.UUID]]


async def _source(db: AsyncSession, name: str) -> AdvisorySource:
    src = await db.scalar(select(AdvisorySource).where(AdvisorySource.name == name))
    if src is None or not src.active:
        raise sources.SourceError(f"advisory source {name} missing or inactive")
    return src


async def ingest(db: AsyncSession) -> IngestResult:
    now = datetime.now(UTC)
    osv = await _source(db, "osv")
    rows = (await db.execute(
        select(DependencyInventory.ecosystem, DependencyInventory.package, DependencyInventory.version)
        .where(DependencyInventory.version.is_not(None), DependencyInventory.ecosystem.in_(OSV_ECOSYSTEMS))
        .distinct())).all()
    queries = [(e, p, v) for e, p, v in rows]
    async with sources.client() as c:
        matches = await sources.osv_matches(c, queries)
        wanted: dict[str, tuple[str, str]] = {}
        for (eco, pkg, _), ids in zip(queries, matches, strict=True):
            for vid in ids:
                wanted.setdefault(vid, (eco, pkg))
        existing = {a.external_id: a for a in await db.scalars(
            select(SecurityAdvisory).where(SecurityAdvisory.source_id == osv.id,
                                           SecurityAdvisory.external_id.in_(list(wanted))))}
        for vid, (eco, pkg) in wanted.items():
            fields = sources.normalize_osv(await sources.osv_vuln(c, vid), eco, pkg)
            adv = existing.get(vid)
            if adv is None:
                adv = SecurityAdvisory(source_id=osv.id, known_exploited=False, retrieved_at=now, **fields)
                db.add(adv)
                existing[vid] = adv
            elif adv.modified_at != fields["modified_at"]:
                # Vendor text changed: refresh facts and drop the AI reading of the old text.
                for k, v in fields.items():
                    setattr(adv, k, v)
                adv.ai_interpretation, adv.extra_conditions, adv.retrieved_at = None, None, now
        kev = await _source(db, "cisa_kev")
        kev_ids = await sources.kev_cves(c)
        for adv in existing.values():
            adv.known_exploited = bool(kev_ids & {adv.external_id, *adv.aliases})
        kev.last_polled_at = now
        nvd = await _source(db, "nvd")
        lookups = 0
        for adv in existing.values():
            cve = next((a for a in [adv.external_id, *adv.aliases] if a.startswith("CVE-")), None)
            if adv.severity is None and cve and lookups < NVD_LOOKUPS_PER_RUN:
                lookups += 1
                vector, score = await sources.nvd_cvss(c, cve)
                adv.cvss_vector = adv.cvss_vector or vector
                adv.severity = sources.severity_from_nvd(score)
        nvd.last_polled_at = now
    osv.last_polled_at = now
    await db.flush()
    pairs = await candidate_pairs(db, [a.id for a in existing.values()])
    await db.commit()
    return IngestResult(queried=len(queries), advisories=len(existing), pairs=pairs)


async def candidate_pairs(db: AsyncSession, advisory_ids: list[uuid.UUID]) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Every repository whose inventory names the advisory's package, at any version or only as a declared range."""
    if not advisory_ids:
        return []
    rows = await db.execute(
        select(SecurityAdvisory.id, DependencyInventory.repository_id)
        .join(DependencyInventory, (DependencyInventory.ecosystem == SecurityAdvisory.ecosystem)
              & (func.lower(DependencyInventory.package) == func.lower(SecurityAdvisory.package)))
        .where(SecurityAdvisory.id.in_(advisory_ids)).distinct())
    return [(a, r) for a, r in rows]


@dataclass(frozen=True)
class PairFacts:
    facts: Facts
    inventory_ids: list[str]
    finding_ids: list[str]
    references: list[str]
    llm_allowed: bool
    inventory: list[dict]


async def facts_for(db: AsyncSession, advisory_id: uuid.UUID, repository_id: uuid.UUID) -> PairFacts:
    from app.db.registry import Project, ProjectComponent

    adv = await db.get(SecurityAdvisory, advisory_id)
    repo = await db.get(Repository, repository_id)
    if adv is None or repo is None:
        raise LookupError("advisory or repository not found")
    project = await db.scalar(select(Project).join(ProjectComponent, ProjectComponent.project_id == Project.id)
                              .where(ProjectComponent.id == repo.component_id))
    inv = list(await db.scalars(select(DependencyInventory).where(
        DependencyInventory.repository_id == repo.id, DependencyInventory.ecosystem == adv.ecosystem,
        func.lower(DependencyInventory.package) == func.lower(adv.package or ""))))
    resolved = [r for r in inv if r.version]
    version_matched = False
    if resolved and adv.ecosystem in OSV_ECOSYSTEMS:
        async with sources.client() as c:
            hits = await sources.osv_matches(c, [(r.ecosystem, r.package, r.version) for r in resolved])
        version_matched = any(adv.external_id in ids for ids in hits)
    refs = [adv.external_id, *adv.aliases]
    findings = [f for f in await db.scalars(select(SecurityFinding).where(
        SecurityFinding.repository_id == repo.id, SecurityFinding.status == FindingStatus.open))
        if set(refs) & set(f.advisory_ids or [])]
    facts = Facts(
        inventory_complete=repo.inventory_complete,
        last_inventory_at=repo.last_inventory_at,
        version_matched=version_matched,
        spec_only=bool(inv) and not resolved,
        scanner_confirmed=bool(findings),
        has_extra_conditions=bool(adv.extra_conditions),
    )
    return PairFacts(
        facts=facts,
        inventory_ids=[str(r.id) for r in inv],
        finding_ids=[str(f.id) for f in findings],
        references=refs,
        llm_allowed=bool(project.llm_allowed) if project else False,
        inventory=[{"id": str(r.id), "package": r.package, "version": r.version, "version_spec": r.version_spec,
                    "direct": r.direct, "manifest_path": r.manifest_path} for r in inv],
    )
