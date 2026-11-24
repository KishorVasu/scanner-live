"""Deterministic impact rules (CLAUDE.md §9, AGENT_SPECIFICATIONS 5.7). Pure functions, no I/O.

`decide` turns the facts about one (advisory, repository) pair into the set of classifications the evidence permits.
When that set has one member the rule decides alone; when it has several (the advisory has extra conditions), the
Impact Analysis agent may pick one, and `record_impact` refuses anything outside the set. The LLM can never widen it.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.db.intel import ImpactClassification as C

INVENTORY_MAX_AGE = timedelta(days=7)


@dataclass(frozen=True)
class Facts:
    inventory_complete: bool | None  # None = never inventoried
    last_inventory_at: datetime | None
    version_matched: bool  # OSV says a resolved version in the inventory is affected
    spec_only: bool  # the package appears only as a declared range, no resolved version
    scanner_confirmed: bool  # an open finding from a successful scan cites this advisory
    has_extra_conditions: bool


@dataclass(frozen=True)
class Decision:
    allowed: frozenset[C]
    default: C
    rule: str

    @property
    def needs_llm(self) -> bool:
        return len(self.allowed) > 1


def decide(f: Facts, now: datetime | None = None) -> Decision:
    now = now or datetime.now(UTC)
    if f.inventory_complete is None or f.last_inventory_at is None:
        return Decision(frozenset({C.not_scanned}), C.not_scanned, "never_inventoried")
    stale = now - f.last_inventory_at > INVENTORY_MAX_AGE
    if f.version_matched:
        if not f.has_extra_conditions:
            return Decision(frozenset({C.confirmed_affected}), C.confirmed_affected, "version_match_no_conditions")
        # Never confirmed on name/version alone when extra conditions exist, unless a scanner already confirmed it.
        allowed = {C.potentially_affected, C.needs_verification}
        if f.scanner_confirmed:
            allowed.add(C.confirmed_affected)
        return Decision(frozenset(allowed), C.potentially_affected, "version_match_with_conditions")
    if f.spec_only:
        return Decision(frozenset({C.needs_verification}), C.needs_verification, "declared_range_only")
    # Package present, resolved version not affected. "Not affected" only on a complete, fresh inventory.
    if f.inventory_complete is False or stale:
        return Decision(frozenset({C.needs_verification}), C.needs_verification,
                        "inventory_partial" if f.inventory_complete is False else "inventory_stale")
    return Decision(frozenset({C.not_affected_on_evidence}), C.not_affected_on_evidence, "version_not_affected")


class RuleViolation(ValueError):
    pass


def check(decision: Decision, classification: C) -> None:
    if classification not in decision.allowed:
        raise RuleViolation(f"{classification.value} is not permitted by rule {decision.rule} "
                            f"(allowed: {sorted(c.value for c in decision.allowed)})")
