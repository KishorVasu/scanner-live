"""PolicyEngine: deny by default, backed by the `policies` table (rule R2)."""

import enum
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Policy, PolicyTier

# Denied even if a policy row says otherwise. Mirrors the forbidden tier in docs/SECURITY_POLICIES.md §2.
FORBIDDEN_ACTIONS = frozenset({
    "edit_file", "write_file", "delete_file", "delete_branch", "git_push", "force_push", "upgrade_dependency",
    "deploy", "rotate_credential", "change_permission", "share_learning_note", "exec_shell", "run_project_script",
})


class Outcome(enum.StrEnum):
    allow = "allow"
    deny = "deny"
    needs_approval = "needs_approval"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str


async def decide(session: AsyncSession, action: str) -> Decision:
    if action in FORBIDDEN_ACTIONS:
        return Decision(Outcome.deny, "forbidden action")
    row = await session.scalar(select(Policy).where(Policy.action == action, Policy.active.is_(True)))
    if row is None:
        return Decision(Outcome.deny, "no policy (deny by default)")
    if row.conditions:
        # ponytail: condition evaluation lands with the first policy that needs it; until then fail closed.
        return Decision(Outcome.deny, "policy conditions not supported")
    if row.tier == PolicyTier.allowed:
        return Decision(Outcome.allow, "policy allows")
    if row.tier == PolicyTier.approval_required:
        return Decision(Outcome.needs_approval, "policy requires approval")
    return Decision(Outcome.deny, "policy forbids")
