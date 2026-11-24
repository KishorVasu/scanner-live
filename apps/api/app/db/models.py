"""Phase 1 tables: access, control and audit. Registry, scanning and intelligence tables arrive in later phases."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    FetchedValue,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, uuid.UUID: UUID(as_uuid=True), datetime: DateTime(timezone=True)}


class Timestamps:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # Maintained by the set_updated_at trigger; the ORM must re-read it.
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), server_onupdate=FetchedValue())


def pg_enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e])


class PolicyTier(enum.StrEnum):
    allowed = "allowed"
    approval_required = "approval_required"
    forbidden = "forbidden"


class ApprovalStatus(enum.StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"
    executed = "executed"
    failed = "failed"


class AgentRunStatus(enum.StrEnum):
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    timed_out = "timed_out"


class ActorType(enum.StrEnum):
    user = "user"
    agent = "agent"
    system = "system"


class SessionScope(enum.StrEnum):
    full = "full"
    totp_setup = "totp_setup"


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class User(Timestamps, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(320), unique=True)  # stored lower-case
    password_hash: Mapped[str] = mapped_column(Text)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_confirmed_at: Mapped[datetime | None]
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    last_login_at: Mapped[datetime | None]
    roles: Mapped[list["Role"]] = relationship(secondary=user_roles, lazy="selectin")


class Role(Timestamps, Base):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(32), unique=True)
    permissions: Mapped[list["Permission"]] = relationship(secondary=role_permissions, lazy="selectin")


class Permission(Timestamps, Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("resource", "action"),)
    resource: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))

    @property
    def key(self) -> str:
        return f"{self.resource}:{self.action}"


class UserSession(Timestamps, Base):
    __tablename__ = "user_sessions"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scope: Mapped[SessionScope] = mapped_column(pg_enum(SessionScope, "session_scope"))
    expires_at: Mapped[datetime]
    absolute_expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))


class Policy(Timestamps, Base):
    __tablename__ = "policies"
    action: Mapped[str] = mapped_column(String(128), unique=True)
    tier: Mapped[PolicyTier] = mapped_column(pg_enum(PolicyTier, "policy_tier"))
    conditions: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    description: Mapped[str] = mapped_column(Text, server_default="")
    active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class Approval(Timestamps, Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint("approver_id IS NULL OR approver_id <> requested_by", name="ck_approvals_no_self_approval"),
    )
    action: Mapped[str] = mapped_column(String(128))
    scope: Mapped[dict[str, Any]]
    scope_hash: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text)
    risks: Mapped[str] = mapped_column(Text, server_default="")
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    requested_by_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="RESTRICT"))
    status: Mapped[ApprovalStatus] = mapped_column(pg_enum(ApprovalStatus, "approval_status"))
    approver_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    decided_at: Mapped[datetime | None]
    expires_at: Mapped[datetime]
    executed_at: Mapped[datetime | None]
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class AgentRun(Timestamps, Base):
    __tablename__ = "agent_runs"
    agent_name: Mapped[str] = mapped_column(String(64), index=True)
    input_hash: Mapped[str] = mapped_column(String(64))
    input: Mapped[dict[str, Any]]
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    model: Mapped[str | None] = mapped_column(String(64))
    tokens_in: Mapped[int] = mapped_column(Integer, server_default="0")
    tokens_out: Mapped[int] = mapped_column(Integer, server_default="0")
    tool_calls: Mapped[int] = mapped_column(Integer, server_default="0")
    status: Mapped[AgentRunStatus] = mapped_column(pg_enum(AgentRunStatus, "agent_run_status"))
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]


class AuditLog(Base):
    """Append-only. The app role has INSERT/SELECT only and a trigger rejects UPDATE/DELETE/TRUNCATE."""

    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    actor_type: Mapped[ActorType] = mapped_column(pg_enum(ActorType, "actor_type"))
    actor_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(320))
    outcome: Mapped[str] = mapped_column(String(32))
    ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
