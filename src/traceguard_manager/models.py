"""Database schema."""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

JsonType = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend.

    SQLite drops the offset when it stores a datetime, so values are normalised
    to UTC on the way in and tagged as UTC on the way out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not accepted; use datetime.now(UTC)")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> uuid.UUID:
    """Time-ordered identifiers: index friendly and not guessable in sequence."""
    return uuid.uuid7()


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JsonType, list[str]: JsonType}


class Role(enum.StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AlertKind(enum.StrEnum):
    DETECTION = "detection"
    BLOCKED = "blocked"
    WOULD_BLOCK = "would_block"
    RESPONSE = "response"
    AGENT_ERROR = "agent_error"


class AlertStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=Role.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(default=True)
    failed_logins: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    password_changed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """A signed-in browser. Only a hash of the session token is stored."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    client_ip: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship(back_populates="sessions")


class Agent(Base):
    """A TraceGuard host. Identity comes from its token, never from the payload."""

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_prefix: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    token_rotated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    hostname: Mapped[str | None] = mapped_column(String(255))
    last_seen_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    healthy: Mapped[bool | None] = mapped_column()
    policy_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    policy_mode: Mapped[str | None] = mapped_column(String(32))
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)
    ringbuf_degraded: Mapped[bool | None] = mapped_column()
    ringbuf_dropped_events: Mapped[int | None] = mapped_column(BigInteger)
    detection_rules: Mapped[int | None] = mapped_column()
    unavailable_hooks: Mapped[list[str]] = mapped_column(default=list)
    events_received: Mapped[int] = mapped_column(BigInteger, default=0)

    alerts: Mapped[list[Alert]] = relationship(back_populates="agent", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        # Agents replay spooled batches after an outage; the fingerprint makes delivery idempotent.
        UniqueConstraint("agent_id", "fingerprint", name="uq_alerts_agent_fingerprint"),
        Index("ix_alerts_status_severity", "status", "severity_rank"),
        Index("ix_alerts_occurred_at", "occurred_at"),
        Index("ix_alerts_hour_bucket", "hour_bucket"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column()
    title: Mapped[str] = mapped_column(String(512))
    rule_id: Mapped[str | None] = mapped_column(String(200), index=True)
    source_event: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    # Whole hours since the epoch, so time-series queries group the same way on every backend.
    hour_bucket: Mapped[int] = mapped_column()
    tags: Mapped[list[str]] = mapped_column(default=list)
    mitre_tactics: Mapped[list[str]] = mapped_column(default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(default=list)
    fields: Mapped[dict[str, Any]] = mapped_column(default=dict)

    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.OPEN.value)
    status_changed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    status_changed_by: Mapped[str | None] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(Text)

    agent: Mapped[Agent] = relationship(back_populates="alerts")


class AuditEvent(Base):
    """Append-only record of security-relevant actions."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_at", "at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(200))
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    client_ip: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
