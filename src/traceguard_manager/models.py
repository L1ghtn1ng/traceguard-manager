"""Database schema."""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, Uuid, text
from sqlalchemy import false as sa_false
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
    # Raised by the manager itself when an agent stops reporting.
    AGENT_OFFLINE = "agent_offline"
    # Raised when an agent says it is stopping.
    AGENT_STOPPED = "agent_stopped"


class AlertStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    # Stored because a mute rule matched: kept for the record, out of the way.
    MUTED = "muted"


class CommandAction(enum.StrEnum):
    BLOCK_PEER = "block_peer"
    FREEZE_CGROUP = "freeze_cgroup"
    LIFT_RESPONSE = "lift_response"
    REFRESH_POLICY = "refresh_policy"


class CommandStatus(enum.StrEnum):
    QUEUED = "queued"
    # Handed to the agent; waiting for its result.
    DELIVERED = "delivered"
    DONE = "done"
    FAILED = "failed"
    REFUSED = "refused"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


FINAL_COMMAND_STATUSES = frozenset(
    {CommandStatus.DONE, CommandStatus.FAILED, CommandStatus.REFUSED, CommandStatus.EXPIRED, CommandStatus.CANCELLED}
)


class ChannelKind(enum.StrEnum):
    WEBHOOK = "webhook"
    SLACK = "slack"
    EMAIL = "email"


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
    # Set when someone else chose the password; cleared when the user sets their own.
    must_change_password: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # The last accepted time step, so a code cannot be replayed inside its window.
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    # SHA-256 digests of unused one-time recovery codes.
    recovery_codes: Mapped[list[str]] = mapped_column(default=list, server_default="[]")

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
    user_agent: Mapped[str | None] = mapped_column(String(200))

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
    tags: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    # Reported by newer agents in their heartbeats; None until then.
    agent_version: Mapped[str | None] = mapped_column(String(32))
    kernel_release: Mapped[str | None] = mapped_column(String(128))
    os_name: Mapped[str | None] = mapped_column(String(128))
    response_mode: Mapped[str | None] = mapped_column(String(16))
    commands_enabled: Mapped[bool | None] = mapped_column()
    policy_remote_sha256: Mapped[str | None] = mapped_column(String(64))
    export_dropped_records: Mapped[int | None] = mapped_column(BigInteger)
    export_dropped_alerts: Mapped[int | None] = mapped_column(BigInteger)
    export_rejected_batches: Mapped[int | None] = mapped_column(BigInteger)
    export_spool_batches: Mapped[int | None] = mapped_column(BigInteger)
    active_responses: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, server_default="[]")
    # Records the manager could not read, which usually means the agent sends OCSF.
    invalid_records: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    last_invalid_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # Set by an agent_stopping record, cleared by the next record.
    stopped_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # The highest run counter the agent has reported; records of a lower run are from an older process.
    run_seq: Mapped[int | None] = mapped_column(BigInteger)
    # The process that reported that run itself, in a live batch; nothing it
    # replays is then taken as newer than the run.
    live_run_id: Mapped[str | None] = mapped_column(String(32))
    # Processes earlier reporters replaced, oldest first: older for certain.
    retired_run_ids: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    # Processes that reported live below the stored run: their replays are capped.
    lower_run_ids: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    # The agent's install IDs, oldest first; the last is current, and the
    # earlier ones mark a replay from an install that was replaced.
    install_ids: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    # The run of the stored stop, when the agent counts its runs: only a
    # newer run's records can end it.
    stop_run_seq: Mapped[int | None] = mapped_column(BigInteger)
    stop_run_id: Mapped[str | None] = mapped_column(String(32))
    # The run that sent the stored heartbeat, when it counts its runs.
    heartbeat_run_seq: Mapped[int | None] = mapped_column(BigInteger)
    heartbeat_install_id: Mapped[str | None] = mapped_column(String(32))
    heartbeat_run_id: Mapped[str | None] = mapped_column(String(32))
    # An unseen install heard only with clamped times, waiting to show by its
    # uptime that it is live: first seen then, with that uptime.
    pending_install_id: Mapped[str | None] = mapped_column(String(32))
    pending_run_id: Mapped[str | None] = mapped_column(String(32))
    pending_uptime: Mapped[int | None] = mapped_column(BigInteger)
    pending_seen_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # Fingerprints of the latest stop records seen, so a replay of any of them is ignored.
    seen_stops: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    # When the stop arrived, by the manager's clock, to tell a restart from a replay.
    stop_received_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # When another process first reported live while that stop stood.
    heard_after_stop_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # The newest record time seen, so a replayed stop older than it is ignored.
    last_record_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    active_responses_truncated: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    stop_reason: Mapped[str | None] = mapped_column(String(16))
    # The policy this manager last served the agent.
    policy_served_sha256: Mapped[str | None] = mapped_column(String(64))
    policy_fetched_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    alerts: Mapped[list[Alert]] = relationship(back_populates="agent", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        # Agents replay spooled batches after an outage; the fingerprint makes delivery idempotent.
        UniqueConstraint("agent_id", "fingerprint", name="uq_alerts_agent_fingerprint"),
        Index("ix_alerts_status_severity", "status", "severity_rank"),
        Index("ix_alerts_occurred_at", "occurred_at"),
        Index("ix_alerts_hour_bucket", "hour_bucket"),
        # Each agent's recent alerts (ids are time-ordered), for its hourly cap.
        Index("ix_alerts_agent_id_id", "agent_id", "id"),
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
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL", name="fk_alerts_assignee_id_users"), index=True
    )
    # When a notification pass picked this alert up; claimed once across all workers.
    notified_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    # The agent's alert_id: a detection's own, or for a response the alert it acted on.
    source_alert_id: Mapped[str | None] = mapped_column(String(128), index=True)

    agent: Mapped[Agent] = relationship(back_populates="alerts")
    assignee: Mapped[User | None] = relationship()
    events: Mapped[list[AlertEvent]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class AlertEvent(Base):
    """One entry in an alert's history: a status change, a note, or a change of owner."""

    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(16))  # status | note | assign
    status: Mapped[str | None] = mapped_column(String(16))
    assignee: Mapped[str | None] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(Text)

    alert: Mapped[Alert] = relationship(back_populates="events")


class MuteRule(Base):
    """Silences new alerts from a rule, a host, or a rule on one host."""

    __tablename__ = "mute_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    rule_id: Mapped[str | None] = mapped_column(String(200), index=True)
    # A host is the agent that reported it, as well as the name it gave: an
    # agent's hostname is its own claim, so another agent could repeat it.
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE", name="fk_mute_rules_agent_id_agents"), index=True
    )
    hostname: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class NotificationChannel(Base):
    """Somewhere new alerts are sent: a webhook, a chat webhook, or email."""

    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    # A URL or a list of addresses. Webhook URLs are credentials, so pages only show the host.
    target: Mapped[str] = mapped_column(Text)
    # Signs webhook bodies. Kept readable because every delivery needs it.
    secret: Mapped[str | None] = mapped_column(String(128))
    min_level: Mapped[str] = mapped_column(String(16), default="high")
    enabled: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_success_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_error_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_error: Mapped[str | None] = mapped_column(String(300))


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


class Policy(Base):
    """A TraceGuard policy document the manager signs and serves to agents."""

    __tablename__ = "policies"
    # At most one default, even when two admins save at once.
    __table_args__ = (
        Index(
            "uq_policies_single_default",
            "is_default",
            unique=True,
            sqlite_where=text("is_default"),
            postgresql_where=text("is_default"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    content: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    # Agents with any of these tags may get this policy; the highest priority wins.
    tags: Mapped[list[str]] = mapped_column(default=list, server_default="[]")
    priority: Mapped[int] = mapped_column(default=0)
    is_default: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class AgentCommand(Base):
    """An instruction queued for an agent, delivered when it next polls."""

    __tablename__ = "agent_commands"
    __table_args__ = (
        Index("ix_agent_commands_agent_status", "agent_id", "status"),
        # For the expiry pass, which looks at waiting commands of every agent.
        Index("ix_agent_commands_status_expires", "status", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(200), default="")
    response_action: Mapped[str | None] = mapped_column(String(32))
    duration_seconds: Mapped[int | None] = mapped_column()
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL", name="fk_agent_commands_alert_id_alerts"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default=CommandStatus.QUEUED.value)
    detail: Mapped[str | None] = mapped_column(String(512))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    delivered_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    agent: Mapped[Agent] = relationship()
