"""Alert queries, triage, and dashboard statistics."""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from .errors import DomainError
from .ingest import SEVERITY_RANK
from .models import Alert, AlertKind, AlertStatus

PAGE_SIZE = 50
MAX_PAGE = 2_000
MAX_SEARCH_LENGTH = 100
MAX_RULE_LENGTH = 200
MAX_HOSTNAME_LENGTH = 255
# Hours since the Unix epoch; the upper bound only keeps the value inside every integer column.
MAX_HOUR_BUCKET = 10_000_000
MAX_NOTE_LENGTH = 2_000
MAX_BULK = 200

# Display buckets over TraceGuard's eight syslog-style severities.
LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")
_LEVEL_RANKS: dict[str, tuple[int, int]] = {
    "critical": (5, 7),
    "high": (4, 4),
    "medium": (3, 3),
    "low": (0, 2),
}


type TextColumn = InstrumentedAttribute[str] | InstrumentedAttribute[str | None]


class AlertError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


def level_for_rank(rank: int) -> str:
    for level, (low, high) in _LEVEL_RANKS.items():
        if low <= rank <= high:
            return level
    return "medium"


def level_for_severity(severity: str) -> str:
    return level_for_rank(SEVERITY_RANK.get(severity, 3))


@dataclass(frozen=True, slots=True)
class AlertFilter:
    status: str | None = None
    level: str | None = None
    kind: str | None = None
    agent_id: uuid.UUID | None = None
    query: str | None = None
    # Exact matches, set by following a link from a rule, a host or an hour of the chart.
    rule: str | None = None
    host: str | None = None
    hour: int | None = None
    page: int = 1

    @classmethod
    def from_params(
        cls,
        *,
        status: str | None,
        level: str | None,
        kind: str | None,
        agent: str | None,
        query: str | None,
        page: int,
        rule: str | None = None,
        host: str | None = None,
        hour: int | None = None,
    ) -> AlertFilter:
        """Build a filter from request parameters; unknown values are dropped, not echoed."""
        agent_id: uuid.UUID | None = None
        if agent:
            try:
                agent_id = uuid.UUID(agent)
            except ValueError:
                agent_id = None
        text = (query or "").strip()[:MAX_SEARCH_LENGTH] or None
        return cls(
            status=status if status in set(AlertStatus) else None,
            level=level if level in LEVELS else None,
            kind=kind if kind in set(AlertKind) else None,
            agent_id=agent_id,
            query=text,
            rule=(rule or "").strip()[:MAX_RULE_LENGTH] or None,
            host=(host or "").strip()[:MAX_HOSTNAME_LENGTH] or None,
            hour=hour if hour is not None and 0 <= hour <= MAX_HOUR_BUCKET else None,
            page=min(max(page, 1), MAX_PAGE),
        )

    def conditions(self) -> list[ColumnElement[bool]]:
        clauses: list[ColumnElement[bool]] = []
        if self.status:
            clauses.append(Alert.status == self.status)
        if self.level:
            low, high = _LEVEL_RANKS[self.level]
            clauses.append(Alert.severity_rank.between(low, high))
        if self.kind:
            clauses.append(Alert.kind == self.kind)
        if self.agent_id:
            clauses.append(Alert.agent_id == self.agent_id)
        if self.rule:
            clauses.append(Alert.rule_id == self.rule)
        if self.host:
            clauses.append(Alert.hostname == self.host)
        if self.hour is not None:
            clauses.append(Alert.hour_bucket == self.hour)
        if self.query:
            # The search term is a bound parameter; escaping only stops it acting as a wildcard.
            pattern = f"%{_escape_like(self.query)}%"
            clauses.append(
                or_(
                    Alert.title.ilike(pattern, escape="\\"),
                    Alert.rule_id.ilike(pattern, escape="\\"),
                    Alert.hostname.ilike(pattern, escape="\\"),
                )
            )
        return clauses


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def list_alerts(session: AsyncSession, filters: AlertFilter) -> tuple[list[Alert], int]:
    clauses = filters.conditions()
    total = await session.scalar(select(func.count()).select_from(Alert).where(*clauses)) or 0
    rows = await session.scalars(
        select(Alert)
        .where(*clauses)
        .order_by(Alert.occurred_at.desc(), Alert.id.desc())
        .limit(PAGE_SIZE)
        .offset((filters.page - 1) * PAGE_SIZE)
    )
    return list(rows), total


async def get_alert(session: AsyncSession, alert_id: uuid.UUID) -> Alert | None:
    return await session.get(Alert, alert_id)


async def recent_for_agent(session: AsyncSession, agent_id: uuid.UUID, *, limit: int = 10) -> list[Alert]:
    rows = await session.scalars(
        select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.occurred_at.desc(), Alert.id.desc()).limit(limit)
    )
    return list(rows)


async def set_status(
    session: AsyncSession,
    *,
    alert_ids: Sequence[uuid.UUID],
    status: str,
    actor: str,
    note: str | None,
    now: datetime,
) -> int:
    """Move alerts to a new status and return how many rows changed."""
    if status not in set(AlertStatus):
        raise AlertError("Unknown status.")
    if not alert_ids or len(alert_ids) > MAX_BULK:
        raise AlertError(f"Select between 1 and {MAX_BULK} alerts.")
    values: dict[str, object] = {"status": status, "status_changed_at": now, "status_changed_by": actor}
    if note is not None:
        cleaned = note.strip()
        if len(cleaned) > MAX_NOTE_LENGTH:
            raise AlertError(f"Notes are limited to {MAX_NOTE_LENGTH} characters.")
        values["note"] = cleaned or None
    result = await session.execute(update(Alert).where(Alert.id.in_(alert_ids)).values(**values))
    return max(getattr(result, "rowcount", 0), 0)


async def alerts_after(session: AsyncSession, cursor: uuid.UUID | None, *, limit: int = 20) -> list[Alert]:
    """Alerts created after ``cursor``. Identifiers are UUIDv7, so they sort by creation time."""
    statement = select(Alert).order_by(Alert.id.desc()).limit(limit)
    if cursor is not None:
        statement = statement.where(Alert.id > cursor)
    return list(reversed(list(await session.scalars(statement))))


async def latest_alert_id(session: AsyncSession) -> uuid.UUID | None:
    # Not max(): PostgreSQL has no max() aggregate for uuid on older releases.
    return await session.scalar(select(Alert.id).order_by(Alert.id.desc()).limit(1))


async def purge_older_than(session: AsyncSession, *, cutoff: datetime) -> int:
    result = await session.execute(delete(Alert).where(Alert.occurred_at < cutoff))
    return max(getattr(result, "rowcount", 0), 0)


@dataclass(frozen=True, slots=True)
class TimelineBar:
    bucket: int
    label: str
    counts: dict[str, int]
    total: int


@dataclass(frozen=True, slots=True)
class DashboardStats:
    open_by_level: dict[str, int]
    open_total: int
    acknowledged_total: int
    resolved_24h: int
    last_24h: int
    timeline: list[TimelineBar] = field(default_factory=list)
    timeline_peak: int = 0
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    top_hosts: list[tuple[str, int]] = field(default_factory=list)
    by_kind: list[tuple[str, int]] = field(default_factory=list)


async def dashboard_stats(session: AsyncSession, *, now: datetime) -> DashboardStats:
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    open_by_level = dict.fromkeys(LEVELS, 0)
    rows = await session.execute(
        select(Alert.severity_rank, func.count()).where(Alert.status == AlertStatus.OPEN.value).group_by(Alert.severity_rank)
    )
    for rank, count in rows:
        open_by_level[level_for_rank(rank)] += count

    status_rows = await session.execute(select(Alert.status, func.count()).group_by(Alert.status))
    status_counts: dict[str, int] = {row[0]: row[1] for row in status_rows}
    resolved_24h = (
        await session.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status == AlertStatus.RESOLVED.value, Alert.status_changed_at >= day_ago)
        )
        or 0
    )

    current_bucket = int(now.timestamp()) // 3600
    first_bucket = current_bucket - 23
    buckets: dict[int, dict[str, int]] = {bucket: dict.fromkeys(LEVELS, 0) for bucket in range(first_bucket, current_bucket + 1)}
    rows = await session.execute(
        select(Alert.hour_bucket, Alert.severity_rank, func.count())
        .where(Alert.hour_bucket.between(first_bucket, current_bucket))
        .group_by(Alert.hour_bucket, Alert.severity_rank)
    )
    for bucket, rank, count in rows:
        buckets[bucket][level_for_rank(rank)] += count
    timeline = [
        TimelineBar(
            bucket=bucket,
            label=datetime.fromtimestamp(bucket * 3600, tz=now.tzinfo).strftime("%H:00"),
            counts=counts,
            total=sum(counts.values()),
        )
        for bucket, counts in buckets.items()
    ]

    async def top(
        column: InstrumentedAttribute[str] | InstrumentedAttribute[str | None],
    ) -> list[tuple[str, int]]:
        result = await session.execute(
            select(column, func.count().label("n"))
            .where(Alert.occurred_at >= week_ago, column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc(), column)
            .limit(6)
        )
        return [(str(name), count) for name, count in result]

    return DashboardStats(
        open_by_level=open_by_level,
        open_total=status_counts.get(AlertStatus.OPEN.value, 0),
        acknowledged_total=status_counts.get(AlertStatus.ACKNOWLEDGED.value, 0),
        resolved_24h=resolved_24h,
        last_24h=sum(bar.total for bar in timeline),
        timeline=timeline,
        timeline_peak=max((bar.total for bar in timeline), default=0),
        top_rules=await top(Alert.rule_id),
        top_hosts=await top(Alert.hostname),
        by_kind=await top(Alert.kind),
    )
