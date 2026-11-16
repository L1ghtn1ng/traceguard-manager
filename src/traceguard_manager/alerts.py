"""Alert queries, triage, and dashboard statistics."""

import csv
import io
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, case, cast, delete, exists, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from .errors import DomainError
from .ingest import SEVERITY_RANK
from .models import Alert, AlertEvent, AlertKind, AlertStatus, User, new_id

PAGE_SIZE = 50
MAX_PAGE = 2_000
MAX_SEARCH_LENGTH = 100
MAX_NOTE_LENGTH = 2_000
MAX_BULK = 200
# "Select all matching" changes this many alerts at most, so one click cannot rewrite the table.
MAX_BULK_MATCHING = 5_000
MAX_RULE_LENGTH = 200
MAX_HOSTNAME_LENGTH = 255
MAX_LABEL_LENGTH = 200
# Hours since the Unix epoch; the upper bound only keeps the value inside every integer column.
MAX_HOUR_BUCKET = 10_000_000
EXPORT_LIMIT = 10_000
GROUP_LIMIT = 200
_CHUNK = 500

# Display buckets over TraceGuard's eight syslog-style severities.
LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")
_LEVEL_RANKS: dict[str, tuple[int, int]] = {
    "critical": (5, 7),
    "high": (4, 4),
    "medium": (3, 3),
    "low": (0, 2),
}

RANGES: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
RANGE_LABELS: dict[str, str] = {"1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days"}
SORTS: tuple[str, ...] = ("time", "severity", "host", "status")
GROUPS: tuple[str, ...] = ("rule", "host")
# Filters on the list-valued columns, by the name used in URLs.
LABELS: tuple[str, ...] = ("tag", "tactic", "technique")
OWNER_ME = "me"
OWNER_NONE = "none"


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


def min_rank_for_level(level: str) -> int:
    """The lowest severity rank that counts as ``level`` or worse."""
    return _LEVEL_RANKS.get(level, _LEVEL_RANKS["high"])[0]


def _label_column(name: str) -> InstrumentedAttribute[list[str]]:
    return {"tag": Alert.tags, "tactic": Alert.mitre_tactics, "technique": Alert.mitre_techniques}[name]


def _list_contains(column: InstrumentedAttribute[list[str]], value: str, dialect: str) -> ColumnElement[bool]:
    """True when a JSON array column holds ``value``. The value is always a bound parameter."""
    if dialect == "postgresql":
        return cast(column, JSONB).contains([value])
    each = func.json_each(column).table_valued("value", name="each_item")
    return exists(select(1).select_from(each).where(each.c.value == value))


@dataclass(frozen=True, slots=True)
class AlertFilter:
    status: str | None = None
    level: str | None = None
    kind: str | None = None
    agent_id: uuid.UUID | None = None
    query: str | None = None
    time_range: str | None = None
    # "me", "none", or a user id.
    owner: str | None = None
    # Exact matches, set by following a link from a rule, a host, a label or an hour of the chart.
    rule: str | None = None
    host: str | None = None
    hour: int | None = None
    tag: str | None = None
    tactic: str | None = None
    technique: str | None = None
    sort: str = "time"
    descending: bool = True
    page: int = 1

    @classmethod
    def from_params(cls, params: Mapping[str, object]) -> AlertFilter:
        """Build a filter from request parameters; unknown values are dropped, not echoed."""

        def text(name: str, limit: int) -> str | None:
            value = params.get(name)
            return (value.strip()[:limit] or None) if isinstance(value, str) else None

        def number(name: str) -> int | None:
            value = params.get(name)
            if isinstance(value, bool):
                return None
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.strip().lstrip("-").isdigit():
                return int(value.strip())
            return None

        def parsed_uuid(value: str | None) -> uuid.UUID | None:
            try:
                return uuid.UUID(value) if value else None
            except ValueError:
                return None

        status, level, kind = text("status", 16), text("level", 16), text("kind", 16)
        owner = text("owner", 36)
        if owner not in {OWNER_ME, OWNER_NONE}:
            owner_id = parsed_uuid(owner)
            owner = str(owner_id) if owner_id else None
        hour, page = number("hour"), number("page")
        sort = text("sort", 16)
        time_range = text("range", 8)
        return cls(
            status=status if status in set(AlertStatus) else None,
            level=level if level in LEVELS else None,
            kind=kind if kind in set(AlertKind) else None,
            agent_id=parsed_uuid(text("agent", 36)),
            query=text("q", MAX_SEARCH_LENGTH),
            time_range=time_range if time_range in RANGES else None,
            owner=owner,
            rule=text("rule", MAX_RULE_LENGTH),
            host=text("host", MAX_HOSTNAME_LENGTH),
            hour=hour if hour is not None and 0 <= hour <= MAX_HOUR_BUCKET else None,
            tag=text("tag", MAX_LABEL_LENGTH),
            tactic=text("tactic", MAX_LABEL_LENGTH),
            technique=text("technique", MAX_LABEL_LENGTH),
            sort=sort if sort in SORTS else "time",
            descending=text("dir", 4) != "asc",
            page=min(max(page or 1, 1), MAX_PAGE),
        )

    def to_query(self) -> dict[str, str]:
        """The filter as URL parameters, without the page. Round-trips through ``from_params``."""
        values: dict[str, str | None] = {
            "q": self.query,
            "status": self.status,
            "level": self.level,
            "kind": self.kind,
            "agent": str(self.agent_id) if self.agent_id else None,
            "range": self.time_range,
            "owner": self.owner,
            "rule": self.rule,
            "host": self.host,
            "hour": str(self.hour) if self.hour is not None else None,
            "tag": self.tag,
            "tactic": self.tactic,
            "technique": self.technique,
            "sort": self.sort if self.sort != "time" else None,
            "dir": None if self.descending else "asc",
        }
        return {key: value for key, value in values.items() if value}

    def conditions(self, *, now: datetime, dialect: str, viewer_id: uuid.UUID | None = None) -> list[ColumnElement[bool]]:
        clauses: list[ColumnElement[bool]] = []
        if self.status:
            clauses.append(Alert.status == self.status)
        else:
            # Muted alerts are kept for the record but stay out of the way unless asked for.
            clauses.append(Alert.status != AlertStatus.MUTED.value)
        if self.level:
            low, high = _LEVEL_RANKS[self.level]
            clauses.append(Alert.severity_rank.between(low, high))
        if self.kind:
            clauses.append(Alert.kind == self.kind)
        if self.agent_id:
            clauses.append(Alert.agent_id == self.agent_id)
        if self.time_range:
            clauses.append(Alert.occurred_at >= now - RANGES[self.time_range])
        if self.owner == OWNER_NONE:
            clauses.append(Alert.assignee_id.is_(None))
        elif self.owner == OWNER_ME:
            # Without a viewer there is nobody for "me" to mean, so nothing matches.
            clauses.append(Alert.assignee_id == viewer_id if viewer_id else Alert.id.is_(None))
        elif self.owner:
            clauses.append(Alert.assignee_id == uuid.UUID(self.owner))
        if self.rule:
            clauses.append(Alert.rule_id == self.rule)
        if self.host:
            clauses.append(Alert.hostname == self.host)
        if self.hour is not None:
            clauses.append(Alert.hour_bucket == self.hour)
        for name in LABELS:
            value: str | None = getattr(self, name)
            if value:
                clauses.append(_list_contains(_label_column(name), value, dialect))
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

    def ordering(self) -> list[Any]:
        columns: dict[str, Any] = {
            "time": Alert.occurred_at,
            "severity": Alert.severity_rank,
            "host": Alert.hostname,
            "status": Alert.status,
        }
        primary = columns[self.sort]
        ordered = [primary.desc() if self.descending else primary.asc()]
        if self.sort != "time":
            ordered.append(Alert.occurred_at.desc())
        # The identifier makes the order total, so paging never repeats or skips a row.
        ordered.append(Alert.id.desc() if self.descending else Alert.id.asc())
        return ordered


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def list_alerts(
    session: AsyncSession,
    filters: AlertFilter,
    *,
    now: datetime,
    dialect: str,
    viewer_id: uuid.UUID | None = None,
) -> tuple[list[Alert], int]:
    clauses = filters.conditions(now=now, dialect=dialect, viewer_id=viewer_id)
    total = await session.scalar(select(func.count()).select_from(Alert).where(*clauses)) or 0
    rows = await session.scalars(
        select(Alert).where(*clauses).order_by(*filters.ordering()).limit(PAGE_SIZE).offset((filters.page - 1) * PAGE_SIZE)
    )
    return list(rows), total


@dataclass(frozen=True, slots=True)
class AlertGroup:
    key: str | None
    total: int
    open: int
    top_rank: int
    latest: datetime


async def grouped(
    session: AsyncSession,
    filters: AlertFilter,
    *,
    by: str,
    now: datetime,
    dialect: str,
    viewer_id: uuid.UUID | None = None,
) -> list[AlertGroup]:
    """Matching alerts collapsed to one row per rule or per host, busiest first."""
    column: TextColumn = Alert.rule_id if by == "rule" else Alert.hostname
    opened = func.sum(case((Alert.status == AlertStatus.OPEN.value, 1), else_=0))
    rows = await session.execute(
        select(column, func.count(), opened, func.max(Alert.severity_rank), func.max(Alert.occurred_at))
        .where(*filters.conditions(now=now, dialect=dialect, viewer_id=viewer_id))
        .group_by(column)
        .order_by(func.count().desc(), column)
        .limit(GROUP_LIMIT)
    )
    return [
        AlertGroup(key=key, total=total, open=int(open_count or 0), top_rank=rank, latest=latest)
        for key, total, open_count, rank, latest in rows
    ]


async def export_rows(
    session: AsyncSession,
    filters: AlertFilter,
    *,
    now: datetime,
    dialect: str,
    viewer_id: uuid.UUID | None = None,
) -> list[Alert]:
    rows = await session.scalars(
        select(Alert)
        .where(*filters.conditions(now=now, dialect=dialect, viewer_id=viewer_id))
        .order_by(*filters.ordering())
        .limit(EXPORT_LIMIT)
    )
    return list(rows)


EXPORT_COLUMNS: tuple[str, ...] = (
    "id",
    "occurred_at",
    "received_at",
    "severity",
    "kind",
    "status",
    "title",
    "rule_id",
    "hostname",
    "agent",
    "owner",
    "tags",
    "mitre_tactics",
    "mitre_techniques",
    "note",
)


def export_record(alert: Alert, *, agent_names: Mapping[uuid.UUID, str], usernames: Mapping[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "occurred_at": alert.occurred_at.isoformat(),
        "received_at": alert.received_at.isoformat(),
        "severity": alert.severity,
        "kind": alert.kind,
        "status": alert.status,
        "title": alert.title,
        "rule_id": alert.rule_id,
        "hostname": alert.hostname,
        "agent": agent_names.get(alert.agent_id),
        "owner": usernames.get(alert.assignee_id) if alert.assignee_id else None,
        "tags": list(alert.tags),
        "mitre_tactics": list(alert.mitre_tactics),
        "mitre_techniques": list(alert.mitre_techniques),
        "note": alert.note,
    }


def _csv_cell(value: object) -> str:
    """Flatten a value for a spreadsheet, defusing anything it would run as a formula."""
    if value is None:
        return ""
    text = " ".join(str(item) for item in value) if isinstance(value, list) else str(value)
    # Agents report these strings, and a spreadsheet treats a leading =, +, - or @ as a formula.
    return f"'{text}" if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def to_csv(records: Sequence[Mapping[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(EXPORT_COLUMNS)
    for record in records:
        writer.writerow([_csv_cell(record.get(column)) for column in EXPORT_COLUMNS])
    return buffer.getvalue()


async def get_alert(session: AsyncSession, alert_id: uuid.UUID) -> Alert | None:
    return await session.get(Alert, alert_id)


async def recent_for_agent(session: AsyncSession, agent_id: uuid.UUID, *, limit: int = 10) -> list[Alert]:
    rows = await session.scalars(
        select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.occurred_at.desc(), Alert.id.desc()).limit(limit)
    )
    return list(rows)


@dataclass(frozen=True, slots=True)
class Related:
    same_rule_total: int
    same_rule: list[Alert]
    same_host: list[Alert]


async def related(session: AsyncSession, alert: Alert, *, limit: int = 5) -> Related:
    """Other alerts from the same rule, and what else the host reported within the hour either side."""
    same_rule_total = 0
    same_rule: list[Alert] = []
    if alert.rule_id:
        scope = (Alert.rule_id == alert.rule_id, Alert.id != alert.id)
        same_rule_total = await session.scalar(select(func.count()).select_from(Alert).where(*scope)) or 0
        same_rule = list(
            await session.scalars(select(Alert).where(*scope).order_by(Alert.occurred_at.desc(), Alert.id.desc()).limit(limit))
        )
    window = timedelta(hours=1)
    same_host = list(
        await session.scalars(
            select(Alert)
            .where(
                Alert.hostname == alert.hostname,
                Alert.id != alert.id,
                Alert.occurred_at.between(alert.occurred_at - window, alert.occurred_at + window),
            )
            .order_by(Alert.occurred_at.desc(), Alert.id.desc())
            .limit(limit)
        )
    )
    return Related(same_rule_total=same_rule_total, same_rule=same_rule, same_host=same_host)


async def history(session: AsyncSession, alert_id: uuid.UUID) -> list[AlertEvent]:
    return list(
        await session.scalars(select(AlertEvent).where(AlertEvent.alert_id == alert_id).order_by(AlertEvent.at, AlertEvent.id))
    )


def _clean_note(note: str | None) -> str | None:
    if note is None:
        return None
    cleaned = note.strip()
    if len(cleaned) > MAX_NOTE_LENGTH:
        raise AlertError(f"Notes are limited to {MAX_NOTE_LENGTH} characters.")
    return cleaned or None


async def _apply_status(
    session: AsyncSession, *, alert_ids: Sequence[uuid.UUID], status: str, actor: str, note: str | None, now: datetime
) -> int:
    """Move alerts to ``status`` and add a history entry to each one that changed or got a note."""
    changed_total = 0
    for start in range(0, len(alert_ids), _CHUNK):
        chunk = list(alert_ids[start : start + _CHUNK])
        current = {row[0]: row[1] for row in await session.execute(select(Alert.id, Alert.status).where(Alert.id.in_(chunk)))}
        changed = {alert_id for alert_id, existing in current.items() if existing != status}
        targets = list(current) if note else list(changed)
        if not targets:
            continue
        values: dict[str, object] = {"status": status, "status_changed_at": now, "status_changed_by": actor}
        if note:
            values["note"] = note
        await session.execute(update(Alert).where(Alert.id.in_(targets)).values(**values))
        await session.execute(
            insert(AlertEvent),
            [
                {
                    "id": new_id(),
                    "alert_id": alert_id,
                    "at": now,
                    "actor": actor,
                    "action": "status" if alert_id in changed else "note",
                    "status": status if alert_id in changed else None,
                    "note": note,
                }
                for alert_id in targets
            ],
        )
        changed_total += len(changed)
    return changed_total


async def set_status(
    session: AsyncSession,
    *,
    alert_ids: Sequence[uuid.UUID],
    status: str,
    actor: str,
    note: str | None,
    now: datetime,
) -> int:
    """Move alerts to a new status and return how many actually changed."""
    if status not in set(AlertStatus):
        raise AlertError("Unknown status.")
    if not alert_ids or len(alert_ids) > MAX_BULK:
        raise AlertError(f"Select between 1 and {MAX_BULK} alerts.")
    return await _apply_status(session, alert_ids=alert_ids, status=status, actor=actor, note=_clean_note(note), now=now)


async def set_status_matching(
    session: AsyncSession,
    filters: AlertFilter,
    *,
    status: str,
    actor: str,
    note: str | None,
    now: datetime,
    dialect: str,
    viewer_id: uuid.UUID | None = None,
) -> int:
    """Move every alert the filter matches, not just the ones on the page."""
    if status not in set(AlertStatus):
        raise AlertError("Unknown status.")
    clauses = filters.conditions(now=now, dialect=dialect, viewer_id=viewer_id)
    ids = list(await session.scalars(select(Alert.id).where(*clauses).limit(MAX_BULK_MATCHING + 1)))
    if len(ids) > MAX_BULK_MATCHING:
        raise AlertError(f"More than {MAX_BULK_MATCHING} alerts match. Narrow the filters and try again.")
    if not ids:
        raise AlertError("No alerts match these filters any more.")
    return await _apply_status(session, alert_ids=ids, status=status, actor=actor, note=_clean_note(note), now=now)


async def add_note(session: AsyncSession, *, alert: Alert, note: str, actor: str, now: datetime) -> None:
    cleaned = _clean_note(note)
    if cleaned is None:
        raise AlertError("Write a note first.")
    alert.note = cleaned
    session.add(AlertEvent(alert_id=alert.id, at=now, actor=actor, action="note", note=cleaned))


async def assign(
    session: AsyncSession, *, alert_ids: Sequence[uuid.UUID], assignee: User | None, actor: str, now: datetime
) -> int:
    """Give alerts an owner, or clear it. Returns how many changed hands."""
    if not alert_ids or len(alert_ids) > MAX_BULK:
        raise AlertError(f"Select between 1 and {MAX_BULK} alerts.")
    new_owner = assignee.id if assignee else None
    current = {
        row[0]: row[1] for row in await session.execute(select(Alert.id, Alert.assignee_id).where(Alert.id.in_(alert_ids)))
    }
    changed = [alert_id for alert_id, owner in current.items() if owner != new_owner]
    if not changed:
        return 0
    await session.execute(update(Alert).where(Alert.id.in_(changed)).values(assignee_id=new_owner))
    await session.execute(
        insert(AlertEvent),
        [
            {
                "id": new_id(),
                "alert_id": alert_id,
                "at": now,
                "actor": actor,
                "action": "assign",
                "assignee": assignee.username if assignee else None,
            }
            for alert_id in changed
        ],
    )
    return len(changed)


async def alerts_after(session: AsyncSession, cursor: uuid.UUID | None, *, limit: int = 20) -> list[Alert]:
    """Unmuted alerts created after ``cursor``. Identifiers are UUIDv7, so they sort by creation time."""
    statement = select(Alert).where(Alert.status != AlertStatus.MUTED.value).order_by(Alert.id.desc()).limit(limit)
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
    unassigned_open: int = 0
    timeline: list[TimelineBar] = field(default_factory=list)
    timeline_peak: int = 0
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    top_hosts: list[tuple[str, int]] = field(default_factory=list)
    by_kind: list[tuple[str, int]] = field(default_factory=list)


async def dashboard_stats(session: AsyncSession, *, now: datetime) -> DashboardStats:
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)
    not_muted = Alert.status != AlertStatus.MUTED.value

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
    unassigned_open = (
        await session.scalar(
            select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.OPEN.value, Alert.assignee_id.is_(None))
        )
        or 0
    )

    current_bucket = int(now.timestamp()) // 3600
    first_bucket = current_bucket - 23
    buckets: dict[int, dict[str, int]] = {bucket: dict.fromkeys(LEVELS, 0) for bucket in range(first_bucket, current_bucket + 1)}
    rows = await session.execute(
        select(Alert.hour_bucket, Alert.severity_rank, func.count())
        .where(Alert.hour_bucket.between(first_bucket, current_bucket), not_muted)
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

    async def top(column: TextColumn) -> list[tuple[str, int]]:
        result = await session.execute(
            select(column, func.count().label("n"))
            .where(Alert.occurred_at >= week_ago, column.is_not(None), not_muted)
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
        unassigned_open=unassigned_open,
        timeline=timeline,
        timeline_peak=max((bar.total for bar in timeline), default=0),
        top_rules=await top(Alert.rule_id),
        top_hosts=await top(Alert.hostname),
        by_kind=await top(Alert.kind),
    )
