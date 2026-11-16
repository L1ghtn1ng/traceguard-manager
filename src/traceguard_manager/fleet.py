"""Agent enrolment, heartbeat tracking, and storage of ingested batches."""

import hashlib
import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from . import mutes, security
from .errors import DomainError
from .ingest import ParsedBatch, severity_rank
from .models import Agent, Alert, AlertKind, AlertStatus, new_id

PAGE_SIZE = 50
MAX_PAGE = 2_000
MAX_TAGS = 16
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}")
STATUSES: tuple[str, ...] = ("online", "degraded", "offline", "pending", "disabled")
SORTS: tuple[str, ...] = ("name", "status", "seen", "host")
# Worst first, so sorting by status puts what needs attention at the top.
_STATUS_ORDER = {"offline": 0, "degraded": 1, "pending": 2, "online": 3, "disabled": 4}
# An agent that has been silent for longer than this is old news, not a new outage.
OFFLINE_ALERT_WINDOW = timedelta(days=1)


class FleetError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


@dataclass(frozen=True, slots=True)
class StoreResult:
    stored: int
    duplicates: int
    new_alert_ids: list[uuid.UUID]


@dataclass(frozen=True, slots=True)
class AgentView:
    """An agent plus the state derived from it at render time."""

    agent: Agent
    status: str  # pending | online | degraded | offline | disabled
    drifted: bool


@dataclass(frozen=True, slots=True)
class FleetSummary:
    total: int
    online: int
    degraded: int
    offline: int
    pending: int
    disabled: int
    drifted: int
    baseline_policy: str | None


def agent_status(agent: Agent, *, now: datetime, offline_after: timedelta) -> str:
    if not agent.enabled:
        return "disabled"
    if agent.last_seen_at is None:
        return "pending"
    if now - agent.last_seen_at > offline_after:
        return "offline"
    if agent.healthy is False or agent.ringbuf_degraded or agent.unavailable_hooks:
        return "degraded"
    return "online"


def baseline_policy(agents: list[Agent]) -> str | None:
    """The policy digest most enabled agents report; anything else counts as drift."""
    digests = Counter(agent.policy_sha256 for agent in agents if agent.enabled and agent.policy_sha256)
    if not digests:
        return None
    # Ties resolve to the smallest digest so the answer is stable between requests.
    return min(digests, key=lambda digest: (-digests[digest], digest))


def describe_fleet(agents: list[Agent], *, now: datetime, offline_after: timedelta) -> tuple[list[AgentView], FleetSummary]:
    baseline = baseline_policy(agents)
    views = [
        AgentView(
            agent=agent,
            status=agent_status(agent, now=now, offline_after=offline_after),
            drifted=bool(agent.enabled and agent.policy_sha256 and baseline and agent.policy_sha256 != baseline),
        )
        for agent in agents
    ]
    counts = Counter(view.status for view in views)
    summary = FleetSummary(
        total=len(views),
        online=counts["online"],
        degraded=counts["degraded"],
        offline=counts["offline"],
        pending=counts["pending"],
        disabled=counts["disabled"],
        drifted=sum(view.drifted for view in views),
        baseline_policy=baseline,
    )
    return views, summary


@dataclass(frozen=True, slots=True)
class FleetQuery:
    """How the fleet page is searched, filtered, sorted and paged."""

    text: str | None = None
    status: str | None = None
    tag: str | None = None
    sort: str = "name"
    descending: bool = False
    page: int = 1

    @classmethod
    def from_params(cls, params: Mapping[str, object]) -> FleetQuery:
        def text(name: str, limit: int) -> str | None:
            value = params.get(name)
            return (value.strip()[:limit] or None) if isinstance(value, str) else None

        status, sort, tag = text("status", 16), text("sort", 16), text("tag", 32)
        page = params.get("page")
        return cls(
            text=text("q", 100),
            status=status if status in STATUSES else None,
            tag=tag if tag and TAG_RE.fullmatch(tag) else None,
            sort=sort if sort in SORTS else "name",
            descending=text("dir", 4) == "desc",
            page=min(max(page, 1), MAX_PAGE) if isinstance(page, int) and not isinstance(page, bool) else 1,
        )

    def to_query(self) -> dict[str, str]:
        values = {
            "q": self.text,
            "status": self.status,
            "tag": self.tag,
            "sort": self.sort if self.sort != "name" else None,
            "dir": "desc" if self.descending else None,
        }
        return {key: value for key, value in values.items() if value}


def select_views(views: Sequence[AgentView], query: FleetQuery) -> tuple[list[AgentView], int]:
    """Apply a fleet query. Status is derived from time, so this runs here rather than in SQL."""
    needle = query.text.lower() if query.text else None
    chosen = [
        view
        for view in views
        if (query.status is None or view.status == query.status)
        and (query.tag is None or query.tag in view.agent.tags)
        and (
            needle is None
            or needle in view.agent.name.lower()
            or needle in (view.agent.hostname or "").lower()
            or any(needle in tag.lower() for tag in view.agent.tags)
        )
    ]
    keys = {
        "name": lambda view: view.agent.name.lower(),
        "status": lambda view: (_STATUS_ORDER[view.status], view.agent.name.lower()),
        "host": lambda view: ((view.agent.hostname or "").lower(), view.agent.name.lower()),
        # Never-seen agents sort as the oldest.
        "seen": lambda view: (view.agent.last_seen_at is not None, view.agent.last_seen_at or view.agent.created_at),
    }
    chosen.sort(key=keys[query.sort], reverse=query.descending)
    start = (query.page - 1) * PAGE_SIZE
    return chosen[start : start + PAGE_SIZE], len(chosen)


def all_tags(agents: Sequence[Agent]) -> list[str]:
    return sorted({tag for agent in agents for tag in agent.tags})


def parse_tags(text: str) -> list[str]:
    """Split a comma or space separated list into tags, rejecting anything unusual."""
    tags: list[str] = []
    for raw in re.split(r"[,\s]+", text.strip()):
        if not raw:
            continue
        if not TAG_RE.fullmatch(raw):
            raise FleetError("Tags are 1-32 characters: letters, digits, dot, dash, colon or underscore.")
        if raw not in tags:
            tags.append(raw)
    if len(tags) > MAX_TAGS:
        raise FleetError(f"An agent can have at most {MAX_TAGS} tags.")
    return tags


async def update_agent(session: AsyncSession, agent: Agent, *, name: str | None, tags: list[str] | None) -> None:
    """Rename an agent or replace its tags. Its token and history are untouched."""
    if name is not None:
        name = name.strip()
        if not security.AGENT_NAME_RE.fullmatch(name):
            raise FleetError("Agent name must be 1-100 characters: letters, digits, dot, dash or underscore.")
        if name != agent.name and await session.scalar(select(Agent.id).where(Agent.name == name)) is not None:
            raise FleetError("An agent with that name already exists.")
        agent.name = name
    if tags is not None:
        agent.tags = tags
    session.add(agent)


async def list_agents(session: AsyncSession) -> list[Agent]:
    return list(await session.scalars(select(Agent).order_by(Agent.name)))


async def get_agent(session: AsyncSession, agent_id: uuid.UUID) -> Agent | None:
    return await session.get(Agent, agent_id)


async def enroll_agent(session: AsyncSession, *, name: str) -> tuple[Agent, str]:
    """Create an agent and return it with its token. The token is shown once."""
    name = name.strip()
    if not security.AGENT_NAME_RE.fullmatch(name):
        raise FleetError("Agent name must be 1-100 characters: letters, digits, dot, dash or underscore.")
    if await session.scalar(select(Agent.id).where(Agent.name == name)) is not None:
        raise FleetError("An agent with that name already exists.")
    token = security.new_agent_token()
    agent = Agent(
        name=name,
        token_hash=security.hash_token(token),
        token_prefix=security.token_display_prefix(token),
        unavailable_hooks=[],
        tags=[],
    )
    session.add(agent)
    await session.flush()
    return agent, token


def rotate_token(agent: Agent, *, now: datetime) -> str:
    """Replace the agent's token; the previous one stops working immediately."""
    token = security.new_agent_token()
    agent.token_hash = security.hash_token(token)
    agent.token_prefix = security.token_display_prefix(token)
    agent.token_rotated_at = now
    return token


async def agent_for_token(session: AsyncSession, token: str) -> Agent | None:
    if not token.startswith(security.AGENT_TOKEN_PREFIX) or len(token) > 128:
        return None
    return await session.scalar(select(Agent).where(Agent.token_hash == security.hash_token(token), Agent.enabled.is_(True)))


async def store_batch(
    session: AsyncSession, *, agent_id: uuid.UUID, batch: ParsedBatch, now: datetime, dialect: str
) -> StoreResult:
    """Persist a parsed batch for one agent in a single transaction."""
    values: dict[str, object] = {
        "last_seen_at": now,
        "events_received": Agent.events_received + batch.received,
    }
    if batch.hostname is not None:
        values["hostname"] = batch.hostname
    if (heartbeat := batch.heartbeat) is not None:
        values |= {
            "hostname": heartbeat.hostname,
            "last_heartbeat_at": heartbeat.at,
            "healthy": heartbeat.healthy,
            "policy_sha256": heartbeat.policy_sha256,
            "policy_mode": heartbeat.policy_mode,
            "uptime_seconds": heartbeat.uptime_seconds,
            "ringbuf_degraded": heartbeat.ringbuf_degraded,
            "ringbuf_dropped_events": heartbeat.ringbuf_dropped_events,
            "detection_rules": heartbeat.detection_rules,
            "unavailable_hooks": heartbeat.unavailable_hooks,
        }
    await session.execute(update(Agent).where(Agent.id == agent_id).values(**values))

    unique = {alert.fingerprint: alert for alert in batch.alerts}
    if not unique:
        return StoreResult(stored=0, duplicates=0, new_alert_ids=[])
    muted = await mutes.active(session, now=now)
    rows = [
        {
            "id": new_id(),
            "agent_id": agent_id,
            "fingerprint": alert.fingerprint,
            "kind": alert.kind.value,
            "severity": alert.severity,
            "severity_rank": severity_rank(alert.severity),
            "title": alert.title,
            "rule_id": alert.rule_id,
            "source_event": alert.source_event,
            "hostname": alert.hostname,
            "occurred_at": alert.occurred_at,
            "received_at": now,
            "hour_bucket": int(alert.occurred_at.timestamp()) // 3600,
            "tags": alert.tags,
            "mitre_tactics": alert.mitre_tactics,
            "mitre_techniques": alert.mitre_techniques,
            "fields": alert.fields,
            "status": (
                AlertStatus.MUTED.value
                if mutes.matches(muted, rule_id=alert.rule_id, hostname=alert.hostname)
                else AlertStatus.OPEN.value
            ),
        }
        for alert in unique.values()
    ]
    insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
    statement = insert(Alert).values(rows).on_conflict_do_nothing(index_elements=["agent_id", "fingerprint"]).returning(Alert.id)
    inserted = list(await session.scalars(statement))
    return StoreResult(stored=len(inserted), duplicates=len(batch.alerts) - len(inserted), new_alert_ids=sorted(inserted))


async def raise_offline_alerts(session: AsyncSession, *, now: datetime, offline_after: timedelta, dialect: str) -> int:
    """Open one alert for each agent that has just gone quiet. Returns how many were new.

    The fingerprint is the moment the agent was last heard from, so repeated
    passes, and passes from other worker processes, add nothing.
    """
    silent = list(
        await session.scalars(
            select(Agent).where(
                Agent.enabled.is_(True),
                Agent.last_seen_at.is_not(None),
                Agent.last_seen_at < now - offline_after,
                Agent.last_seen_at > now - offline_after - OFFLINE_ALERT_WINDOW,
            )
        )
    )
    if not silent:
        return 0
    muted = await mutes.active(session, now=now)
    rows = []
    for agent in silent:
        assert agent.last_seen_at is not None  # guaranteed by the query
        hostname = agent.hostname or agent.name
        rows.append(
            {
                "id": new_id(),
                "agent_id": agent.id,
                "fingerprint": hashlib.sha256(f"offline:{agent.last_seen_at.isoformat()}".encode()).hexdigest(),
                "kind": AlertKind.AGENT_OFFLINE.value,
                "severity": "error",
                "severity_rank": severity_rank("error"),
                "title": f"Agent {agent.name} stopped reporting",
                "rule_id": None,
                "source_event": None,
                "hostname": hostname,
                "occurred_at": now,
                "received_at": now,
                "hour_bucket": int(now.timestamp()) // 3600,
                "tags": [],
                "mitre_tactics": [],
                "mitre_techniques": [],
                "fields": {"agent": agent.name, "last_seen_at": agent.last_seen_at.isoformat()},
                "status": (
                    AlertStatus.MUTED.value if mutes.matches(muted, rule_id=None, hostname=hostname) else AlertStatus.OPEN.value
                ),
            }
        )
    insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
    statement = insert(Alert).values(rows).on_conflict_do_nothing(index_elements=["agent_id", "fingerprint"]).returning(Alert.id)
    return len(list(await session.scalars(statement)))


async def resolve_offline_alerts(session: AsyncSession, *, agent_id: uuid.UUID, now: datetime) -> None:
    """Close an agent's open "stopped reporting" alerts once it is heard from again."""
    await session.execute(
        update(Alert)
        .where(
            Alert.agent_id == agent_id,
            Alert.kind == AlertKind.AGENT_OFFLINE.value,
            Alert.status.in_([AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value]),
        )
        .values(
            status=AlertStatus.RESOLVED.value,
            status_changed_at=now,
            status_changed_by="system",
            note="The agent is reporting again.",
        )
    )
