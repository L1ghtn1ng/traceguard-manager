"""Agent enrolment, heartbeat tracking, and storage of ingested batches."""

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from . import security
from .errors import DomainError
from .ingest import ParsedBatch, severity_rank
from .models import Agent, Alert, AlertStatus, new_id


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


def describe_fleet(
    agents: list[Agent], *, now: datetime, offline_after: timedelta
) -> tuple[list[AgentView], FleetSummary]:
    baseline = baseline_policy(agents)
    views = [
        AgentView(
            agent=agent,
            status=agent_status(agent, now=now, offline_after=offline_after),
            drifted=bool(
                agent.enabled and agent.policy_sha256 and baseline and agent.policy_sha256 != baseline
            ),
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
    return await session.scalar(
        select(Agent).where(Agent.token_hash == security.hash_token(token), Agent.enabled.is_(True))
    )


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
            "status": AlertStatus.OPEN.value,
        }
        for alert in unique.values()
    ]
    insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
    statement = (
        insert(Alert)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["agent_id", "fingerprint"])
        .returning(Alert.id)
    )
    inserted = list(await session.scalars(statement))
    return StoreResult(
        stored=len(inserted), duplicates=len(batch.alerts) - len(inserted), new_alert_ids=sorted(inserted)
    )
