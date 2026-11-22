"""Commands for agents: queued from the console, fetched by long-poll.

An agent that runs with ``TRACEGUARD_COMMAND_URL`` polls for its commands,
runs each at most once, and reports the result. The agent has the last
word: it refuses actions it is not configured to accept, and applies
responses only as its response mode allows.
"""

import asyncio
import ipaddress
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import DomainError
from .models import Agent, AgentCommand, CommandAction, CommandStatus

# A command the agent has not fetched by then is not sent at all.
COMMAND_LIFETIME = timedelta(minutes=10)
# A command the agent fetched but has not answered is given up on this long
# after it expired; a result that still arrives is recorded anyway.
RESULT_GRACE = timedelta(hours=1)
MAX_TARGET_LENGTH = 200
# The detail of a delivered command the manager gave up on; only these take a late result.
NO_RESULT_DETAIL = "The agent fetched it but never reported a result."
MAX_WAITERS_PER_AGENT = 4
# A delivered command with no result by then is sent again; the agent
# answers a repeat with the result it already has.
REDELIVER_AFTER = timedelta(seconds=90)
MAX_PER_POLL = 16
MAX_OUTSTANDING = 50
MIN_DURATION = timedelta(minutes=1)
MAX_DURATION = timedelta(hours=24)
MAX_POLL_WAIT = 25
MAX_DETAIL_LENGTH = 512
RESPONSE_ACTIONS = (CommandAction.BLOCK_PEER.value, CommandAction.FREEZE_CGROUP.value)
RESULT_STATUSES = frozenset({CommandStatus.DONE, CommandStatus.FAILED, CommandStatus.REFUSED, CommandStatus.EXPIRED})
LABELS = {
    CommandAction.BLOCK_PEER.value: "Block peer",
    CommandAction.FREEZE_CGROUP.value: "Freeze cgroup",
    CommandAction.LIFT_RESPONSE.value: "Lift response",
    CommandAction.REFRESH_POLICY.value: "Refresh policy",
}
DURATIONS: dict[str, timedelta] = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "4h": timedelta(hours=4),
    "24h": timedelta(hours=24),
}
DURATION_LABELS = {"15m": "15 minutes", "1h": "1 hour", "4h": "4 hours", "24h": "24 hours"}


class CommandError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


class Bell:
    """Wakes this process's long-polls when a command is queued.

    Polls also re-check the database every few seconds, so a command queued
    by another worker process is still delivered promptly.
    """

    def __init__(self) -> None:
        self._waiters: defaultdict[uuid.UUID, set[asyncio.Event]] = defaultdict(set)
        self._polls: defaultdict[uuid.UUID, int] = defaultdict(int)

    def acquire(self, agent_id: uuid.UUID) -> bool:
        """Reserve one of this agent's poll slots for the whole request, or refuse."""
        if self._polls[agent_id] >= MAX_WAITERS_PER_AGENT:
            return False
        self._polls[agent_id] += 1
        return True

    def release(self, agent_id: uuid.UUID) -> None:
        self._polls[agent_id] -= 1
        if self._polls[agent_id] <= 0:
            del self._polls[agent_id]

    def ring(self, agent_id: uuid.UUID) -> None:
        for event in self._waiters.get(agent_id, ()):
            event.set()

    async def wait(self, agent_id: uuid.UUID, seconds: float, *, stop: asyncio.Event | None = None) -> None:
        """Wait until a command is queued for the agent, ``stop`` is set, or ``seconds`` pass."""
        event = asyncio.Event()
        self._waiters[agent_id].add(event)
        waits = [asyncio.ensure_future(event.wait())]
        if stop is not None:
            waits.append(asyncio.ensure_future(stop.wait()))
        try:
            await asyncio.wait(waits, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pending in waits:
                pending.cancel()
            waiters = self._waiters.get(agent_id)
            if waiters is not None:
                waiters.discard(event)
                if not waiters:
                    self._waiters.pop(agent_id, None)


def _validate(action: str, target: str, response_action: str | None, duration: timedelta | None) -> tuple[str, int | None]:
    """Check a command and return its normalised target and duration in seconds."""
    target = target.strip()
    if len(target) > MAX_TARGET_LENGTH:
        raise CommandError(f"Targets are limited to {MAX_TARGET_LENGTH} characters.")
    match action:
        case CommandAction.BLOCK_PEER.value:
            try:
                address = ipaddress.ip_address(target)
            except ValueError:
                raise CommandError("Enter the peer's IP address.") from None
            if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
                raise CommandError("Enter the address without an IPv6 zone.")
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                raise CommandError("Loopback, unspecified and multicast addresses cannot be blocked.")
            target = str(address)
        case CommandAction.FREEZE_CGROUP.value:
            if not (target.isascii() and target.isdigit() and len(target) <= 20) or not 0 < int(target) < 2**64:
                raise CommandError("Enter the kernel cgroup ID, a positive number.")
            target = str(int(target))
        case CommandAction.LIFT_RESPONSE.value:
            if response_action not in RESPONSE_ACTIONS:
                raise CommandError("Choose which kind of response to lift.")
            if not target or len(target) > 200:
                raise CommandError("Say which response to lift.")
            return target, None
        case CommandAction.REFRESH_POLICY.value:
            return "", None
        case _:
            raise CommandError("Unknown command.")
    if duration is None or not MIN_DURATION <= duration <= MAX_DURATION:
        raise CommandError("Choose how long the response lasts, from 1 minute to 24 hours.")
    return target, int(duration.total_seconds())


async def queue(
    session: AsyncSession,
    *,
    agent: Agent,
    action: str,
    target: str = "",
    response_action: str | None = None,
    duration: timedelta | None = None,
    alert_id: uuid.UUID | None = None,
    actor: str,
    now: datetime,
) -> AgentCommand:
    if not agent.enabled:
        raise CommandError("This agent is disabled.")
    target, seconds = _validate(action, target, response_action, duration)
    # Take the agent row's write lock first, so two admins queueing at once
    # are counted one after the other, on SQLite as on PostgreSQL.
    await session.execute(update(Agent).where(Agent.id == agent.id).values(id=Agent.id))
    outstanding = await session.scalar(
        select(AgentCommand.id)
        .where(
            AgentCommand.agent_id == agent.id,
            AgentCommand.status.in_([CommandStatus.QUEUED.value, CommandStatus.DELIVERED.value]),
        )
        .offset(MAX_OUTSTANDING - 1)
        .limit(1)
    )
    if outstanding is not None:
        raise CommandError(f"This agent already has {MAX_OUTSTANDING} commands waiting.")
    command = AgentCommand(
        agent_id=agent.id,
        action=action,
        target=target,
        response_action=response_action if action == CommandAction.LIFT_RESPONSE.value else None,
        duration_seconds=seconds,
        alert_id=alert_id,
        status=CommandStatus.QUEUED.value,
        created_by=actor,
        created_at=now,
        expires_at=now + COMMAND_LIFETIME,
    )
    session.add(command)
    await session.flush()
    return command


async def expire_stale(session: AsyncSession, *, now: datetime) -> None:
    """Close commands that will never get a result.

    A queued command the agent never fetched expires with its deadline. One
    it fetched is given longer, because the agent may still be reporting.
    """
    await session.execute(
        update(AgentCommand)
        .where(AgentCommand.status == CommandStatus.QUEUED.value, AgentCommand.expires_at <= now)
        .values(status=CommandStatus.EXPIRED.value, completed_at=now, detail="The agent did not pick it up in time.")
    )
    await session.execute(
        update(AgentCommand)
        .where(AgentCommand.status == CommandStatus.DELIVERED.value, AgentCommand.expires_at <= now - RESULT_GRACE)
        .values(status=CommandStatus.EXPIRED.value, completed_at=now, detail=NO_RESULT_DETAIL)
    )


def _due(agent_id: uuid.UUID, now: datetime) -> Any:
    return (
        AgentCommand.agent_id == agent_id,
        AgentCommand.expires_at > now,
        (AgentCommand.status == CommandStatus.QUEUED.value)
        | ((AgentCommand.status == CommandStatus.DELIVERED.value) & (AgentCommand.delivered_at <= now - REDELIVER_AFTER)),
    )


async def has_due(session: AsyncSession, *, agent_id: uuid.UUID, now: datetime) -> bool:
    """Whether any command is waiting to be handed to the agent. A plain read."""
    return await session.scalar(select(AgentCommand.id).where(*_due(agent_id, now)).limit(1)) is not None


async def take(session: AsyncSession, *, agent_id: uuid.UUID, now: datetime, token_hash: str | None = None) -> list[AgentCommand]:
    """Commands to hand to the agent now, marked delivered.

    An idle poll only reads. Claiming is a conditional update, so a command
    cancelled or answered meanwhile is never handed over or set back to
    delivered, on SQLite as on PostgreSQL. With ``token_hash``, the same
    statement checks the agent is still enabled with that token, so a
    rotation or disable that commits first stops the claim.
    """
    candidates = list(
        await session.scalars(
            select(AgentCommand.id).where(*_due(agent_id, now)).order_by(AgentCommand.created_at).limit(MAX_PER_POLL)
        )
    )
    if not candidates:
        return []
    conditions = [AgentCommand.id.in_(candidates), *_due(agent_id, now)]
    if token_hash is not None:
        conditions.append(
            AgentCommand.agent_id.in_(
                select(Agent.id).where(Agent.id == agent_id, Agent.enabled.is_(True), Agent.token_hash == token_hash)
            )
        )
    claimed = set(
        await session.scalars(
            update(AgentCommand)
            .where(*conditions)
            .values(status=CommandStatus.DELIVERED.value, delivered_at=now)
            .returning(AgentCommand.id)
        )
    )
    if not claimed:
        return []
    return list(
        await session.scalars(
            select(AgentCommand)
            .where(AgentCommand.id.in_(claimed))
            .order_by(AgentCommand.created_at)
            .execution_options(populate_existing=True)
        )
    )


def wire(command: AgentCommand) -> dict[str, Any]:
    """The command as the agent reads it."""
    payload: dict[str, Any] = {
        "id": str(command.id),
        "action": command.action,
        "target": command.target,
        "expires_at": command.expires_at.isoformat(),
    }
    if command.response_action:
        payload["response_action"] = command.response_action
    if command.duration_seconds:
        payload["duration_seconds"] = command.duration_seconds
    return payload


async def record_result(
    session: AsyncSession, *, agent_id: uuid.UUID, command_id: uuid.UUID, status: str, detail: str | None, now: datetime
) -> AgentCommand | None:
    """Store an agent's result. Returns None for a command that is not this agent's."""
    command = await session.get(AgentCommand, command_id)
    if command is None or command.agent_id != agent_id:
        return None
    if status not in RESULT_STATUSES:
        raise CommandError("Unknown result status.")
    # Conditional, like cancel and take: only a command the agent was given
    # takes a result, and one the manager gave up on after delivering it
    # still takes the agent's, which says what really happened. A repeat
    # report, or one racing a cancel, changes nothing.
    await session.execute(
        update(AgentCommand)
        .where(
            AgentCommand.id == command_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.delivered_at.is_not(None),
            (AgentCommand.status == CommandStatus.DELIVERED.value)
            | ((AgentCommand.status == CommandStatus.EXPIRED.value) & (AgentCommand.detail == NO_RESULT_DETAIL)),
        )
        .values(status=status, detail=(detail or "")[:MAX_DETAIL_LENGTH] or None, completed_at=now)
    )
    await session.refresh(command)
    return command


async def cancel(session: AsyncSession, command: AgentCommand, *, now: datetime, actor: str) -> None:
    """Cancel a command the agent has not fetched. Racing a poll, only one wins."""
    cancelled = await session.scalar(
        update(AgentCommand)
        .where(AgentCommand.id == command.id, AgentCommand.status == CommandStatus.QUEUED.value)
        .values(status=CommandStatus.CANCELLED.value, completed_at=now, detail=f"Cancelled by {actor}.")
        .returning(AgentCommand.id)
    )
    if cancelled is None:
        raise CommandError("Only a command the agent has not fetched yet can be cancelled.")
    await session.refresh(command)


async def get(session: AsyncSession, command_id: uuid.UUID) -> AgentCommand | None:
    return await session.get(AgentCommand, command_id)


async def recent(session: AsyncSession, *, agent_id: uuid.UUID, limit: int = 20) -> list[AgentCommand]:
    return list(
        await session.scalars(
            select(AgentCommand).where(AgentCommand.agent_id == agent_id).order_by(AgentCommand.created_at.desc()).limit(limit)
        )
    )


async def outstanding(session: AsyncSession, *, agent_id: uuid.UUID) -> list[AgentCommand]:
    """Every command still waiting for the agent, oldest first: at most MAX_OUTSTANDING."""
    return list(
        await session.scalars(
            select(AgentCommand)
            .where(
                AgentCommand.agent_id == agent_id,
                AgentCommand.status.in_([CommandStatus.QUEUED.value, CommandStatus.DELIVERED.value]),
            )
            .order_by(AgentCommand.created_at)
            .limit(MAX_OUTSTANDING)
        )
    )


async def for_alert(session: AsyncSession, *, alert_id: uuid.UUID) -> list[AgentCommand]:
    return list(
        await session.scalars(
            select(AgentCommand).where(AgentCommand.alert_id == alert_id).order_by(AgentCommand.created_at.desc()).limit(20)
        )
    )


def describe(command: AgentCommand) -> str:
    label = LABELS.get(command.action, command.action)
    match command.action:
        case CommandAction.BLOCK_PEER.value | CommandAction.FREEZE_CGROUP.value:
            hours = (command.duration_seconds or 0) / 3600
            span = f"{hours:g} h" if hours >= 1 else f"{(command.duration_seconds or 0) // 60} min"
            return f"{label} {command.target} for {span}"
        case CommandAction.LIFT_RESPONSE.value:
            kind = LABELS.get(command.response_action or "", command.response_action or "")
            return f"{label}: {kind.lower()} {command.target}"
        case _:
            return label
