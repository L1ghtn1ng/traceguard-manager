"""Agent enrolment, heartbeat tracking, and storage of ingested batches."""

import hashlib
import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from . import mutes, security
from .errors import DomainError
from .ingest import MAX_CLOCK_SKEW, Heartbeat, ParsedBatch, Stopping, severity_rank
from .models import Agent, Alert, AlertKind, AlertStatus, new_id

PAGE_SIZE = 50
MAX_PAGE = 2_000
MAX_TAGS = 16
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}")
STATUSES: tuple[str, ...] = ("online", "degraded", "stopped", "offline", "pending", "disabled")
SORTS: tuple[str, ...] = ("name", "status", "seen", "host")
# Worst first, so sorting by status puts what needs attention at the top.
_STATUS_ORDER = {"offline": 0, "stopped": 1, "degraded": 2, "pending": 3, "online": 4, "disabled": 5}
# An agent that has been silent for longer than this is old news, not a new outage.
OFFLINE_ALERT_WINDOW = timedelta(days=1)
# How many stop records each agent remembers, to recognise replays.
MAX_SEEN_STOPS = 64
# Remembered stops: settled ones (s:) and rejected ones (r:) are capped apart,
# so neither kind can push the other out.
MAX_SETTLED_STOPS = 48
MAX_REJECTED_STOPS = MAX_SEEN_STOPS - MAX_SETTLED_STOPS


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
    stopped: int
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
    if agent.stopped_at is not None:
        # It said it was stopping and has sent nothing newer.
        return "stopped"
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
        stopped=counts["stopped"],
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
    """Replace the agent's token; the previous one stops working immediately.

    It also forgets the agent's run counter, so an agent whose state was
    restored from a backup, and counts from an older number, is heard again.
    """
    agent.run_seq = None
    agent.install_ids = []
    agent.stop_run_seq = None
    # stop_run_id is kept: it names the stopped process, not its place in
    # the count, and later processes are told apart from it by it.
    agent.heartbeat_run_seq = None
    agent.heartbeat_install_id = None
    agent.heartbeat_run_id = None
    agent.pending_install_id = None
    agent.pending_run_id = None
    agent.pending_uptime = None
    agent.pending_seen_at = None
    agent.live_run_id = None
    agent.lower_run_ids = []
    agent.retired_run_ids = []
    token = security.new_agent_token()
    agent.token_hash = security.hash_token(token)
    agent.token_prefix = security.token_display_prefix(token)
    agent.token_rotated_at = now
    return token


async def agent_for_token(session: AsyncSession, token: str) -> Agent | None:
    if not token.startswith(security.AGENT_TOKEN_PREFIX) or len(token) > 128:
        return None
    return await session.scalar(select(Agent).where(Agent.token_hash == security.hash_token(token), Agent.enabled.is_(True)))


# How close to the receive time a heartbeat's stamp must be for its uptime
# to be read as of now: a live batch is sent within seconds, a held-up
# request carries its old stamp.
SENT_JUST_NOW = timedelta(seconds=60)

# Retired processes remembered per agent.
MAX_RETIRED_RUNS = 16

# The TraceGuard-Delivery header's values.
DELIVERY_LIVE = "live"
DELIVERY_REPLAY = "replay"

# Install IDs remembered per agent, so a replay from a replaced install is
# recognised as old.
MAX_INSTALL_IDS = 8


class _RunOrder:
    """Orders an agent's runs by install, then by the install's run counter.

    A record's key is None when it cannot be ordered: it carries no counter,
    or comes from an install not seen before that no live heartbeat vouches
    for. Clocks then decide, as for agents that do not count their runs.
    """

    def __init__(self, agent: Agent | None, *, adopt: str | None = None) -> None:
        self.installs: list[str] = list(agent.install_ids) if agent is not None else []
        self.run_seq = agent.run_seq if agent is not None else None
        # An install not seen before, introduced by a live heartbeat: newer
        # than every known one, its counter started again.
        self.adopt = adopt
        # Column values that move the order back, when the running agent says so.
        self.rebase: dict[str, object] = {}

    @property
    def current(self) -> tuple[int, int] | None:
        return None if self.run_seq is None else (max(len(self.installs) - 1, 0), self.run_seq)

    def key(self, install: str | None, run_seq: int | None) -> tuple[int, int] | None:
        if run_seq is None:
            return None
        if install is None:
            return (max(len(self.installs) - 1, 0), run_seq)
        if install in self.installs:
            return (self.installs.index(install), run_seq)
        if not self.installs and self.run_seq is None:
            # Nothing is known yet, so nothing can be replayed over.
            return (0, run_seq)
        if install == self.adopt:
            return (max(len(self.installs), 1), run_seq)
        return None

    def rebased(self, install: str | None, run_seq: int) -> _RunOrder:
        """The order with ``install`` current at ``run_seq``, as the running agent reports."""
        moved = _RunOrder(None, adopt=self.adopt)
        moved.installs = [*(known for known in self.installs if known != install), install] if install else list(self.installs)
        moved.run_seq = run_seq
        moved.rebase = {"install_ids": moved.installs[-MAX_INSTALL_IDS:], "run_seq": run_seq}
        return moved

    def advance(self, records: list[tuple[str | None, int | None]]) -> dict[str, object]:
        """The column values that record the newest run among ``records``."""
        values = dict(self.rebase)
        newest: tuple[tuple[int, int], str | None] | None = None
        for install, run_seq in records:
            key = self.key(install, run_seq)
            if key is not None and (newest is None or key > newest[0]):
                newest = (key, install)
        if newest is None:
            return values
        key, install = newest
        if install is not None and install not in self.installs:
            # A new install's counter starts again.
            return values | {"install_ids": [*self.installs, install][-MAX_INSTALL_IDS:], "run_seq": key[1]}
        if self.current is None or key > self.current:
            return values | {"run_seq": key[1]}
        return values


# How long, by the manager's clock, a clamped heartbeat's install must keep
# reporting before its uptime counts as proof that it is live, and how far
# the uptime may drift from that clock.
PENDING_INSTALL_PROOF = timedelta(seconds=60)
PENDING_INSTALL_DRIFT = timedelta(seconds=30)


def _uptime_tracks_clock(
    agent: Agent, install: str, run_id: str | None, uptime: int, now: datetime, *, span: timedelta = PENDING_INSTALL_PROOF
) -> bool:
    """Whether this run reported before, long enough ago, with an uptime that grew as the manager's clock did."""
    if (
        agent.pending_install_id != install
        or agent.pending_run_id != run_id
        or agent.pending_uptime is None
        or agent.pending_seen_at is None
    ):
        return False
    # In whole seconds, so no uptime the parser accepts can overflow.
    elapsed = (now - agent.pending_seen_at).total_seconds()
    grown = uptime - agent.pending_uptime
    drift = max(PENDING_INSTALL_DRIFT.total_seconds(), elapsed / 10)
    return elapsed >= span.total_seconds() and abs(grown - elapsed) <= drift


def _pending_holds(
    agent: Agent, install: str, run_id: str | None, uptime: int, now: datetime, *, span: timedelta = PENDING_INSTALL_PROOF
) -> bool:
    """Whether the stored first sighting of this run still stands.

    It does while the same process is seen again too soon, or with a lower
    uptime (an older sample, replayed late). Once the proof's span has passed
    without the uptime keeping step, the next sample starts the proof again.
    """
    if (
        agent.pending_install_id != install
        or agent.pending_run_id != run_id
        or agent.pending_uptime is None
        or agent.pending_seen_at is None
    ):
        return False
    return uptime < agent.pending_uptime or now - agent.pending_seen_at < span


def _may_claim_pending(agent: Agent, heartbeat: Heartbeat, now: datetime, *, span: timedelta = PENDING_INSTALL_PROOF) -> bool:
    """Whether this heartbeat may start a proof: the slot is free, its own, or held by a claim that has stalled.

    One slot serves every proof, so a single sample from another process
    must not displace one under way.
    """
    assert heartbeat.install_id is not None and heartbeat.uptime_seconds is not None
    if _pending_holds(agent, heartbeat.install_id, heartbeat.run_id, heartbeat.uptime_seconds, now, span=span):
        return False
    if agent.pending_run_id is None or agent.pending_seen_at is None or agent.pending_run_id == heartbeat.run_id:
        return True
    # Longer than the longest proof, so none under way is cut short.
    return now - agent.pending_seen_at >= 4 * PENDING_INSTALL_PROOF


def _pending(heartbeat: Heartbeat, now: datetime) -> dict[str, object]:
    return {
        "pending_install_id": heartbeat.install_id,
        "pending_run_id": heartbeat.run_id,
        "pending_uptime": heartbeat.uptime_seconds,
        "pending_seen_at": now,
    }


_NO_PENDING: dict[str, object] = {
    "pending_install_id": None,
    "pending_run_id": None,
    "pending_uptime": None,
    "pending_seen_at": None,
}


def _from_before_the_stop(
    agent: Agent,
    heartbeat: Heartbeat | None,
    batch: ParsedBatch,
    now: datetime,
    *,
    older_run: bool = False,
    seen: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """Whether a live batch is an earlier process's, held up on the way: stamped before the stop.

    Its uptime overrides the stamp when it shows the process started after
    the stop arrived, as after a clock stepped back.
    """
    assert agent.stopped_at is not None
    if heartbeat is not None:
        if (
            heartbeat.uptime_seconds is not None
            and agent.stop_received_at is not None
            and heartbeat.uptime_seconds < (now - agent.stop_received_at).total_seconds()
            # The uptime is as of sending: only a heartbeat sent just now
            # (its stamp current) can show a start after the stop, as after
            # a clock stepped back; a held-up one only seems to. A counted
            # heartbeat of an older run is a predecessor's, whatever it shows.
            and not older_run
            and heartbeat.own_time
            and abs(now - heartbeat.at) <= SENT_JUST_NOW
        ):
            return False
        return heartbeat.own_time and heartbeat.at <= agent.stopped_at
    if batch.latest_at is None:
        # Only stops: their own stamps say when the sender was last running.
        # A stamp replaced by the receive time says nothing, and a stop seen
        # before (a retry) is no new sign of life.
        latest_stop = max((stop.at for stop in batch.stops if stop.own_time and stop.fingerprint not in seen), default=None)
        return latest_stop is None or latest_stop <= agent.stopped_at
    return batch.latest_at <= agent.stopped_at


async def alerts_in_last_hour(session: AsyncSession, *, agent_id: uuid.UUID, now: datetime) -> int:
    """How many alerts this agent stored in the past hour (alert ids are UUIDv7, so time-ordered)."""
    floor = uuid.UUID(int=(int((now - timedelta(hours=1)).timestamp() * 1000) & ((1 << 48) - 1)) << 80)
    return await session.scalar(select(func.count()).select_from(Alert).where(Alert.agent_id == agent_id, Alert.id >= floor)) or 0


async def store_batch(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    batch: ParsedBatch,
    now: datetime,
    dialect: str,
    delivery: str | None = None,
    sender_run: str | None = None,
) -> StoreResult:
    """Persist a parsed batch for one agent in a single transaction.

    ``delivery`` is how the agent says it sent the batch (TraceGuard 1.9):
    "live" holds only records of the process running now, "replay" was
    resent from the spool and may be from any earlier run, and None is an
    agent that does not say, judged by counters and clocks alone.
    ``sender_run`` is the sending process's run ID: a replay of its own
    records is as current as a live batch.
    """
    values: dict[str, object] = {
        "last_seen_at": now,
        "events_received": Agent.events_received + batch.received,
    }
    if batch.hostname is not None:
        values["hostname"] = batch.hostname
    if batch.invalid:
        values |= {"invalid_records": Agent.invalid_records + batch.invalid, "last_invalid_at": now}
    # The UPDATE takes the agent row's write lock first, so the run decisions
    # below read state no concurrent batch for this agent can change.
    await session.execute(update(Agent).where(Agent.id == agent_id).values(**values))
    before = await session.get(Agent, agent_id, populate_existing=True)
    # Stops already received, by fingerprint, before this batch.
    seen_before = {entry.split(":", 1)[-1] for entry in before.seen_stops} if before is not None else set()
    heartbeat = batch.heartbeat
    if delivery == DELIVERY_LIVE and sender_run is None and heartbeat is not None:
        # A live batch is the running process's, so its heartbeat names it.
        sender_run = heartbeat.run_id
    # Processes since replaced by a newer live reporter: older for certain,
    # so nothing they sent, live or replayed, is current any more.
    retired = set(before.retired_run_ids) if before is not None else set()
    # Retirement can be wrong (a dead process's request held up on the way
    # can retire the running one), so a retired process that keeps reporting
    # live, its uptime growing with the manager's clock, comes back.
    revived = False
    revive_pending: dict[str, object] = {}
    if (
        before is not None
        and sender_run in retired
        and delivery == DELIVERY_LIVE
        and heartbeat is not None
        and heartbeat.run_id == sender_run
        and heartbeat.install_id
        and heartbeat.run_seq is not None
        and heartbeat.uptime_seconds is not None
    ):
        # Over a recorded stop, held-up requests of a dead process spaced like
        # a live one could pass the proof: without a fresh stamp to vouch for
        # the process, the proof must run for longer.
        fresh_stamp = heartbeat.own_time and abs(now - heartbeat.at) <= MAX_CLOCK_SKEW
        span = PENDING_INSTALL_PROOF if before.stopped_at is None or fresh_stamp else 3 * PENDING_INSTALL_PROOF
        if _uptime_tracks_clock(before, heartbeat.install_id, heartbeat.run_id, heartbeat.uptime_seconds, now, span=span):
            revived = True
            retired.discard(sender_run)
        elif _may_claim_pending(before, heartbeat, now, span=span):
            revive_pending = _pending(heartbeat, now)
    from_retired = sender_run is not None and sender_run in retired
    if from_retired:
        delivery = DELIVERY_REPLAY
    # The running process resending what it spooled itself: as current as a
    # live batch, but no newer than what it already sent live.
    promoted = bool(delivery == DELIVERY_REPLAY and heartbeat is not None and heartbeat.run_id and heartbeat.run_id == sender_run)
    if promoted:
        delivery = DELIVERY_LIVE
    replayed = delivery == DELIVERY_REPLAY
    # A heartbeat the running agent sent itself: the current process,
    # whatever its count or clock says.
    current_process = delivery == DELIVERY_LIVE and heartbeat is not None
    # Only a heartbeat stamped by its own clock no earlier than the stored
    # one introduces an install: a replayed spool from an install never seen
    # must not take over. Liveness is not required, so a host whose clock is
    # slow is still heard.
    adopt = (
        heartbeat.install_id
        if heartbeat is not None
        and not replayed
        and (current_process or heartbeat.own_time)
        and heartbeat.install_id
        and heartbeat.run_seq is not None
        and (current_process or before is None or before.last_heartbeat_at is None or heartbeat.at >= before.last_heartbeat_at)
        else None
    )
    pending_values: dict[str, object] = dict(revive_pending)
    if (
        adopt is None
        and delivery is None
        and heartbeat is not None
        and not heartbeat.own_time
        and heartbeat.install_id
        and heartbeat.run_seq is not None
        and heartbeat.uptime_seconds is not None
        and before is not None
        and heartbeat.install_id not in before.install_ids
        and (before.install_ids or before.run_seq is not None)
    ):
        # A clock far ahead hides the stamps, so a live process must show
        # itself another way: its uptime grows with the manager's clock
        # between two heartbeats, where a replayed spool arrives in a burst.
        if _uptime_tracks_clock(before, heartbeat.install_id, heartbeat.run_id, heartbeat.uptime_seconds, now):
            adopt = heartbeat.install_id
        elif _may_claim_pending(before, heartbeat, now):
            pending_values = _pending(heartbeat, now)
    if adopt is not None and before is not None and before.pending_install_id is not None and adopt not in before.install_ids:
        # A new install is now known; a proof under way for a known one goes on.
        pending_values = dict(_NO_PENDING)
    runs = _RunOrder(before, adopt=adopt)
    rebased = False
    current_key = runs.current
    heartbeat_key = runs.key(heartbeat.install_id, heartbeat.run_seq) if heartbeat is not None else None
    if revived and heartbeat is not None and heartbeat.run_seq is not None:
        # The revived process is the running agent: the order is its own.
        if heartbeat_key != current_key:
            runs = runs.rebased(heartbeat.install_id, heartbeat.run_seq)
            current_key = runs.current
            heartbeat_key = runs.key(heartbeat.install_id, heartbeat.run_seq)
        pending_values = dict(_NO_PENDING)
        rebased = True
    if (
        current_process
        and heartbeat is not None
        and heartbeat.run_seq is not None
        and heartbeat.install_id
        and heartbeat.uptime_seconds is not None
        and heartbeat_key is not None
        and current_key is not None
        and heartbeat_key < current_key
        and before is not None
        # The process the current one replaced, or the one that stopped, is
        # older for certain: a late request of it proves no rollback.
        and heartbeat.run_id not in retired | {before.stop_run_id}
    ):
        # The running agent counts lower than the manager remembers: its
        # counter went back, as when its state is restored from a backup, or
        # an old run's request was held up on the way. Only a process that
        # keeps reporting, its uptime growing with the manager's clock, is
        # taken as the counter going back.
        if _uptime_tracks_clock(before, heartbeat.install_id, heartbeat.run_id, heartbeat.uptime_seconds, now):
            runs = runs.rebased(heartbeat.install_id, heartbeat.run_seq)
            current_key = runs.current
            heartbeat_key = runs.key(heartbeat.install_id, heartbeat.run_seq)
            pending_values = dict(_NO_PENDING)
            rebased = True
        elif _may_claim_pending(before, heartbeat, now):
            pending_values = _pending(heartbeat, now)
    # Whatever is replayed was recorded before the process now replaying it
    # started, so once that process has reported its run live, nothing it
    # replays is newer than that run: what counts higher is from before the
    # counter went back, and is stale. Another sender is a newer process,
    # whose spool may hold runs in between.
    capped = (
        replayed
        and current_key is not None
        and before is not None
        and sender_run is not None
        # Or the process whose lower count awaits proof: it cannot hold
        # genuine runs above the stored one either.
        and sender_run in {before.live_run_id, before.pending_run_id, *before.lower_run_ids}
    )

    def stale_replay(key: tuple[int, int] | None) -> bool:
        return capped and key is not None and current_key is not None and key > current_key

    # A heartbeat of an older run than the one the agent already reported is
    # a late replay from a process that has gone: it changes nothing.
    # A heartbeat of the replaced process is older for certain; so is one the
    # sender replays from another process once the sender's own is stored.
    inherited = bool(
        heartbeat is not None
        and before is not None
        and heartbeat.run_id
        and (
            heartbeat.run_id in retired
            or (replayed and sender_run is not None and heartbeat.run_id != sender_run and before.heartbeat_run_id == sender_run)
        )
    )
    older_run = (
        inherited
        or from_retired
        or stale_replay(heartbeat_key)
        or (heartbeat_key is not None and current_key is not None and heartbeat_key < current_key)
    )
    # A newer run, or a new install of the agent: a new process, whatever its clock says.
    newer_run = heartbeat_key is not None and current_key is not None and heartbeat_key > current_key
    # The newest run known once this batch is counted. A stop from a run
    # older than it is stale, even beside a newer heartbeat in one batch.
    newest_known = max((key for key in (current_key, None if older_run else heartbeat_key) if key is not None), default=None)
    stale_stops: set[str] = set()
    # Stops of a run newer than the stored one, and not followed by a
    # heartbeat of their own run in this batch, by their run's key.
    newer_stops: dict[str, tuple[int, int]] = {}
    # Stops whose run could be ordered; only those are kept as numbered.
    ordered_stops: set[str] = set()
    for stop in batch.stops:
        stop_key = runs.key(stop.install_id, stop.run_seq)
        if stop_key is None:
            continue
        ordered_stops.add(stop.fingerprint)
        replaced = from_retired or bool(stop.run_id and stop.run_id in retired)
        if replaced or stale_replay(stop_key) or (newest_known is not None and stop_key < newest_known):
            stale_stops.add(stop.fingerprint)
        elif (
            current_key is not None
            and stop_key > current_key
            and (heartbeat is None or heartbeat_key != stop_key or heartbeat.at <= stop.at)
        ):
            newer_stops[stop.fingerprint] = stop_key
    restarted = bool(
        heartbeat is not None
        and not older_run
        and (
            newer_run
            # The running agent counts from an older number now: a new process.
            or rebased
            # The running agent's own heartbeat, from another process than
            # the one that stopped.
            or (
                current_process
                and before is not None
                and before.stopped_at is not None
                and bool(heartbeat.run_id)
                and before.stop_run_id is not None
                and heartbeat.run_id != before.stop_run_id
                # Unless counters show a different run, it could be an earlier
                # process's request held up on the way (no counter, or one a
                # rollback repeated): it must be stamped after the stop,
                # unless its clock is too far ahead to say (a wrong "back"
                # is caught by the offline alert; a wrong "stopped" is not).
                and (
                    (heartbeat_key is not None and heartbeat_key != current_key)
                    or not heartbeat.own_time
                    or heartbeat.at > before.stopped_at
                )
            )
            # Without run counters on both sides, a live heartbeat whose uptime
            # is shorter than the time since the stop arrived started after
            # it, unless it is the stopped process itself.
            or (
                (heartbeat_key is None or current_key is None)
                and not replayed
                # A counted heartbeat from an install not yet proven, whose
                # stamp was replaced, must pass the pending proof first.
                and (heartbeat.run_seq is None or heartbeat.own_time)
                # Its uptime is as of sending: only a heartbeat sent just now
                # says how long the process has been up; a held-up one only
                # seems to have started late.
                and abs(now - heartbeat.at) <= SENT_JUST_NOW
                and before is not None
                and not (heartbeat.run_id and before.stop_run_id == heartbeat.run_id)
                and heartbeat.uptime_seconds is not None
                and before.stopped_at is not None
                and before.stop_received_at is not None
                and heartbeat.uptime_seconds < (now - before.stop_received_at).total_seconds()
            )
        )
    )
    run_values = (
        {}
        if capped
        else runs.advance(
            [
                (record.install_id, record.run_seq)
                for record in (None if older_run else heartbeat, *batch.stops)
                if record is not None and not (isinstance(record, Stopping) and record.fingerprint in stale_stops)
            ]
        )
    )
    run_values |= pending_values
    # The process that reported the stored run live, if one did.
    reporter = (sender_run or (heartbeat.run_id if heartbeat is not None else None)) if delivery == DELIVERY_LIVE else None
    previous_reporter = before.live_run_id if before is not None else None
    if from_retired:
        # A retired process's late batch moves nothing.
        run_values = dict(pending_values)
    advanced = "run_seq" in run_values
    same_count_takeover = (
        current_process
        and not older_run
        and heartbeat_key == current_key
        and before is not None
        and reporter is not None
        and before.live_run_id != reporter
    )
    if advanced or same_count_takeover:
        run_values["live_run_id"] = reporter
        # Retired only when counters prove a successor: a newer run, or the
        # running agent itself at the same count. A change of reporter with
        # no counters proves nothing, and must not silence the running one.
        proven = advanced or heartbeat_key is not None
        if proven and previous_reporter is not None and previous_reporter != reporter:
            kept = [run for run in before.retired_run_ids if run != previous_reporter and run in retired] if before else []
            run_values["retired_run_ids"] = [*kept, previous_reporter][-MAX_RETIRED_RUNS:]
    if revived and "retired_run_ids" not in run_values and before is not None:
        run_values["retired_run_ids"] = [run for run in before.retired_run_ids if run in retired]
    if (
        current_process
        and heartbeat is not None
        and heartbeat.run_id
        and not promoted
        and heartbeat_key is not None
        and current_key is not None
        and heartbeat_key < current_key
        and before is not None
        and heartbeat.run_id not in before.lower_run_ids
        and not from_retired
    ):
        # A process reporting live below the stored run: whatever it replays
        # is capped, whoever holds the proof slot.
        run_values["lower_run_ids"] = [*before.lower_run_ids, heartbeat.run_id][-MAX_RETIRED_RUNS:]
    if (
        current_process
        # An own replay may clear it only by establishing a newer run.
        and (not promoted or newer_run)
        and heartbeat is not None
        and heartbeat_key is not None
        and not older_run
        and before is not None
        and before.pending_run_id is not None
        and before.pending_run_id != heartbeat.run_id
        and not pending_values
    ):
        # The running agent reports at or above the stored run: a lower count
        # awaiting proof was someone else's, and is dropped.
        run_values |= _NO_PENDING
    if run_values:
        # Under the row lock taken by the first UPDATE.
        await session.execute(update(Agent).where(Agent.id == agent_id).values(**run_values))
    # A heartbeat from an install that cannot be ordered, stamped with the
    # receive time, could be a replay from anywhere: it must not set the
    # details, nor a "newest" time that would hold back the live agent's.
    unplaceable = (
        heartbeat is not None and heartbeat.run_seq is not None and heartbeat_key is None and (replayed or not heartbeat.own_time)
    )
    if (heartbeat := batch.heartbeat) is not None and not older_run and not unplaceable:
        heartbeat_values: dict[str, object] = {
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
            "agent_version": heartbeat.agent_version,
            "kernel_release": heartbeat.kernel_release,
            "os_name": heartbeat.os_name,
            "response_mode": heartbeat.response_mode,
            "commands_enabled": heartbeat.commands_enabled,
            "policy_remote_sha256": heartbeat.policy_remote_sha256,
            "export_dropped_records": heartbeat.export_dropped_records,
            "export_dropped_alerts": heartbeat.export_dropped_alerts,
            "export_rejected_batches": heartbeat.export_rejected_batches,
            "export_spool_batches": heartbeat.export_spool_batches,
            "active_responses": [response.as_json() for response in heartbeat.active_responses or []],
            "active_responses_truncated": heartbeat.active_responses_truncated,
            "heartbeat_run_seq": heartbeat.run_seq,
            "heartbeat_run_id": heartbeat.run_id,
            "heartbeat_install_id": heartbeat.install_id,
        }
        # A spooled heartbeat replayed after an outage must not undo a newer
        # one. Clocks order one process's heartbeats only: one from the
        # newest run, replacing another process's, wins whatever the stamps
        # say, since the old one may be from a clock that was running fast.
        stored_key = runs.key(before.heartbeat_install_id, before.heartbeat_run_seq) if before is not None else None
        replaces_older_run = (
            heartbeat_key is not None and heartbeat_key == newest_known and stored_key is not None and stored_key < heartbeat_key
        )
        fresh = or_(Agent.last_heartbeat_at.is_(None), Agent.last_heartbeat_at <= heartbeat.at)
        # Within one process, uptime orders the heartbeats whatever the clocks
        # or counters say; a process is its run ID, since a counter can repeat.
        same_run = (
            before is not None
            and bool(heartbeat.run_id)
            and heartbeat.run_id == before.heartbeat_run_id
            and heartbeat.uptime_seconds is not None
            and before.uptime_seconds is not None
        )
        if same_run:
            newest = heartbeat.uptime_seconds >= before.uptime_seconds
            condition = (Agent.id == agent_id) if newest else None
        else:
            # A replay promoted to live is newest unless an earlier sample of
            # its own process: the sender is the running agent.
            own_older = promoted and before is not None and before.heartbeat_run_id == heartbeat.run_id
            newest = restarted or replaces_older_run or (current_process and not own_older)
            condition = (Agent.id == agent_id) if newest else (Agent.id == agent_id) & fresh
        if condition is not None:
            await session.execute(update(Agent).where(condition).values(**heartbeat_values))
    await _track_stop(
        session,
        agent_id=agent_id,
        batch=batch,
        now=now,
        dialect=dialect,
        restarted=restarted,
        heartbeat_unordered=heartbeat is not None and heartbeat_key is None and not replayed,
        ordered_stops=ordered_stops,
        stale_stops=stale_stops,
        newer_stops=newer_stops,
        superseded=older_run,
    )
    if sender_run is not None and not from_retired:
        # Another process reporting while the stop stands: if it goes
        # silent, nothing else will say so, so the offline alert must. The
        # stopped process's own trailing batches are not that.
        after = await session.get(Agent, agent_id)
        if (
            after is not None
            and after.stopped_at is not None
            and after.heard_after_stop_at is None
            and after.stop_run_id is not None
            and sender_run != after.stop_run_id
            and (
                # Live (or its own replay), and not an earlier process's
                # request held up from before the stop.
                (
                    delivery == DELIVERY_LIVE
                    and not _from_before_the_stop(after, heartbeat, batch, now, older_run=older_run, seen=seen_before)
                )
                # Or resending the stop it now stands on: it ran after it.
                or (replayed and after.stop_received_at == now)
            )
        ):
            after.heard_after_stop_at = now

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
            "source_alert_id": alert.source_alert_id,
            "status": (
                AlertStatus.MUTED.value
                if mutes.matches(muted, rule_id=alert.rule_id, hostname=alert.hostname, agent_id=agent_id)
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
                # An agent that said it was stopping already has its own
                # alert, unless it was heard from again after the stop.
                or_(Agent.stopped_at.is_(None), Agent.heard_after_stop_at.is_not(None)),
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
                    AlertStatus.MUTED.value
                    if mutes.matches(muted, rule_id=None, hostname=hostname, agent_id=agent.id)
                    else AlertStatus.OPEN.value
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


async def _track_stop(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    batch: ParsedBatch,
    now: datetime,
    dialect: str,
    restarted: bool = False,
    heartbeat_unordered: bool = False,
    ordered_stops: frozenset[str] | set[str] = frozenset(),
    stale_stops: frozenset[str] | set[str] = frozenset(),
    newer_stops: dict[str, tuple[int, int]] | None = None,
    superseded: bool = False,
) -> None:
    """Raise an alert when an agent says it is stopping, and resolve it when it is back.

    Spooled batches arrive out of order after a restart, so a stop counts
    only when nothing newer has been seen from the agent, in this batch or
    any earlier one, and a stop ends only with a record newer than it.
    """
    agent = await session.get(Agent, agent_id, populate_existing=True)
    if agent is None:
        return
    if restarted:
        # The old run's stamps may be from a clock that ran fast; judge
        # what comes next by this run's clock only.
        agent.last_record_at = None
    seen = [moment for moment in (agent.last_record_at, agent.last_heartbeat_at, batch.latest_at) if moment is not None]
    newest_seen = max(seen) if seen else None
    # The newest stop not seen before: a replayed one must not hide a
    # genuine stop beside it in the same batch.
    known = {entry.split(":", 1)[-1] for entry in agent.seen_stops}
    unseen = [candidate for candidate in batch.stops if candidate.fingerprint not in known]
    if unseen:
        # Beyond the remembered list, a stop already alerted on is seen too.
        alerted = set(
            await session.scalars(
                select(Alert.fingerprint).where(
                    Alert.agent_id == agent_id, Alert.fingerprint.in_([candidate.fingerprint for candidate in unseen])
                )
            )
        )
        unseen = [candidate for candidate in unseen if candidate.fingerprint not in alerted]
    # A stop from a run older than the newest known is stale; of the rest,
    # a newer run's stop first, then the newest time, then the last sent:
    # clocks only order a run's own records.
    newer_stops = newer_stops or {}
    contenders = [(index, candidate) for index, candidate in enumerate(unseen) if candidate.fingerprint not in stale_stops]

    def rank(item: tuple[int, Stopping]) -> tuple[bool, tuple[int, int], datetime, int]:
        index, candidate = item
        run = newer_stops.get(candidate.fingerprint)
        return (run is not None, run or (0, 0), candidate.at, index)

    stopping = max(contenders, key=rank)[1] if contenders else None
    # Records newer than an earlier stop prove the agent came back, even
    # when the same batch also holds a later stop.
    # A batch from an older run (its heartbeat says so) proves nothing about
    # the current one, however late its records are stamped.
    # A numbered stop ends only with a newer run, since a batch without a
    # heartbeat cannot say which run its records are from; or with a
    # heartbeat that cannot be ordered, from another process, stamped by its
    # own clock after the stop and no earlier than the stored heartbeat: a
    # later run that could not count itself.
    heartbeat = batch.heartbeat
    unordered_return = bool(
        heartbeat_unordered
        and heartbeat is not None
        and heartbeat.own_time
        and heartbeat.run_id
        and heartbeat.run_id != agent.stop_run_id
        and agent.stopped_at is not None
        and heartbeat.at > agent.stopped_at
        and (agent.last_heartbeat_at is None or heartbeat.at >= agent.last_heartbeat_at)
    )
    came_back = (
        not superseded
        and (agent.stop_run_seq is None or unordered_return)
        and batch.latest_at is not None
        and agent.stopped_at is not None
        and batch.latest_at > agent.stopped_at
    )
    if agent.stopped_at is not None and (came_back or restarted):
        agent.stopped_at = None
        agent.stop_reason = None
        agent.stop_received_at = None
        agent.heard_after_stop_at = None
        agent.stop_run_seq = None
        agent.stop_run_id = None
        await _resolve_stops(session, agent_id=agent_id, now=now, note="The agent is reporting again.")
    # Run counters settle it, whatever the clocks say: a newer run's stop is
    # genuine. Within one run, the clock decides.
    from_newer_run = stopping is not None and stopping.fingerprint in newer_stops
    stop_is_newest = from_newer_run or (stopping is not None and (newest_seen is None or stopping.at >= newest_seen))
    # Every stop considered is remembered, accepted or not, so a retried
    # batch can never mark a running agent stopped. A genuine stop turned
    # down by a wrong clock is not lost from view: the agent then goes
    # silent, and the offline alert covers it.
    if unseen:
        # Settled: the accepted stop and the older ones beside it in its batch.
        accepted = stopping if stop_is_newest else None

        def label(candidate: Stopping) -> str:
            settled = accepted is not None and candidate.at <= accepted.at
            return f"{'s' if settled else 'r'}:{candidate.fingerprint}"

        added = [label(candidate) for candidate in unseen]
        agent.seen_stops = _bounded_stops([*agent.seen_stops, *dict.fromkeys(added)])
    if stop_is_newest and stopping is not None and (agent.stopped_at is None or stopping.at > agent.stopped_at or from_newer_run):
        if agent.stopped_at is not None:
            # A crash loop sends stop after stop with nothing between them:
            # keep one open alert, for the latest.
            await _resolve_stops(session, agent_id=agent_id, now=now, note="Superseded by a later stop.")
        agent.stopped_at = stopping.at
        agent.stop_reason = stopping.reason
        agent.stop_received_at = now
        agent.heard_after_stop_at = None
        # Numbered only when its run could be ordered; otherwise clocks end it.
        agent.stop_run_seq = stopping.run_seq if stopping.fingerprint in ordered_stops else None
        agent.stop_run_id = stopping.run_id
        await _raise_stopped_alert(session, agent=agent, stopping=stopping, now=now, dialect=dialect)
    if (
        not superseded
        and batch.latest_at is not None
        and (agent.last_record_at is None or batch.latest_at > agent.last_record_at)
    ):
        agent.last_record_at = batch.latest_at


def _bounded_stops(entries: list[str]) -> list[str]:
    """Keep the newest MAX_SEEN_STOPS entries, guaranteeing each class its share.

    Settled (``s:``) and rejected (``r:``) entries each keep up to their own cap
    first; any room left goes to the newest of either, so neither class is
    evicted while there is space.
    """
    if len(entries) <= MAX_SEEN_STOPS:
        return entries
    reserved: set[int] = set()
    settled_left, rejected_left = MAX_SETTLED_STOPS, MAX_REJECTED_STOPS
    for index in range(len(entries) - 1, -1, -1):
        if entries[index].startswith("r:"):
            if rejected_left:
                rejected_left -= 1
                reserved.add(index)
        elif settled_left:
            settled_left -= 1
            reserved.add(index)
    spare = MAX_SEEN_STOPS - len(reserved)
    for index in range(len(entries) - 1, -1, -1):
        if spare <= 0:
            break
        if index not in reserved:
            reserved.add(index)
            spare -= 1
    return [entry for index, entry in enumerate(entries) if index in reserved]


def _stop_fingerprint(stopping: Stopping) -> str:
    # By record identity; the time alone can repeat after a clock correction.
    return stopping.fingerprint or hashlib.sha256(f"stopped:{stopping.at.isoformat()}".encode()).hexdigest()


async def _resolve_stops(session: AsyncSession, *, agent_id: uuid.UUID, now: datetime, note: str) -> None:
    await session.execute(
        update(Alert)
        .where(
            Alert.agent_id == agent_id,
            Alert.kind == AlertKind.AGENT_STOPPED.value,
            Alert.status.in_([AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value]),
        )
        .values(
            status=AlertStatus.RESOLVED.value,
            status_changed_at=now,
            status_changed_by="system",
            note=note,
        )
    )


async def _raise_stopped_alert(session: AsyncSession, *, agent: Agent, stopping: Stopping, now: datetime, dialect: str) -> None:
    hostname = agent.hostname or agent.name
    severity = "error" if stopping.reason == "error" else "notice"
    title = f"Agent {agent.name} stopped"
    if stopping.reason == "error":
        title = f"Agent {agent.name} stopped after an error"
    fields: dict[str, object] = {"agent": agent.name, "reason": stopping.reason}
    if stopping.error:
        fields["error"] = stopping.error
    muted = await mutes.active(session, now=now)
    row = {
        "id": new_id(),
        "agent_id": agent.id,
        "fingerprint": _stop_fingerprint(stopping),
        "kind": AlertKind.AGENT_STOPPED.value,
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "title": title,
        "rule_id": None,
        "source_event": "agent_stopping",
        "hostname": hostname,
        "occurred_at": stopping.at,
        "received_at": now,
        "hour_bucket": int(stopping.at.timestamp()) // 3600,
        "tags": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "fields": fields,
        "status": AlertStatus.MUTED.value
        if mutes.matches(muted, rule_id=None, hostname=hostname, agent_id=agent.id)
        else AlertStatus.OPEN.value,
    }
    insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
    await session.execute(insert(Alert).values([row]).on_conflict_do_nothing(index_elements=["agent_id", "fingerprint"]))


def in_force(agent: Agent, *, now: datetime) -> list[dict[str, object]]:
    """The agent's reported responses whose deadline has not passed.

    The list is from the last heartbeat, so one can expire between them.
    """
    current: list[dict[str, object]] = []
    for item in agent.active_responses:
        until = item.get("until")
        if isinstance(until, str):
            try:
                deadline = datetime.fromisoformat(until)
            except ValueError:
                deadline = None
            if deadline is not None and deadline.tzinfo is not None and deadline <= now:
                continue
        current.append(item)
    return current
