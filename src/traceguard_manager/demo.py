"""Sample agents and alerts for trying the dashboard without a TraceGuard agent.

Everything is built as TraceGuard export records and stored through the same
parser and storage path as real ingest, so the demo exercises the real code.
Demo agents are named ``demo-...`` and their tokens are discarded, so nothing
can authenticate as one.
"""

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import alerts, fleet, mutes
from .errors import DomainError
from .ingest import parse_batch
from .models import Agent, AlertStatus, MuteRule

DEMO_PREFIX = "demo-"
RECENT_ALERTS = 90  # spread over the last 24 hours, so the chart has a shape
OLDER_ALERTS = 70  # spread over the six days before that
_BASELINE_POLICY = "3f9a" * 16
_DRIFTED_POLICY = "b71c" * 16


class DemoError(DomainError):
    """A user-facing refusal. The message is safe to show."""


@dataclass(frozen=True, slots=True)
class DemoHost:
    name: str
    seen_ago: timedelta = timedelta(minutes=2)
    policy: str = _BASELINE_POLICY
    unavailable_hooks: tuple[str, ...] = ()
    weight: int = 1  # share of the alerts


# One of each state the fleet page can show.
HOSTS: tuple[DemoHost, ...] = (
    DemoHost("demo-web-01", weight=4),
    DemoHost("demo-web-02", weight=2),
    DemoHost("demo-db-01", unavailable_hooks=("lsm/file_open",), weight=2),
    DemoHost("demo-build-01", policy=_DRIFTED_POLICY, weight=1),
    DemoHost("demo-edge-01", seen_ago=timedelta(hours=3), weight=1),
)
PENDING_HOST = "demo-new-01"  # enrolled, never connected
DEMO_ACTOR = "demo"
# One mute rule, so the muted status and the mute page have something in them.
MUTED_RULE = "tg-new-setuid-binary"
MUTED_HOST = "demo-build-01"


@dataclass(frozen=True, slots=True)
class DemoRule:
    rule_id: str
    severity: str
    message: str
    source_event: str
    tags: tuple[str, ...]
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    fields: tuple[tuple[str, Any], ...]
    weight: int


RULES: tuple[DemoRule, ...] = (
    DemoRule(
        "tg-reverse-shell",
        "critical",
        "Interactive shell spawned by a network service",
        "exec",
        ("shell", "execution"),
        ("TA0002",),
        ("T1059",),
        (("exe", "/usr/bin/bash"), ("parent_comm", "nginx")),
        2,
    ),
    DemoRule(
        "tg-credential-file-read",
        "error",
        "Credential file read by an unexpected process",
        "file_open",
        ("credentials",),
        ("TA0006",),
        ("T1003",),
        (("path", "/etc/shadow"), ("comm", "python3")),
        3,
    ),
    DemoRule(
        "tg-mining-pool-dns",
        "warning",
        "DNS lookup for a known mining pool",
        "dns",
        ("cryptomining",),
        ("TA0040",),
        ("T1496",),
        (("query", "pool.miner.example"), ("comm", "kworker")),
        5,
    ),
    DemoRule(
        "tg-rare-outbound-port",
        "warning",
        "Outbound connection to an unusual port",
        "connection",
        ("network",),
        ("TA0011",),
        ("T1571",),
        (("dest_ip", "203.0.113.40"), ("dest_port", 4444), ("comm", "curl")),
        4,
    ),
    DemoRule(
        "tg-new-setuid-binary",
        "notice",
        "New setuid binary written",
        "file_open",
        ("persistence",),
        ("TA0004",),
        ("T1548",),
        (("path", "/usr/local/bin/helper"), ("comm", "install")),
        3,
    ),
)


@dataclass(frozen=True, slots=True)
class DemoSummary:
    agents: int
    alerts: int


def _detection(rng: random.Random, host: str, at: datetime, serial: int) -> dict[str, Any]:
    rule = rng.choices(RULES, weights=[rule.weight for rule in RULES])[0]
    return {
        "timestamp": at.isoformat(),
        "level": "info",
        "message": "detection alert",
        "hostname": host,
        "event": "detection_alert",
        "source_event": rule.source_event,
        "alert_id": f"DEMO{serial:05d}",
        "detection_rule_id": rule.rule_id,
        "severity": rule.severity,
        "detection_message": rule.message,
        "tags": list(rule.tags),
        "mitre_tactics": list(rule.tactics),
        "mitre_techniques": list(rule.techniques),
        "threshold_count": 1,
        "pid": 1000 + serial,
        **dict(rule.fields),
    }


def _enforcement(rng: random.Random, host: str, at: datetime, serial: int) -> dict[str, Any]:
    base = {"timestamp": at.isoformat(), "level": "info", "hostname": host, "pid": 1000 + serial}
    match rng.randrange(4):
        case 0:
            return base | {"message": "egress_blocked", "event": "egress_blocked", "domain": "exfil.example", "comm": "curl"}
        case 1:
            return base | {
                "message": "exec_would_block",
                "event": "exec_would_block",
                "exe": "/var/www/uploads/payload",
                "comm": "sh",
            }
        case 2:
            return base | {
                "message": "killed process after detection",
                "event": "response",
                "action": "kill",
                "exe": "/var/www/uploads/payload",
            }
        case _:
            return base | {"level": "error", "message": "failed to attach hook lsm/file_open", "event": "agent"}


def _heartbeat(host: DemoHost, at: datetime) -> dict[str, Any]:
    return {
        "timestamp": at.isoformat(),
        "level": "info",
        "message": "heartbeat",
        "hostname": host.name,
        "event": "heartbeat",
        "policy_sha256": host.policy,
        "policy_mode": "enforce",
        "uptime_seconds": 86_400 * 3 + 5_400,
        "healthy": not host.unavailable_hooks,
        "unavailable_hooks": list(host.unavailable_hooks),
        "ringbuf_dropped_events": 0,
        "ringbuf_degraded": False,
        "detection_rules": len(RULES),
        "agent_version": "1.9.0",
        "kernel_release": "6.12.48-1-amd64",
        "os_name": "Debian GNU/Linux 13 (trixie)",
        "response_mode": "dry-run",
        "commands_enabled": False,
        "export_dropped_records": 0,
        "export_dropped_alerts": 0,
        "export_rejected_batches": 0,
        "export_spool_batches": 0,
        "active_responses": [],
    }


def build_records(*, now: datetime, seed: int = 26) -> dict[str, list[dict[str, Any]]]:
    """The records each demo host reports, keyed by host name. Same seed, same data."""
    rng = random.Random(seed)  # noqa: S311 - sample data, not a security decision
    records: dict[str, list[dict[str, Any]]] = {host.name: [] for host in HOSTS}
    weights = [host.weight for host in HOSTS]
    ages = [timedelta(seconds=rng.randrange(60, 86_400)) for _ in range(RECENT_ALERTS)]
    ages += [timedelta(seconds=rng.randrange(86_400, 7 * 86_400)) for _ in range(OLDER_ALERTS)]
    for serial, age in enumerate(ages):
        host = rng.choices(HOSTS, weights=weights)[0]
        # A host that went quiet cannot have reported anything since.
        at = now - max(age, host.seen_ago)
        build = _detection if rng.random() < 0.75 else _enforcement
        records[host.name].append(build(rng, host.name, at, serial))
    for host in HOSTS:
        records[host.name].append(_heartbeat(host, now - host.seen_ago))
    return records


async def _demo_agents(session: AsyncSession) -> list[Agent]:
    return list(await session.scalars(select(Agent).where(Agent.name.startswith(DEMO_PREFIX, autoescape=True))))


async def seed(
    session: AsyncSession, *, now: datetime, dialect: str, offline_after: timedelta = timedelta(minutes=15), force: bool = False
) -> DemoSummary:
    """Create the demo fleet and its alerts.

    Refuses to mix sample alerts into a database that already has real agents
    unless ``force`` is set.
    """
    existing = await fleet.list_agents(session)
    if any(agent.name.startswith(DEMO_PREFIX) for agent in existing):
        raise DemoError("Demo data is already present. Remove it first with `traceguard-manager demo-data --remove`.")
    if existing and not force:
        raise DemoError(
            f"This database already has {len(existing)} enrolled agent(s). "
            "Sample alerts would be mixed in with real ones; pass --force if that is what you want."
        )

    await mutes.create(
        session,
        rule_id=MUTED_RULE,
        hostname=MUTED_HOST,
        reason="Expected: package builds install setuid helpers.",
        duration="forever",
        actor=DEMO_ACTOR,
        now=now,
    )
    await session.flush()
    stored = 0
    new_ids: list[uuid.UUID] = []
    records = build_records(now=now)
    for host in HOSTS:
        agent, _token = await fleet.enroll_agent(session, name=host.name)
        seen_at = now - host.seen_ago
        result = await fleet.store_batch(
            session, agent_id=agent.id, batch=parse_batch(records[host.name], now=seen_at), now=seen_at, dialect=dialect
        )
        stored += result.stored
        new_ids += result.new_alert_ids
    await fleet.enroll_agent(session, name=PENDING_HOST)
    # The host that went quiet gets the alert the manager raises for that.
    stored += await fleet.raise_offline_alerts(session, now=now, offline_after=offline_after, dialect=dialect)

    # Leave most alerts open, with some already worked, so every status has rows.
    rng = random.Random(len(new_ids))  # noqa: S311 - sample data, not a security decision
    rng.shuffle(new_ids)
    quarter = len(new_ids) // 4
    for status, ids, note in (
        (AlertStatus.ACKNOWLEDGED, new_ids[:quarter], None),
        (AlertStatus.RESOLVED, new_ids[quarter : 2 * quarter], "Expected: scheduled maintenance job."),
    ):
        for start in range(0, len(ids), alerts.MAX_BULK):
            await alerts.set_status(
                session, alert_ids=ids[start : start + alerts.MAX_BULK], status=status.value, actor=DEMO_ACTOR, note=note, now=now
            )
    return DemoSummary(agents=len(HOSTS) + 1, alerts=stored)


async def remove(session: AsyncSession) -> int:
    """Delete every demo agent, and with each its alerts. Returns how many agents went."""
    agents = await _demo_agents(session)
    for agent in agents:
        await session.delete(agent)
    await session.execute(delete(MuteRule).where(MuteRule.created_by == DEMO_ACTOR))
    return len(agents)
