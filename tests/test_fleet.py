from datetime import UTC, datetime, timedelta

from traceguard_manager.fleet import agent_status, baseline_policy, describe_fleet
from traceguard_manager.models import Agent

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
OFFLINE_AFTER = timedelta(minutes=15)


def make_agent(name: str, **values: object) -> Agent:
    defaults: dict[str, object] = {
        "enabled": True,
        "last_seen_at": NOW - timedelta(minutes=1),
        "healthy": True,
        "ringbuf_degraded": False,
        "unavailable_hooks": [],
        "policy_sha256": "a" * 64,
    }
    return Agent(name=name, token_hash=name, token_prefix="tgm_", **(defaults | values))


def status(**values: object) -> str:
    return agent_status(make_agent("x", **values), now=NOW, offline_after=OFFLINE_AFTER)


def test_status_precedence() -> None:
    assert status() == "online"
    assert status(enabled=False) == "disabled"
    assert status(last_seen_at=None) == "pending"
    assert status(last_seen_at=NOW - timedelta(minutes=16)) == "offline"
    assert status(healthy=False) == "degraded"
    assert status(ringbuf_degraded=True) == "degraded"
    assert status(unavailable_hooks=["lsm/bprm_check"]) == "degraded"
    # An agent that stopped reporting is offline even if its last word was "unhealthy".
    assert status(healthy=False, last_seen_at=NOW - timedelta(hours=3)) == "offline"


def test_baseline_is_the_most_common_policy_among_enabled_agents() -> None:
    agents = [
        make_agent("a"),
        make_agent("b"),
        make_agent("c", policy_sha256="b" * 64),
        make_agent("d", policy_sha256="c" * 64, enabled=False),
        make_agent("e", policy_sha256=None),
    ]
    assert baseline_policy(agents) == "a" * 64
    assert baseline_policy([]) is None


def test_baseline_tie_is_deterministic() -> None:
    agents = [make_agent("a", policy_sha256="f" * 64), make_agent("b", policy_sha256="1" * 64)]
    assert baseline_policy(agents) == baseline_policy(list(reversed(agents))) == "1" * 64


def test_describe_fleet_counts_and_drift() -> None:
    agents = [
        make_agent("a"),
        make_agent("b"),
        make_agent("c", policy_sha256="b" * 64),
        make_agent("d", last_seen_at=None, policy_sha256=None),
        make_agent("e", last_seen_at=NOW - timedelta(hours=1)),
        make_agent("f", enabled=False, policy_sha256="c" * 64),
    ]
    views, summary = describe_fleet(agents, now=NOW, offline_after=OFFLINE_AFTER)
    assert (summary.total, summary.online, summary.offline, summary.pending, summary.disabled) == (
        6,
        3,
        1,
        1,
        1,
    )
    assert summary.drifted == 1
    assert [view.agent.name for view in views if view.drifted] == ["c"]
