"""What newer agents report: version and export health, stops, linked responses, unreadable records."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from traceguard_manager import fleet
from traceguard_manager.models import Agent, Alert, AlertKind, AlertStatus

from .conftest import Site
from .helpers import data, detection, heartbeat, now_iso


def _at(seconds_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds_ago)).isoformat()


async def _agent(site: Site) -> Agent:
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        return agent


async def _alerts(site: Site, kind: AlertKind) -> list[Alert]:
    async with site.manager.database.session() as session:
        return list(await session.scalars(select(Alert).where(Alert.kind == kind.value).order_by(Alert.occurred_at)))


def stopping(reason: str = "signal", timestamp: str | None = None, **extra: object) -> dict[str, object]:
    return {
        "timestamp": timestamp or now_iso(),
        "level": "info",
        "message": "agent stopping",
        "hostname": "web-01",
        "event": "agent_stopping",
        "reason": reason,
        **extra,
    }


async def test_heartbeat_reports_version_export_health_and_responses(site: Site) -> None:
    response = await site.ingest(
        [
            heartbeat(
                agent_version="1.9.0",
                kernel_release="6.12.48",
                os_name="Debian GNU/Linux 13",
                response_mode="enforce",
                commands_enabled=True,
                policy_remote_sha256="B" * 64,
                export_dropped_records=12,
                export_dropped_alerts=2,
                export_rejected_batches=1,
                export_spool_batches=3,
                active_responses=[
                    {"action": "block_peer", "target": "203.0.113.7", "until": _at(-600), "applied": True, "manual": True},
                    {"action": "reboot", "target": "x"},
                    "not an object",
                ],
            )
        ]
    )
    assert response.status_code == 200
    agent = await _agent(site)
    assert (agent.agent_version, agent.kernel_release, agent.os_name) == ("1.9.0", "6.12.48", "Debian GNU/Linux 13")
    assert agent.response_mode == "enforce" and agent.commands_enabled is True
    assert agent.policy_remote_sha256 == "b" * 64
    assert (agent.export_dropped_records, agent.export_dropped_alerts, agent.export_rejected_batches) == (12, 2, 1)
    assert agent.export_spool_batches == 3
    assert len(agent.active_responses) == 1
    assert agent.active_responses[0]["target"] == "203.0.113.7" and agent.active_responses[0]["manual"] is True

    page = (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text
    assert "1.9.0" in page and "Debian GNU/Linux 13" in page
    assert 'data-testid="agent-dropping"' in page
    assert "203.0.113.7" in page


async def test_a_replayed_old_heartbeat_does_not_undo_a_newer_one(site: Site) -> None:
    await site.ingest([heartbeat(agent_version="1.9.1", timestamp=_at(10))])
    await site.ingest([heartbeat(agent_version="1.9.0", timestamp=_at(600))])
    assert (await _agent(site)).agent_version == "1.9.1"


async def test_older_agents_still_work(site: Site) -> None:
    await site.ingest([heartbeat()])
    agent = await _agent(site)
    assert agent.agent_version is None and agent.active_responses == []
    page = (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text
    assert "older than 1.9" in page


async def test_a_clean_stop_raises_an_alert_that_resolves_when_the_agent_returns(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(120))])
    await site.ingest([stopping(timestamp=_at(60))])
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.stop_reason == "signal"
    [alert] = await _alerts(site, AlertKind.AGENT_STOPPED)
    assert alert.status == AlertStatus.OPEN.value and alert.severity == "notice"
    assert "web-01 stopped" in alert.title
    assert 'data-testid="agent-stopped"' in (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text

    # The same stop delivered twice does not raise a second alert.
    await site.ingest([stopping(timestamp=alert.occurred_at.isoformat())])
    assert len(await _alerts(site, AlertKind.AGENT_STOPPED)) == 1

    await site.ingest([heartbeat()])
    agent = await _agent(site)
    assert agent.stopped_at is None
    [alert] = await _alerts(site, AlertKind.AGENT_STOPPED)
    assert alert.status == AlertStatus.RESOLVED.value


async def test_a_stop_after_an_error_is_an_error(site: Site) -> None:
    await site.ingest([stopping(reason="error", error="ring buffer closed")])
    [alert] = await _alerts(site, AlertKind.AGENT_STOPPED)
    assert alert.severity == "error" and alert.fields["error"] == "ring buffer closed"


async def test_a_stale_stop_replayed_after_a_restart_is_ignored(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(5))])
    await site.ingest([stopping(timestamp=_at(300))])
    assert (await _agent(site)).stopped_at is None
    assert await _alerts(site, AlertKind.AGENT_STOPPED) == []


async def test_a_stopped_agent_gets_no_second_offline_alert(site: Site) -> None:
    await site.ingest([stopping()])
    offline_after = timedelta(seconds=site.manager.config.agent_offline_seconds)
    later = datetime.now(UTC) + offline_after + timedelta(minutes=1)
    async with site.manager.database.session() as session:
        raised = await fleet.raise_offline_alerts(
            session, now=later, offline_after=offline_after, dialect=site.manager.database.dialect
        )
    assert raised == 0


async def test_unreadable_records_are_counted_and_explained(site: Site) -> None:
    ocsf = {"time": 1700000000000, "class_uid": 2004, "metadata": {"version": "1.3.0"}}
    response = await site.ingest([ocsf, ocsf, heartbeat()])
    assert data(response)["invalid"] == 2
    agent = await _agent(site)
    assert agent.invalid_records == 2 and agent.last_invalid_at is not None
    page = (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text
    assert "TRACEGUARD_EVENT_SCHEMA=traceguard" in page


async def test_dry_run_dns_and_resolver_records_are_would_blocks(site: Site) -> None:
    base = {"timestamp": now_iso(), "level": "info", "hostname": "web-01", "domain": "evil.example", "mode": "dry-run"}
    await site.ingest(
        [
            base | {"message": "would-block", "event": "dns"},
            base | {"message": "would-block-udp", "event": "resolver", "endpoint": "198.51.100.4"},
            base | {"message": "blocked-udp", "event": "resolver_blocked", "endpoint": "198.51.100.5"},
        ]
    )
    assert len(await _alerts(site, AlertKind.WOULD_BLOCK)) == 2
    assert len(await _alerts(site, AlertKind.BLOCKED)) == 1


async def test_command_records_are_not_alerts(site: Site) -> None:
    record = {
        "timestamp": now_iso(),
        "level": "error",
        "message": "manager command",
        "hostname": "web-01",
        "event": "command",
        "status": "failed",
    }
    assert data(await site.ingest([record]))["ignored"] == 1
    assert await _alerts(site, AlertKind.AGENT_ERROR) == []


async def test_responses_link_to_the_alert_that_caused_them(site: Site) -> None:
    response_record = {
        "timestamp": now_iso(),
        "level": "info",
        "message": "response applied",
        "hostname": "web-01",
        "event": "response",
        "response_id": "block-scanner",
        "action": "block_peer",
        "target": "203.0.113.9",
        "detection_rule_id": "tg-reverse-shell",
        "alert_id": "ALERT-77",
        "mode": "enforce",
    }
    await site.ingest([detection("ALERT-77", peer_address="203.0.113.9"), response_record])
    [found] = await _alerts(site, AlertKind.DETECTION)
    [acted] = await _alerts(site, AlertKind.RESPONSE)
    assert found.source_alert_id == acted.source_alert_id == "ALERT-77"

    browser = await site.admin()
    page = (await browser.get(f"/alerts/{found.id}")).text
    assert 'data-testid="linked-alerts"' in page and "response applied" in page
    # The detection offers to block its peer; the response offers to lift itself.
    assert 'data-testid="quick-block"' in page and "203.0.113.9" in page
    # A lift is offered only while the agent still reports the block as active.
    assert 'data-testid="quick-lift"' not in (await browser.get(f"/alerts/{acted.id}")).text
    await site.ingest([heartbeat(active_responses=[{"action": "block_peer", "target": "203.0.113.9", "applied": True}])])
    lift_page = (await browser.get(f"/alerts/{acted.id}")).text
    assert 'data-testid="quick-lift"' in lift_page and "Lift the current block" in lift_page
    # A viewer may look but not act.
    assert 'data-testid="quick-block"' not in (await (await site.viewer()).get(f"/alerts/{found.id}")).text


async def test_a_stop_followed_by_newer_records_in_one_batch_is_ignored(site: Site) -> None:
    # Spooled records from before and after a restart arrive together.
    await site.ingest([stopping(timestamp=_at(60)), detection("AFTER", timestamp=_at(30))])
    assert (await _agent(site)).stopped_at is None
    assert await _alerts(site, AlertKind.AGENT_STOPPED) == []


async def test_a_replayed_stop_older_than_any_record_is_ignored(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300))])
    await site.ingest([stopping(timestamp=_at(120))])
    # The agent comes back with alerts only, then replays its old final batch.
    await site.ingest([detection("BACK", timestamp=_at(60))])
    assert (await _agent(site)).stopped_at is None
    await site.ingest([stopping(timestamp=_at(120))])
    agent = await _agent(site)
    assert agent.stopped_at is None
    [alert] = await _alerts(site, AlertKind.AGENT_STOPPED)
    assert alert.status == AlertStatus.RESOLVED.value


async def test_a_stopped_agent_is_shown_as_stopped(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60))])
    await site.ingest([stopping()])
    browser = await site.viewer()
    page = (await browser.get("/agents?status=stopped")).text
    assert "web-01" in page and "state-stopped" in page
    assert "web-01" not in (await browser.get("/agents?status=online")).text


async def test_out_of_range_times_never_fail_a_batch(site: Site) -> None:
    response = await site.ingest(
        [
            heartbeat(
                timestamp="0001-01-01T00:00:00+05:00",
                active_responses=[{"action": "block_peer", "target": "203.0.113.7", "until": "9999-12-31T23:59:59-05:00"}],
                active_responses_truncated=True,
            ),
            detection("ODD", timestamp="0001-01-01T00:30:00+01:00"),
        ]
    )
    assert response.status_code == 200, response.text
    agent = await _agent(site)
    assert agent.active_responses[0]["until"] is None and agent.active_responses_truncated is True
    assert "listed only the first" in (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text


async def test_a_replay_with_a_restart_and_a_new_stop_closes_the_old_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(600))])
    await site.ingest([stopping(timestamp=_at(500))])
    # The agent came back (heartbeat) and stopped again; both arrive together.
    await site.ingest([heartbeat(timestamp=_at(300)), stopping(timestamp=_at(200))])
    statuses = sorted(alert.status for alert in await _alerts(site, AlertKind.AGENT_STOPPED))
    assert statuses == [AlertStatus.OPEN.value, AlertStatus.RESOLVED.value]
    assert (await _agent(site)).stopped_at is not None


async def test_a_crash_loop_keeps_one_open_stop_alert(site: Site) -> None:
    for seconds_ago in (300, 200, 100):
        await site.ingest([stopping(reason="error", error="ring buffer closed", timestamp=_at(seconds_ago))])
    statuses = sorted(alert.status for alert in await _alerts(site, AlertKind.AGENT_STOPPED))
    assert statuses == [AlertStatus.OPEN.value, AlertStatus.RESOLVED.value, AlertStatus.RESOLVED.value]


async def test_a_restart_with_a_corrected_clock_clears_the_stop(site: Site) -> None:
    # The agent's clock ran five minutes fast when it stopped.
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([stopping(timestamp=_at(-290))])
    assert (await _agent(site)).stopped_at is not None
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    # It restarts with the right time: its stamps are older, its uptime short.
    await site.ingest([heartbeat(timestamp=now_iso(), uptime_seconds=30, agent_version="1.9.1")])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.agent_version == "1.9.1"


async def test_expired_responses_are_not_shown_as_in_force(site: Site) -> None:
    await site.ingest(
        [
            heartbeat(
                active_responses=[
                    {"action": "block_peer", "target": "203.0.113.1", "until": _at(60), "applied": True},
                    {"action": "block_peer", "target": "203.0.113.2", "until": _at(-600), "applied": True},
                ]
            )
        ]
    )
    page = (await (await site.viewer()).get(f"/agents/{site.agent_id}")).text
    assert "203.0.113.2" in page and "203.0.113.1" not in page


async def test_after_a_clock_corrected_restart_a_new_stop_still_counts(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(-280)), detection("FAST", timestamp=_at(-285))])
    await site.ingest([stopping(timestamp=_at(-290))])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=30)])
    assert (await _agent(site)).stopped_at is None
    # The restarted agent stops again, by its corrected clock.
    await site.ingest([stopping(timestamp=_at(5))])
    assert (await _agent(site)).stopped_at is not None


async def test_a_handled_stop_replayed_after_a_restart_changes_nothing(site: Site) -> None:
    fast_stop = stopping(timestamp=_at(-290))
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([fast_stop])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=30)])
    assert (await _agent(site)).stopped_at is None
    # The old stop arrives again from the spool.
    await site.ingest([fast_stop])
    assert (await _agent(site)).stopped_at is None


async def test_a_replayed_stop_does_not_hide_a_genuine_one_in_the_same_batch(site: Site) -> None:
    old_stop = stopping(timestamp=_at(-290))
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([old_stop])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=30)])
    # The restarted agent stops for real; its spool replays the old stop with it.
    await site.ingest([stopping(reason="error", error="crashed", timestamp=_at(5)), old_stop])
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.stop_reason == "error"


async def test_different_stops_at_the_same_time_are_both_seen(site: Site) -> None:
    moment = _at(-290)
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([stopping(reason="signal", timestamp=moment)])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    # A clock-corrected restart, then a different stop that parses to the same instant.
    await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=30)])
    await site.ingest([stopping(reason="error", error="crashed", timestamp=moment)])
    reasons = sorted(alert.fields["reason"] for alert in await _alerts(site, AlertKind.AGENT_STOPPED))
    assert reasons == ["error", "signal"]


async def test_every_stop_of_a_replayed_batch_is_recognised(site: Site) -> None:
    first, second = stopping(reason="signal", timestamp=_at(-285)), stopping(reason="error", timestamp=_at(-290))
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([first, second])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.stop_received_at = datetime.now(UTC) - timedelta(minutes=2)
    await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=30)])
    assert (await _agent(site)).stopped_at is None
    await site.ingest([first, second])
    assert (await _agent(site)).stopped_at is None
    assert len(await _alerts(site, AlertKind.AGENT_STOPPED)) == 1


async def test_a_stale_stop_retried_after_a_restart_changes_nothing(site: Site) -> None:
    old = stopping(reason="signal", timestamp=_at(-250))
    # Turned down behind a newer heartbeat from the same, fast-clocked run.
    await site.ingest([heartbeat(timestamp=_at(-300), uptime_seconds=7200)])
    await site.ingest([old])
    assert (await _agent(site)).stopped_at is None
    # The agent restarts with the right time, then the old batch is retried.
    await site.ingest([heartbeat(timestamp=_at(30), uptime_seconds=20)])
    await site.ingest([old])
    assert (await _agent(site)).stopped_at is None
    assert await _alerts(site, AlertKind.AGENT_STOPPED) == []


RUN1, RUN2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


async def test_a_restart_without_a_stop_record_is_still_recognised(site: Site) -> None:
    # Run 1 has a fast clock and is killed without a stop record.
    await site.ingest([heartbeat(timestamp=_at(-500), uptime_seconds=7200, run_id=RUN1, run_seq=1)])
    # Run 2, with the right time, starts and then crashes.
    await site.ingest(
        [
            heartbeat(timestamp=_at(30), uptime_seconds=20, run_id=RUN2, run_seq=2),
            stopping(reason="error", timestamp=_at(5), run_seq=2),
        ]
    )
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.stop_reason == "error"
    assert agent.uptime_seconds == 20


async def test_a_clock_corrected_backwards_restart_is_recognised(site: Site) -> None:
    # Implied start times are almost equal, but the run IDs differ.
    await site.ingest([heartbeat(timestamp=_at(-290), uptime_seconds=290, run_id=RUN1, run_seq=1)])
    await site.ingest(
        [
            heartbeat(timestamp=_at(2), uptime_seconds=1, run_id=RUN2, run_seq=2),
            stopping(reason="error", timestamp=_at(1), run_seq=2),
        ]
    )
    agent = await _agent(site)
    assert agent.uptime_seconds == 1 and agent.stopped_at is not None


async def test_a_late_heartbeat_of_a_known_run_is_never_a_restart(site: Site) -> None:
    # Same run, uptime and wall clock out of step (as after a suspend), delivered out of order.
    await site.ingest([heartbeat(timestamp=_at(5), uptime_seconds=130, run_id=RUN1, run_seq=1, agent_version="1.9.1")])
    await site.ingest([stopping(timestamp=_at(3), run_seq=1)])
    await site.ingest([heartbeat(timestamp=_at(300), uptime_seconds=40, run_id=RUN1, run_seq=1, agent_version="1.9.0")])
    agent = await _agent(site)
    assert agent.agent_version == "1.9.1" and agent.stopped_at is not None
    # An old run's heartbeat replayed after a restart is not one either.
    await site.ingest([heartbeat(timestamp=_at(2), uptime_seconds=10, run_id=RUN2, run_seq=2, agent_version="1.9.2")])
    await site.ingest([heartbeat(timestamp=_at(200), uptime_seconds=5, run_id=RUN1, run_seq=1, agent_version="1.9.0")])
    assert (await _agent(site)).agent_version == "1.9.2"


async def test_an_out_of_order_heartbeat_from_the_same_run_is_not_a_restart(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(5), uptime_seconds=130, agent_version="1.9.1", run_id=RUN1)])
    await site.ingest([stopping(timestamp=_at(3))])
    await site.ingest([heartbeat(timestamp=_at(35), uptime_seconds=100, agent_version="1.9.0", healthy=False, run_id=RUN1)])
    agent = await _agent(site)
    assert agent.agent_version == "1.9.1" and agent.uptime_seconds == 130 and agent.healthy is True
    assert agent.stopped_at is not None


async def test_rejected_stops_never_push_out_settled_ones(site: Site) -> None:
    from traceguard_manager import fleet

    loser, winner = stopping(reason="signal", timestamp=_at(-285)), stopping(reason="error", timestamp=_at(-290))
    await site.ingest([heartbeat(timestamp=_at(-280))])
    await site.ingest([loser, winner])
    # A flood of stale stops, each turned down behind a newer heartbeat.
    await site.ingest([heartbeat(timestamp=_at(-600))])
    for index in range(fleet.MAX_SEEN_STOPS + 5):
        await site.ingest([stopping(reason=f"stale-{index}", timestamp=_at(3000 + index))])
    agent = await _agent(site)
    remembered = {entry.split(":", 1)[-1] for entry in agent.seen_stops}
    assert len(agent.seen_stops) <= fleet.MAX_SEEN_STOPS
    assert sum(entry.startswith("s:") for entry in agent.seen_stops) == 2
    assert len(remembered) == len(agent.seen_stops)


def test_settled_and_rejected_stops_are_capped_apart() -> None:
    from traceguard_manager import fleet

    entries = [f"s:{index}" for index in range(fleet.MAX_SEEN_STOPS)] + ["r:new"]
    kept = fleet._bounded_stops(entries)
    # The rejected stop keeps its reserved place; settled ones fill the rest.
    assert "r:new" in kept and len(kept) == fleet.MAX_SEEN_STOPS
    assert sum(entry.startswith("s:") for entry in kept) == fleet.MAX_SEEN_STOPS - 1


async def test_an_older_run_replayed_after_a_newer_one_changes_nothing(site: Site) -> None:
    # Run 2 is up and has stopped for real; run 1's spool arrives afterwards.
    await site.ingest([heartbeat(timestamp=_at(60), run_seq=2, agent_version="1.9.2")])
    await site.ingest([stopping(reason="error", timestamp=_at(30), run_seq=2)])
    # Run 1 had a fast clock, so its stamps look later than run 2's.
    await site.ingest(
        [
            heartbeat(timestamp=_at(-120), run_seq=1, agent_version="1.9.0"),
            detection("OLD", timestamp=_at(-110)),
            stopping(timestamp=_at(-100), run_seq=1),
        ]
    )
    agent = await _agent(site)
    assert agent.agent_version == "1.9.2" and agent.stopped_at is not None and agent.stop_reason == "error"
    open_stops = [alert for alert in await _alerts(site, AlertKind.AGENT_STOPPED) if alert.status == AlertStatus.OPEN.value]
    assert len(open_stops) == 1 and open_stops[0].fields["reason"] == "error"


async def test_a_newer_runs_stop_counts_whatever_its_clock(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(-400), run_seq=1)])
    # Run 2 starts with a corrected clock and crashes before its first heartbeat gets through.
    await site.ingest([stopping(reason="error", timestamp=_at(5), run_seq=2)])
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.run_seq == 2


def test_either_class_of_remembered_stop_may_use_spare_room() -> None:
    from traceguard_manager import fleet

    rejected = [f"r:{index}" for index in range(fleet.MAX_SEEN_STOPS + 3)]
    kept = fleet._bounded_stops(rejected)
    assert len(kept) == fleet.MAX_SEEN_STOPS and kept[-1] == rejected[-1]


INSTALL_A, INSTALL_B = "a" * 32, "b" * 32


async def test_a_reinstalled_agent_starts_its_count_again(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=30, install_id=INSTALL_A)])
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=30, install_id=INSTALL_A)])
    # The counter file was lost: the new install counts from 1.
    await site.ingest([heartbeat(timestamp=_at(5), run_id=RUN2, run_seq=1, install_id=INSTALL_B, agent_version="2.0.0")])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 1 and agent.install_ids == [INSTALL_A, INSTALL_B]
    assert agent.agent_version == "2.0.0"
    # The old install's spool, replayed later, is older whatever its numbers say.
    await site.ingest(
        [
            heartbeat(timestamp=_at(-50), run_id=RUN1, run_seq=30, install_id=INSTALL_A, agent_version="1.9.0"),
            stopping(timestamp=_at(-40), run_id=RUN1, run_seq=30, install_id=INSTALL_A),
        ]
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 1 and agent.agent_version == "2.0.0"


async def test_a_newer_runs_stop_is_not_ended_by_an_older_runs_records(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(-400), run_seq=1)])
    await site.ingest([stopping(reason="error", timestamp=_at(5), run_seq=2)])
    # Run 1's spooled events, stamped by its fast clock, with no heartbeat to say whose they are.
    await site.ingest([detection("LATE", timestamp=_at(-300))])
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.stop_run_seq == 2
    # Run 3 ends it.
    await site.ingest([heartbeat(timestamp=_at(1), run_seq=3)])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.stop_run_seq is None


async def test_a_stop_older_than_a_heartbeat_in_its_batch_is_stale(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(120), run_seq=1)])
    await site.ingest([stopping(timestamp=_at(60), run_seq=2), heartbeat(timestamp=_at(-600), run_seq=3)])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 3
    assert await _alerts(site, AlertKind.AGENT_STOPPED) == []


async def test_the_stopped_process_replayed_is_not_a_restart_without_counters(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(2), uptime_seconds=10, run_id=RUN1)])
    await site.ingest([stopping(timestamp=_at(1), run_id=RUN1)])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None and agent.stop_run_id == RUN1
        agent.stop_received_at = datetime.now(UTC) - timedelta(seconds=120)
    # The same process's short-uptime heartbeat, from before its stop, retried two minutes on.
    await site.ingest([heartbeat(timestamp=_at(3), uptime_seconds=9, run_id=RUN1)])
    assert (await _agent(site)).stopped_at is not None
    # Another process with that uptime has started since.
    await site.ingest([heartbeat(timestamp=_at(0), uptime_seconds=10, run_id=RUN2)])
    assert (await _agent(site)).stopped_at is None


async def test_a_newer_runs_heartbeat_after_its_stop_still_updates_the_details(site: Site) -> None:
    # Run 1's clock ran fast; run 2's stop gets through before its heartbeat.
    await site.ingest([heartbeat(timestamp=_at(-400), run_id=RUN1, run_seq=1, agent_version="1.9.0")])
    await site.ingest([stopping(reason="error", timestamp=_at(5), run_id=RUN2, run_seq=2)])
    await site.ingest([heartbeat(timestamp=_at(10), run_id=RUN2, run_seq=2, agent_version="1.9.2")])
    agent = await _agent(site)
    assert agent.agent_version == "1.9.2" and agent.heartbeat_run_seq == 2
    assert agent.stopped_at is not None


async def test_stops_at_the_same_time_take_the_last_sent(site: Site) -> None:
    when = _at(5)
    await site.ingest([stopping(reason="signal", timestamp=when), stopping(reason="error", timestamp=when, error="boom")])
    assert (await _agent(site)).stop_reason == "error"


async def test_an_unseen_installs_replay_never_takes_over(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(5), run_id=RUN2, run_seq=5, install_id=INSTALL_B, agent_version="2.0.0")])
    # The spool of an install the manager never heard from, replayed late.
    await site.ingest([stopping(timestamp=_at(4800), run_id=RUN1, run_seq=2, install_id=INSTALL_A)])
    await site.ingest([heartbeat(timestamp=_at(4900), run_id=RUN1, run_seq=2, install_id=INSTALL_A, agent_version="1.0")])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.install_ids == [INSTALL_B] and agent.run_seq == 5
    assert agent.agent_version == "2.0.0"
    await site.ingest([heartbeat(timestamp=_at(1), run_id=RUN2, run_seq=5, install_id=INSTALL_B, agent_version="2.0.1")])
    assert (await _agent(site)).agent_version == "2.0.1"


async def test_a_numbered_stop_ends_with_a_later_run_that_cannot_count(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(400), run_id=RUN1, run_seq=1, install_id=INSTALL_A)])
    await site.ingest([stopping(timestamp=_at(300), run_id=RUN1, run_seq=1, install_id=INSTALL_A)])
    assert (await _agent(site)).stopped_at is not None
    # The next run could not keep its counter, and has been up a while.
    await site.ingest([heartbeat(timestamp=_at(1), uptime_seconds=290, run_id=RUN2)])
    assert (await _agent(site)).stopped_at is None


async def test_the_first_install_id_after_bare_counters_is_a_new_count(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_seq=30)])
    await site.ingest([stopping(timestamp=_at(30), run_seq=30)])
    await site.ingest([heartbeat(timestamp=_at(2), run_id=RUN2, run_seq=1, install_id=INSTALL_A)])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 1 and agent.install_ids == [INSTALL_A]


async def test_a_replay_does_not_undo_a_newer_heartbeat_without_a_counter(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=3, agent_version="1.0")])
    await site.ingest([heartbeat(timestamp=_at(30), run_id=RUN2, agent_version="2.0")])
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=3, agent_version="1.0")])
    assert (await _agent(site)).agent_version == "2.0"


async def test_the_newest_runs_stop_wins_whatever_the_clocks(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(600), run_seq=1)])
    await site.ingest(
        [stopping(reason="signal", timestamp=_at(-300), run_seq=2), stopping(reason="error", timestamp=_at(10), run_seq=3)]
    )
    agent = await _agent(site)
    assert agent.stop_reason == "error" and agent.run_seq == 3


async def test_a_first_numbered_stop_before_its_runs_heartbeat_is_ignored(site: Site) -> None:
    await site.ingest([stopping(timestamp=_at(20), run_seq=1), heartbeat(timestamp=_at(10), run_seq=1)])
    assert (await _agent(site)).stopped_at is None


async def test_rotating_the_token_forgets_the_run_counter(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_seq=30, install_id=INSTALL_A)])
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        fleet.rotate_token(agent, now=datetime.now(UTC))
        assert agent.run_seq is None and agent.install_ids == []


async def test_a_slow_clocked_new_install_is_still_heard(site: Site) -> None:
    # The new install's clock runs 20 minutes slow, beyond the allowed skew.
    await site.ingest([heartbeat(timestamp=_at(3000), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    await site.ingest([stopping(timestamp=_at(2900), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    await site.ingest([heartbeat(timestamp=_at(1200), run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.install_ids == [INSTALL_A, INSTALL_B] and agent.run_seq == 1
    # Its own stops end by its next run as usual.
    await site.ingest([stopping(timestamp=_at(1100), run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    assert (await _agent(site)).stop_run_seq == 1
    await site.ingest([heartbeat(timestamp=_at(1000), run_id=RUN1, run_seq=2, install_id=INSTALL_B)])
    assert (await _agent(site)).stopped_at is None


async def test_a_stop_that_cannot_be_ordered_is_ended_by_clocks(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(600), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    # An install never seen, with no heartbeat of its own to vouch for it.
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.stop_run_seq is None
    await site.ingest([detection("BACK", timestamp=_at(5))])
    assert (await _agent(site)).stopped_at is None


async def test_a_future_stamped_replay_from_an_unseen_install_never_takes_over(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(5), run_id=RUN2, run_seq=5, install_id=INSTALL_B, agent_version="2.0.0")])
    # Stamped a day ahead, so the receive time stands in for it.
    await site.ingest([heartbeat(timestamp=_at(-86400), run_id=RUN1, run_seq=2, install_id=INSTALL_A, agent_version="1.0")])
    agent = await _agent(site)
    assert agent.install_ids == [INSTALL_B] and agent.run_seq == 5
    await site.ingest([heartbeat(timestamp=_at(1), run_id=RUN2, run_seq=5, install_id=INSTALL_B, agent_version="2.0.1")])
    assert (await _agent(site)).agent_version == "2.0.1"


async def _age_agent(site: Site, **fields: timedelta) -> None:
    """Move the named times on the agent row back by the given amounts."""
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        for name, by in fields.items():
            setattr(agent, name, getattr(agent, name) - by)


async def test_a_fast_clocked_new_install_is_adopted_once_its_uptime_proves_it_live(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    # The reinstalled agent's clock runs an hour ahead, so its stamps are replaced.
    ahead = _at(-3600)
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=10, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    agent = await _agent(site)
    assert agent.install_ids == [INSTALL_A] and agent.pending_install_id == INSTALL_B
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=ahead, uptime_seconds=100, run_id=RUN2, run_seq=1, install_id=INSTALL_B, agent_version="2.0")]
    )
    agent = await _agent(site)
    assert agent.install_ids == [INSTALL_A, INSTALL_B] and agent.stopped_at is None and agent.agent_version == "2.0"
    assert agent.pending_install_id is None


async def test_a_replayed_burst_from_an_unseen_install_proves_nothing(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    ahead = _at(-3600)
    for uptime in (10, 70, 130):
        await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=uptime, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    # Spread out, but the uptime grew far faster than the manager's clock.
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=3600, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    assert (await _agent(site)).install_ids == [INSTALL_A]


async def test_an_uncounted_restart_on_a_fast_clock_ends_a_numbered_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    await _age_agent(site, stop_received_at=timedelta(seconds=120))
    await site.ingest([heartbeat(timestamp=_at(-3600), uptime_seconds=5, run_id=RUN2)])
    assert (await _agent(site)).stopped_at is None


async def test_the_running_agents_heartbeat_wins_whatever_its_count_or_clock(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    # Restored from a backup: the same install counts from 11, and its clock is an hour slow.
    await site.ingest(
        [heartbeat(timestamp=_at(3600), uptime_seconds=10, run_id=RUN2, run_seq=11, install_id=INSTALL_A)],
        delivery="live",
    )
    # One heartbeat is not enough: it could be an old run's, held up on the way.
    assert (await _agent(site)).run_seq == 30
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(3510), uptime_seconds=100, run_id=RUN2, run_seq=11, install_id=INSTALL_A, agent_version="2.0")],
        delivery="live",
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 11 and agent.agent_version == "2.0"
    # A spooled batch of the run before, replayed after, changes nothing.
    await site.ingest(
        [heartbeat(timestamp=_at(40), run_id=RUN1, run_seq=30, install_id=INSTALL_A, agent_version="1.0")],
        delivery="replay",
        sender_run=RUN2,
    )
    agent = await _agent(site)
    assert agent.agent_version == "2.0"


async def test_a_running_new_install_is_heard_at_once(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    # Its clock runs an hour ahead, so its stamp is replaced, but it says it is running.
    await site.ingest([heartbeat(timestamp=_at(-3600), run_id=RUN2, run_seq=1, install_id=INSTALL_B)], delivery="live")
    agent = await _agent(site)
    assert agent.install_ids == [INSTALL_A, INSTALL_B] and agent.stopped_at is None


async def test_a_replayed_unseen_install_never_takes_over_whatever_its_stamp(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(3600), run_id=RUN2, run_seq=5, install_id=INSTALL_B)], delivery="live")
    # Stamped later than the slow running agent's heartbeat, but resent from a spool.
    await site.ingest(
        [heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=2, install_id=INSTALL_A, agent_version="1.0")],
        delivery="replay",
    )
    agent = await _agent(site)
    assert agent.install_ids == [INSTALL_B] and agent.agent_version != "1.0"


async def test_a_running_agent_that_cannot_count_ends_a_numbered_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    # A fast clock, no counter, and long up: only the delivery says it is back.
    await site.ingest([heartbeat(timestamp=_at(-3600), uptime_seconds=99999, run_id=RUN2)], delivery="live")
    assert (await _agent(site)).stopped_at is None


async def test_a_replayed_uncounted_heartbeat_does_not_end_a_numbered_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(600), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(300), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await _age_agent(site, stop_received_at=timedelta(seconds=120))
    await site.ingest([heartbeat(timestamp=_at(5), uptime_seconds=5, run_id=RUN2)], delivery="replay")
    assert (await _agent(site)).stopped_at is not None


async def test_a_held_up_live_heartbeat_of_an_older_run_changes_nothing(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(5), run_id=RUN2, run_seq=6, install_id=INSTALL_A, agent_version="2.0")], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(3), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    # Run 5's last batch, delayed by a proxy, arrives after run 6 stopped.
    await site.ingest(
        [heartbeat(timestamp=_at(60), uptime_seconds=600, run_id=RUN1, run_seq=5, install_id=INSTALL_A, agent_version="1.0")],
        delivery="live",
    )
    agent = await _agent(site)
    assert agent.run_seq == 6 and agent.agent_version == "2.0" and agent.stopped_at is not None


async def test_a_replay_of_the_running_processs_own_heartbeat_counts_as_live(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(30), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    # Run 6, a new install, spooled its first heartbeat during an outage and resends it itself.
    await site.ingest(
        [heartbeat(timestamp=_at(-3600), run_id=RUN2, run_seq=1, install_id=INSTALL_B)], delivery="replay", sender_run=RUN2
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.install_ids == [INSTALL_A, INSTALL_B]


async def test_a_late_older_sample_does_not_hold_back_the_pending_proof(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    ahead = _at(-3600)
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=3600, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    # The same process's spooled heartbeat from long before, resent late.
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=30, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    assert (await _agent(site)).pending_uptime == 3600
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=3690, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    assert (await _agent(site)).install_ids == [INSTALL_A, INSTALL_B]


async def test_a_counter_rollback_lowers_the_count_and_restarts_the_watermark(site: Site) -> None:
    # Run 30's clock ran an hour fast; no stop was ever sent.
    await site.ingest(
        [heartbeat(timestamp=_at(-3000), uptime_seconds=10, run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=10, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=100, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.run_seq == 11 and agent.live_run_id == RUN2
    # Its stop, stamped by the corrected clock, counts.
    await site.ingest([stopping(timestamp=_at(5), run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live")
    assert (await _agent(site)).stopped_at is not None


async def test_a_replayed_stop_from_before_a_rollback_is_stale(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(60), uptime_seconds=10, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None and agent.live_run_id == RUN2
    # The run-30 timeline's stop, its clock ahead, resent from a spool that survived.
    await site.ingest(
        [stopping(timestamp=_at(-300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="replay", sender_run=RUN2
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 11


async def test_replays_before_any_live_report_still_advance_through_runs(site: Site) -> None:
    for run, version in ((1, "1.0"), (2, "1.1"), (3, "1.2")):
        await site.ingest(
            [heartbeat(timestamp=_at(600 - run * 60), run_id=RUN1, run_seq=run, install_id=INSTALL_A, agent_version=version)],
            delivery="replay",
        )
    agent = await _agent(site)
    assert agent.run_seq == 3 and agent.agent_version == "1.2" and agent.live_run_id is None


async def test_an_older_same_run_heartbeat_on_a_fast_clock_does_not_undo_a_newer_one(site: Site) -> None:
    ahead = _at(-3600)
    await site.ingest(
        [heartbeat(timestamp=ahead, uptime_seconds=200, run_id=RUN1, run_seq=3, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=ahead, uptime_seconds=100, run_id=RUN1, run_seq=3, install_id=INSTALL_A)],
        delivery="replay",
        sender_run=RUN1,
    )
    assert (await _agent(site)).uptime_seconds == 200


async def test_huge_uptimes_never_fail_a_batch(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)])
    ahead = _at(-3600)
    await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=1, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    response = await site.ingest([heartbeat(timestamp=ahead, uptime_seconds=2**62, run_id=RUN2, run_seq=1, install_id=INSTALL_B)])
    assert response.status_code == 200


async def test_a_new_process_that_repeats_a_count_is_heard(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(60), uptime_seconds=100000, run_id=RUN1, run_seq=10, install_id=INSTALL_A, healthy=True)],
        delivery="live",
    )
    # Restored to a snapshot taken at 9, the next process counts 10 again.
    await site.ingest(
        [heartbeat(timestamp=_at(5), uptime_seconds=5, run_id=RUN2, run_seq=10, install_id=INSTALL_A, healthy=False)],
        delivery="live",
    )
    agent = await _agent(site)
    assert agent.healthy is False and agent.heartbeat_run_id == RUN2


async def test_an_uncounted_processs_own_replay_does_not_undo_its_live_heartbeat(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(5), uptime_seconds=300, run_id=RUN1, agent_version="3")], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(205), uptime_seconds=100, run_id=RUN1, agent_version="1")],
        delivery="replay",
        sender_run=RUN1,
    )
    agent = await _agent(site)
    assert agent.uptime_seconds == 300 and agent.agent_version == "3"


RUN3 = "c" * 32


async def test_a_newer_senders_replay_of_a_run_in_between_still_counts(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(120), run_id=RUN1, run_seq=11, install_id=INSTALL_A)], delivery="live")
    # Run 12 stopped during an outage; run 13 uploads its spooled stop first.
    await site.ingest(
        [stopping(timestamp=_at(60), run_id=RUN2, run_seq=12, install_id=INSTALL_A)], delivery="replay", sender_run=RUN3
    )
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.run_seq == 12


async def test_a_held_up_predecessors_live_stop_does_not_mark_the_agent_stopped(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=29, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=5, run_id=RUN2, run_seq=30, install_id=INSTALL_A)], delivery="live"
    )
    # Run 29's last requests, held up on the way, arrive after.
    await site.ingest(
        [heartbeat(timestamp=_at(30), uptime_seconds=900, run_id=RUN1, run_seq=29, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(20), run_id=RUN1, run_seq=29, install_id=INSTALL_A)], delivery="live")
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.retired_run_ids == [RUN1] and agent.live_run_id == RUN2


async def test_replays_from_a_process_awaiting_proof_of_its_lower_count_are_capped(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    # Inside the proof window, it replays a spooled stop from the old timeline.
    await site.ingest(
        [stopping(timestamp=_at(5), run_id=RUN3, run_seq=31, install_id=INSTALL_A)], delivery="replay", sender_run=RUN2
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 30


async def test_the_replaced_processs_records_stay_stale_whoever_sends_them(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(100), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=95, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).retired_run_ids == [RUN1]
    # The next process replays run 30's old stop before its own heartbeat.
    await site.ingest(
        [stopping(timestamp=_at(5), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="replay", sender_run=RUN3
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 11


async def test_an_inherited_heartbeat_with_the_same_count_does_not_replace_the_senders(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=50, run_id=RUN2, run_seq=10, install_id=INSTALL_A, agent_version="2")],
        delivery="live",
    )
    # An older process's sample with the same count, stamped by a faster clock.
    await site.ingest(
        [heartbeat(timestamp=_at(-300), uptime_seconds=9000, run_id=RUN1, run_seq=10, install_id=INSTALL_A, agent_version="1")],
        delivery="replay",
        sender_run=RUN2,
    )
    assert (await _agent(site)).agent_version == "2"


async def test_a_new_uncounted_processs_own_first_heartbeat_wins_when_replayed(site: Site) -> None:
    # The previous process's clock ran ahead.
    await site.ingest([heartbeat(timestamp=_at(-400), uptime_seconds=900, run_id=RUN1, agent_version="1")], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(30), uptime_seconds=3, run_id=RUN2, agent_version="2")], delivery="replay", sender_run=RUN2
    )
    assert (await _agent(site)).agent_version == "2"


async def test_a_retired_senders_late_replay_moves_nothing(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(100), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=95, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    # A delayed replay sent by the retired run 30, of an older run's stop.
    await site.ingest(
        [stopping(timestamp=_at(5), run_id=RUN3, run_seq=29, install_id=INSTALL_A)], delivery="replay", sender_run=RUN1
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 11 and agent.live_run_id == RUN2


async def test_every_retired_process_stays_retired(site: Site) -> None:
    for seq, (run, version) in enumerate(((RUN1, "1"), (RUN2, "2"), (RUN3, "3")), start=1):
        await site.ingest(
            [
                heartbeat(
                    timestamp=_at(30), uptime_seconds=5, run_id=run, run_seq=seq, install_id=INSTALL_A, agent_version=version
                )
            ],
            delivery="live",
        )
    agent = await _agent(site)
    assert agent.agent_version == "3"
    # Run 1's delayed replay of its own heartbeat.
    await site.ingest(
        [heartbeat(timestamp=_at(400), uptime_seconds=1, run_id=RUN1, agent_version="1")], delivery="replay", sender_run=RUN1
    )
    agent = await _agent(site)
    assert agent.agent_version == "3" and agent.live_run_id == RUN3


async def test_a_rollback_proof_completes_with_frequent_heartbeats(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=7, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=7, install_id=INSTALL_A)], delivery="live")
    # The counter went back; the new process reports every 10 seconds.
    for uptime in range(0, 80, 10):
        await site.ingest(
            [heartbeat(timestamp=_at(80 - uptime), uptime_seconds=uptime, run_id=RUN2, run_seq=6, install_id=INSTALL_A)],
            delivery="live",
        )
        if (await _agent(site)).pending_seen_at is not None:
            await _age_agent(site, pending_seen_at=timedelta(seconds=10))
    agent = await _agent(site)
    assert agent.run_seq == 6 and agent.stopped_at is None and agent.heartbeat_run_id == RUN2


async def test_a_lower_counts_stop_awaiting_proof_is_left_to_the_offline_alert(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(120), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    # Unproven, it could be an old run's stop held up on the way.
    await site.ingest([stopping(timestamp=_at(10), run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live")
    assert (await _agent(site)).stopped_at is None


async def test_a_replay_that_advances_the_run_retires_the_reporter(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=10, install_id=INSTALL_A)], delivery="live")
    # Run 12 replays run 11's heartbeat before sending its own.
    await site.ingest(
        [heartbeat(timestamp=_at(200), run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="replay", sender_run=RUN3
    )
    agent = await _agent(site)
    assert agent.run_seq == 11 and agent.retired_run_ids == [RUN1]


async def test_reporters_without_counters_are_never_retired(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(30), uptime_seconds=5, run_id=RUN3, agent_version="3")], delivery="live")
    # Delayed live heartbeats from two older processes, then the running one again.
    for run in (RUN1, RUN2):
        await site.ingest([heartbeat(timestamp=_at(20), uptime_seconds=900, run_id=run, agent_version="old")], delivery="live")
    await site.ingest([heartbeat(timestamp=_at(1), uptime_seconds=34, run_id=RUN3, agent_version="3")], delivery="live")
    agent = await _agent(site)
    assert agent.retired_run_ids == [] and agent.agent_version == "3"


async def test_a_newer_runs_live_report_drops_someone_elses_pending_proof(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(120), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(100), uptime_seconds=900, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).pending_run_id == RUN2
    await site.ingest([heartbeat(timestamp=_at(5), run_id=RUN3, run_seq=31, install_id=INSTALL_A)], delivery="live")
    assert (await _agent(site)).pending_run_id is None


async def test_a_running_process_retired_by_a_held_up_request_comes_back(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=8, install_id=INSTALL_A)], delivery="live")
    # Restored: run 6 proves its lower count.
    await site.ingest(
        [heartbeat(timestamp=_at(100), uptime_seconds=5, run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(10), uptime_seconds=95, run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live"
    )
    # A dead run 9's live request, held up on the way, arrives and takes over.
    await site.ingest(
        [heartbeat(timestamp=_at(200), uptime_seconds=40, run_id=RUN3, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.run_seq == 9 and RUN2 in agent.retired_run_ids
    # Run 6 keeps reporting, its uptime in step with the manager's clock.
    await site.ingest(
        [heartbeat(timestamp=_at(5), uptime_seconds=100, run_id=RUN2, run_seq=6, install_id=INSTALL_A, agent_version="6")],
        delivery="live",
        sender_run=RUN2,
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(1), uptime_seconds=190, run_id=RUN2, run_seq=6, install_id=INSTALL_A, agent_version="6")],
        delivery="live",
        sender_run=RUN2,
    )
    agent = await _agent(site)
    assert agent.run_seq == 6 and agent.live_run_id == RUN2 and RUN2 not in agent.retired_run_ids
    assert RUN3 in agent.retired_run_ids and agent.agent_version == "6" and agent.stopped_at is None


async def test_a_promoted_older_replay_does_not_drop_another_runs_proof(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(300), uptime_seconds=500, run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(400), uptime_seconds=400, run_id=RUN1, run_seq=30, install_id=INSTALL_A)],
        delivery="replay",
        sender_run=RUN1,
    )
    assert (await _agent(site)).pending_run_id == RUN2


async def test_a_single_sample_from_another_process_does_not_take_a_proof_under_way(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(200), uptime_seconds=60, run_id=RUN3, run_seq=12, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).pending_run_id == RUN2


async def test_an_agent_heard_from_after_its_stop_can_still_go_offline(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    # A restored run 11 reports once, then crashes before proving its count.
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    config = site.manager.config
    later = datetime.now(UTC) + timedelta(seconds=config.agent_offline_seconds + 5)
    async with site.manager.database.session() as session:
        raised = await fleet.raise_offline_alerts(
            session,
            now=later,
            offline_after=timedelta(seconds=config.agent_offline_seconds),
            dialect=site.manager.database.dialect,
        )
    assert raised == 1


async def test_a_held_up_uncounted_heartbeat_does_not_end_a_later_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), uptime_seconds=5, run_id=RUN1)], delivery="live")
    await site.ingest([heartbeat(timestamp=_at(100), uptime_seconds=5, run_id=RUN2)], delivery="live")
    await site.ingest([stopping(timestamp=_at(50), run_id=RUN2)], delivery="live")
    # Run 1's live heartbeat from before, held up on the way.
    await site.ingest([heartbeat(timestamp=_at(290), uptime_seconds=15, run_id=RUN1)], delivery="live")
    assert (await _agent(site)).stopped_at is not None


async def test_a_dead_retired_processs_held_requests_do_not_revive_it_over_a_stop(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(900), uptime_seconds=60, run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(600), uptime_seconds=5, run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(500), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    # Two of run 5's live heartbeats, held up alike, arrive a minute apart.
    await site.ingest(
        [heartbeat(timestamp=_at(840), uptime_seconds=120, run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live"
    )
    if (await _agent(site)).pending_seen_at is not None:
        await _age_agent(site, pending_seen_at=timedelta(seconds=60))
    await site.ingest(
        [heartbeat(timestamp=_at(780), uptime_seconds=180, run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.run_seq == 6 and RUN1 in agent.retired_run_ids


async def _offline_alerts_raised(site: Site) -> int:
    config = site.manager.config
    later = datetime.now(UTC) + timedelta(seconds=config.agent_offline_seconds + 5)
    async with site.manager.database.session() as session:
        return await fleet.raise_offline_alerts(
            session,
            now=later,
            offline_after=timedelta(seconds=config.agent_offline_seconds),
            dialect=site.manager.database.dialect,
        )


async def test_a_clean_stops_trailing_batch_raises_no_offline_alert(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(60), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [stopping(timestamp=_at(10), run_id=RUN1, run_seq=5, install_id=INSTALL_A), detection("A", timestamp=_at(11))],
        delivery="live",
    )
    # The shutdown flush's second batch: older records, no heartbeat.
    await site.ingest([detection("B", timestamp=_at(12))], delivery="live", sender_run=RUN1)
    assert await _offline_alerts_raised(site) == 0


async def test_a_wrongly_retired_process_with_a_fast_clock_comes_back_over_a_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=8, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(200), uptime_seconds=5, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    # A dead run 10's held-up heartbeat and stop retire run 9 and mark the agent stopped.
    await site.ingest(
        [heartbeat(timestamp=_at(150), uptime_seconds=40, run_id=RUN3, run_seq=10, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(140), run_id=RUN3, run_seq=10, install_id=INSTALL_A)], delivery="live")
    agent = await _agent(site)
    assert agent.stopped_at is not None and RUN2 in agent.retired_run_ids
    # Run 9 keeps reporting; its clock is an hour ahead, so its stamps are
    # replaced and vouch for nothing: the proof runs for longer.
    ahead = _at(-3600)
    await site.ingest(
        [heartbeat(timestamp=ahead, uptime_seconds=100, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=200))
    await site.ingest(
        [heartbeat(timestamp=ahead, uptime_seconds=300, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and RUN2 not in agent.retired_run_ids


async def test_a_lower_count_senders_replays_are_capped_without_the_proof_slot(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    # A delayed run 12 heartbeat takes the proof slot first.
    await site.ingest(
        [heartbeat(timestamp=_at(250), uptime_seconds=50, run_id=RUN3, run_seq=12, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(20), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.pending_run_id == RUN3 and RUN2 in agent.lower_run_ids
    # Run 11 replays a pre-rollback run 31 stop.
    await site.ingest(
        [stopping(timestamp=_at(10), run_id="d" * 32, run_seq=31, install_id=INSTALL_A)], delivery="replay", sender_run=RUN2
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and agent.run_seq == 30


async def test_an_own_replay_that_advances_the_run_drops_an_old_proof(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(250), uptime_seconds=50, run_id=RUN2, run_seq=12, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).pending_run_id == RUN2
    await site.ingest(
        [heartbeat(timestamp=_at(30), uptime_seconds=5, run_id=RUN3, run_seq=31, install_id=INSTALL_A)],
        delivery="replay",
        sender_run=RUN3,
    )
    agent = await _agent(site)
    assert agent.run_seq == 31 and agent.pending_run_id is None


async def test_a_wrongly_retired_process_with_a_slow_clock_comes_back_after_a_longer_proof(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=8, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [heartbeat(timestamp=_at(200), uptime_seconds=5, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest(
        [heartbeat(timestamp=_at(150), uptime_seconds=40, run_id=RUN3, run_seq=10, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(140), run_id=RUN3, run_seq=10, install_id=INSTALL_A)], delivery="live")
    # Run 9's clock is an hour slow: its stamps are its own but say nothing current.
    await site.ingest(
        [heartbeat(timestamp=_at(3600), uptime_seconds=100, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    await _age_agent(site, pending_seen_at=timedelta(seconds=90))
    await site.ingest(
        [heartbeat(timestamp=_at(3510), uptime_seconds=190, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).stopped_at is not None
    await _age_agent(site, pending_seen_at=timedelta(seconds=110))
    await site.ingest(
        [heartbeat(timestamp=_at(3400), uptime_seconds=300, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    agent = await _agent(site)
    assert agent.stopped_at is None and RUN2 not in agent.retired_run_ids


async def test_a_new_process_that_sends_only_events_and_dies_still_goes_offline(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    # The next process sends a detection, then crashes before any heartbeat.
    await site.ingest([detection("NEW", timestamp=_at(280))], delivery="live", sender_run=RUN2)
    assert await _offline_alerts_raised(site) == 1


async def test_rotating_the_token_keeps_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([detection("NEW", timestamp=_at(280))], delivery="live", sender_run=RUN2)
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        fleet.rotate_token(agent, now=datetime.now(UTC))
    assert (await _agent(site)).heard_after_stop_at is not None


async def test_a_held_up_predecessors_heartbeat_after_a_clean_stop_raises_no_offline_alert(site: Site) -> None:
    await site.ingest(
        [heartbeat(timestamp=_at(300), uptime_seconds=600, run_id=RUN2, run_seq=5, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN2, run_seq=5, install_id=INSTALL_A)], delivery="live")
    # Run 4, which never got a live batch through, has one held-up heartbeat arrive.
    await site.ingest(
        [heartbeat(timestamp=_at(1000), uptime_seconds=900, run_id=RUN1, run_seq=4, install_id=INSTALL_A)], delivery="live"
    )
    assert await _offline_alerts_raised(site) == 0


async def test_a_replacements_own_replayed_heartbeat_counts_as_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    # Restored to count 11, it spools its first heartbeat, resends it, and crashes.
    await site.ingest(
        [heartbeat(timestamp=_at(100), uptime_seconds=5, run_id=RUN2, run_seq=11, install_id=INSTALL_A)],
        delivery="replay",
        sender_run=RUN2,
    )
    assert await _offline_alerts_raised(site) == 1


async def test_rotating_the_token_keeps_the_stopped_runs_identity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        fleet.rotate_token(agent, now=datetime.now(UTC))
    assert (await _agent(site)).stop_run_id == RUN1


async def test_a_replay_that_delivers_the_previous_stop_counts_as_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest(
        [stopping(timestamp=_at(290), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="replay", sender_run=RUN2
    )
    agent = await _agent(site)
    assert agent.stopped_at is not None and agent.heard_after_stop_at is not None


async def test_a_held_up_stop_only_batch_is_no_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    # An older run's stop, held up on the way.
    await site.ingest(
        [stopping(timestamp=_at(900), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live", sender_run=RUN1
    )
    assert await _offline_alerts_raised(site) == 0


async def test_a_held_up_stop_with_a_replaced_stamp_is_no_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    # Stamped an hour ahead, so the receive time stands in for it.
    await site.ingest(
        [stopping(timestamp=_at(-3600), run_id=RUN1, run_seq=5, install_id=INSTALL_A)], delivery="live", sender_run=RUN1
    )
    assert await _offline_alerts_raised(site) == 0


async def test_a_retried_stop_seen_before_is_no_post_stop_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    old_stop = stopping(timestamp=_at(100), run_id=RUN1, run_seq=5, install_id=INSTALL_A)
    # The older run's stop, fast-stamped, arrives and is rejected first.
    await site.ingest([old_stop], delivery="live", sender_run=RUN1)
    await site.ingest([stopping(timestamp=_at(200), run_id=RUN2, run_seq=6, install_id=INSTALL_A)], delivery="live")
    # A retry of the same batch.
    await site.ingest([old_stop], delivery="live", sender_run=RUN1)
    assert await _offline_alerts_raised(site) == 0


async def test_a_held_up_early_heartbeat_does_not_seem_to_start_after_the_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(1200), run_id=RUN2, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(1100), run_id=RUN2, run_seq=5, install_id=INSTALL_A)], delivery="live")
    await _age_agent(site, stop_received_at=timedelta(seconds=20))
    # Run 4's first heartbeat (up 5 seconds), held up since well before the stop.
    await site.ingest(
        [heartbeat(timestamp=_at(1210), uptime_seconds=5, run_id=RUN1, run_seq=4, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).heard_after_stop_at is None


async def test_a_held_up_heartbeat_with_a_repeated_count_does_not_end_a_clean_stop(site: Site) -> None:
    # After a rollback, run 9 is counted twice; the second stops cleanly.
    await site.ingest(
        [heartbeat(timestamp=_at(60), uptime_seconds=400, run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    await site.ingest([stopping(timestamp=_at(50), run_id=RUN2, run_seq=9, install_id=INSTALL_A)], delivery="live")
    # The first run 9's live heartbeat, held up since before.
    await site.ingest(
        [heartbeat(timestamp=_at(400), uptime_seconds=10, run_id=RUN1, run_seq=9, install_id=INSTALL_A)], delivery="live"
    )
    assert (await _agent(site)).stopped_at is not None
    assert await _offline_alerts_raised(site) == 0


async def test_a_held_up_uncounted_heartbeat_does_not_seem_to_start_after_the_stop(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(400), uptime_seconds=400, run_id=RUN2)], delivery="live")
    await site.ingest([stopping(timestamp=_at(300), run_id=RUN2)], delivery="live")
    await _age_agent(site, stop_received_at=timedelta(seconds=30))
    # An earlier process's first heartbeat (up 10 seconds), held up for minutes.
    await site.ingest([heartbeat(timestamp=_at(500), uptime_seconds=10, run_id=RUN1)], delivery="live")
    assert (await _agent(site)).stopped_at is not None


async def test_a_later_stop_only_batch_from_another_process_counts_as_activity(site: Site) -> None:
    await site.ingest([heartbeat(timestamp=_at(300), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    await site.ingest([stopping(timestamp=_at(290), run_id=RUN1, run_seq=30, install_id=INSTALL_A)], delivery="live")
    # A restored run 11 sends only its own stop, stamped later, and is gone.
    await site.ingest(
        [stopping(timestamp=_at(30), run_id=RUN2, run_seq=11, install_id=INSTALL_A)], delivery="live", sender_run=RUN2
    )
    assert await _offline_alerts_raised(site) == 1
