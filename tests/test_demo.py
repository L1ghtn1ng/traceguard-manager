"""Sample data goes through the real ingest path and stays apart from real agents."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from traceguard_manager import demo, fleet
from traceguard_manager.config import Config
from traceguard_manager.db import Database
from traceguard_manager.ingest import parse_batch
from traceguard_manager.models import Agent, Alert, AlertKind, AlertStatus

from .conftest import Site

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def test_records_are_repeatable_and_all_valid() -> None:
    first = demo.build_records(now=NOW)
    assert first == demo.build_records(now=NOW)
    kinds: set[AlertKind] = set()
    for host, records in first.items():
        batch = parse_batch(records, now=NOW)
        assert batch.invalid == 0, host
        assert batch.ignored == 0, host
        assert batch.heartbeat is not None, host
        kinds |= {alert.kind for alert in batch.alerts}
    assert kinds == set(AlertKind) - {AlertKind.AGENT_OFFLINE}  # every type an agent can report has an example


async def test_seed_fills_every_fleet_state_and_alert_status(config: Config) -> None:
    database = Database(config)
    try:
        await database.create_all()
        async with database.session() as session:
            summary = await demo.seed(session, now=NOW, dialect=database.dialect)
        # Everything the hosts reported, plus the alert raised for the host that went quiet.
        assert summary.alerts == demo.RECENT_ALERTS + demo.OLDER_ALERTS + 1

        async with database.session() as session:
            _, fleet_summary = fleet.describe_fleet(
                await fleet.list_agents(session), now=NOW, offline_after=timedelta(minutes=15)
            )
            statuses = dict((await session.execute(select(Alert.status, func.count()).group_by(Alert.status))).all())
        assert fleet_summary.total == summary.agents
        assert (fleet_summary.online, fleet_summary.degraded, fleet_summary.offline, fleet_summary.pending) == (3, 1, 1, 1)
        assert fleet_summary.drifted == 1
        assert set(statuses) == {status.value for status in AlertStatus}  # including muted, from the sample mute rule

        async with database.session() as session:
            with pytest.raises(demo.DemoError, match="already present"):
                await demo.seed(session, now=NOW, dialect=database.dialect)
    finally:
        await database.dispose()


async def test_seed_refuses_to_mix_with_real_agents_and_remove_leaves_them(site: Site) -> None:
    database = site.manager.database
    async with database.session() as session:
        with pytest.raises(demo.DemoError, match="--force"):
            await demo.seed(session, now=NOW, dialect=database.dialect)
    async with database.session() as session:
        await demo.seed(session, now=NOW, dialect=database.dialect, force=True)
    async with database.session() as session:
        assert await demo.remove(session) == len(demo.HOSTS) + 1
    async with database.session() as session:
        assert list(await session.scalars(select(Agent.name))) == ["web-01"]
        assert await session.scalar(select(func.count()).select_from(Alert)) == 0
