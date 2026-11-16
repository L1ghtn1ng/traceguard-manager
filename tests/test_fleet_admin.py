"""Finding agents, renaming and tagging them, noticing when one goes quiet, and searching the audit log."""

from datetime import timedelta

from sqlalchemy import select, update

from traceguard_manager import fleet
from traceguard_manager.models import Agent, Alert, AuditEvent, utcnow

from .conftest import Site
from .helpers import data, detection, heartbeat

OFFLINE_AFTER = timedelta(minutes=15)


async def _enrol(site: Site, *names: str) -> dict[str, str]:
    """Enrol agents and return their tokens by name."""
    admin = await site.admin()
    tokens = {}
    for name in names:
        tokens[name] = str(data(await admin.post("/agents", {"name": name}))["token"])
    return tokens


async def _raise_offline(site: Site) -> int:
    async with site.manager.database.session() as session:
        return await fleet.raise_offline_alerts(
            session, now=utcnow(), offline_after=OFFLINE_AFTER, dialect=site.manager.database.dialect
        )


async def test_fleet_can_be_searched_filtered_and_sorted(site: Site) -> None:
    tokens = await _enrol(site, "db-01", "db-02", "cache-01")
    await site.ingest([heartbeat("db-01")], token=tokens["db-01"])
    await site.ingest([heartbeat("db-02", unavailable_hooks=["lsm/file_open"])], token=tokens["db-02"])
    admin = await site.admin()
    async with site.manager.database.session() as session:
        ids = dict((await session.execute(select(Agent.name, Agent.id))).all())
    assert (await admin.send("PATCH", f"/agents/{ids['db-01']}", {"tags": "prod, database"})).status_code == 200
    assert (await admin.send("PATCH", f"/agents/{ids['cache-01']}", {"tags": "prod"})).status_code == 200

    def rows(text: str) -> list[str]:
        table = text.split('data-testid="agents-table"')[1]
        return [chunk.split('">')[1].split("<")[0] for chunk in table.split('class="row-link" href="/agents/')[1:]]

    viewer = await site.viewer()
    assert rows((await viewer.get("/agents")).text) == ["cache-01", "db-01", "db-02", "web-01"]
    assert rows((await viewer.get("/agents?q=DB-")).text) == ["db-01", "db-02"]
    assert rows((await viewer.get("/agents?status=degraded")).text) == ["db-02"]
    assert rows((await viewer.get("/agents?status=pending")).text) == ["cache-01", "web-01"]
    assert rows((await viewer.get("/agents?tag=prod")).text) == ["cache-01", "db-01"]
    assert rows((await viewer.get("/agents?q=database")).text) == ["db-01"]  # tags are searched too
    assert rows((await viewer.get("/agents?sort=name&dir=desc")).text) == ["web-01", "db-02", "db-01", "cache-01"]
    assert rows((await viewer.get("/agents?sort=status")).text)[0] == "db-02"  # what needs attention first

    nothing = (await viewer.get("/agents?q=zzz")).text
    assert "No agents match" in nothing and "4 agents are enrolled" in nothing
    assert (await viewer.get("/agents?status=bogus&sort=token_hash&page=-3")).status_code == 200


async def test_fleet_is_paged(site: Site) -> None:
    async with site.manager.database.session() as session:
        for index in range(fleet.PAGE_SIZE + 4):
            await fleet.enroll_agent(session, name=f"node-{index:03d}")
    viewer = await site.viewer()
    first = (await viewer.get("/agents?q=node")).text
    assert first.count('class="row-link" href="/agents/') == fleet.PAGE_SIZE
    assert "Page 1 of 2" in first and 'href="/agents?q=node&amp;page=2"' in first
    assert (await viewer.get("/agents?q=node&page=2")).text.count('class="row-link" href="/agents/') == 4


async def test_agents_can_be_renamed_and_tagged(site: Site) -> None:
    await _enrol(site, "db-01")
    admin = await site.admin()
    renamed = await admin.send("PATCH", f"/agents/{site.agent_id}", {"name": "web-frontend-01", "tags": "prod web  prod"})
    assert data(renamed) == {"name": "web-frontend-01", "tags": ["prod", "web"]}
    # The token and the history belong to the agent, not to its name.
    assert (await site.ingest([heartbeat()])).status_code == 200

    assert (await admin.send("PATCH", f"/agents/{site.agent_id}", {"name": "db-01"})).status_code == 400  # taken
    assert (await admin.send("PATCH", f"/agents/{site.agent_id}", {"name": "bad name!"})).status_code == 400
    assert (await admin.send("PATCH", f"/agents/{site.agent_id}", {"tags": "<script>"})).status_code == 400
    assert (
        await admin.send("PATCH", f"/agents/{site.agent_id}", {"tags": " ".join(f"t{n}" for n in range(20))})
    ).status_code == 400
    assert (await (await site.analyst()).send("PATCH", f"/agents/{site.agent_id}", {"tags": "mine"})).status_code == 403
    page = (await admin.get(f"/agents/{site.agent_id}")).text
    assert 'href="/agents?tag=prod"' in page


async def test_token_dialog_can_tell_when_the_agent_has_connected(site: Site) -> None:
    admin = await site.admin()
    state = data(await admin.get(f"/agents/{site.agent_id}/state", accept="application/json"))
    assert state == {"status": "pending", "connected": False}
    await site.ingest([heartbeat()])
    assert data(await admin.get(f"/agents/{site.agent_id}/state", accept="application/json")) == {
        "status": "online",
        "connected": True,
    }

    # After a rotation, only a report made with the new token counts.
    rotated = data(await admin.post(f"/agents/{site.agent_id}/rotate"))
    assert data(await admin.get(f"/agents/{site.agent_id}/state", accept="application/json"))["connected"] is False
    await site.ingest([heartbeat()], token=str(rotated["token"]))
    assert data(await admin.get(f"/agents/{site.agent_id}/state", accept="application/json"))["connected"] is True
    assert (await site.browser().get(f"/agents/{site.agent_id}/state", accept="application/json")).status_code == 401


async def test_an_agent_going_quiet_raises_one_alert_and_returning_closes_it(site: Site) -> None:
    await _enrol(site, "never-connected")
    await site.ingest([heartbeat()])
    assert await _raise_offline(site) == 0  # reporting normally

    async with site.manager.database.session() as session:
        await session.execute(update(Agent).where(Agent.name == "web-01").values(last_seen_at=utcnow() - timedelta(minutes=20)))
    assert await _raise_offline(site) == 1
    assert await _raise_offline(site) == 0  # once per outage, however often it is checked
    async with site.manager.database.session() as session:
        alert = await session.scalar(select(Alert))
    assert alert is not None
    assert (alert.kind, alert.status, alert.title) == ("agent_offline", "open", "Agent web-01 stopped reporting")
    page = (await (await site.viewer()).get("/alerts?kind=agent_offline")).text
    assert "1 matching" in page and "stopped reporting" in page

    await site.ingest([heartbeat()])
    async with site.manager.database.session() as session:
        alert = await session.scalar(select(Alert))
    assert alert is not None
    assert (alert.status, alert.status_changed_by) == ("resolved", "system")

    # A second outage is a new alert; an agent that was never seen or is disabled is not an outage.
    async with site.manager.database.session() as session:
        await session.execute(update(Agent).where(Agent.name == "web-01").values(last_seen_at=utcnow() - timedelta(minutes=30)))
    assert await _raise_offline(site) == 1
    async with site.manager.database.session() as session:
        await session.execute(update(Agent).values(enabled=False, last_seen_at=utcnow() - timedelta(minutes=40)))
    assert await _raise_offline(site) == 0


async def test_long_silent_agents_are_not_reported_as_new_outages(site: Site) -> None:
    await site.ingest([heartbeat()])
    async with site.manager.database.session() as session:
        await session.execute(update(Agent).values(last_seen_at=utcnow() - timedelta(days=3)))
    assert await _raise_offline(site) == 0


async def test_audit_log_can_be_filtered_and_shows_detail(site: Site) -> None:
    await site.ingest([detection("A")])
    analyst = await site.analyst()
    async with site.manager.database.session() as session:
        alert_id = str(await session.scalar(select(Alert.id)))
    await analyst.post("/alerts/status", {"ids": [alert_id], "status": "resolved"})
    failed = site.browser()
    await failed.login("analyst", "wrong-password-000")
    admin = await site.admin()

    everything = (await admin.get("/audit")).text
    assert "alert.status" in everything and "auth.login" in everything
    assert "&#34;status&#34;: &#34;resolved&#34;" in everything  # the stored detail is now shown

    by_action = (await admin.get("/audit?action=alert.status")).text
    assert "1 recorded actions" in by_action
    failures = (await admin.get("/audit?outcome=failure")).text
    assert "1 recorded actions" in failures and "auth.login" in failures
    by_actor = (await admin.get("/audit?actor=Analyst&range=1h")).text
    assert "admin</a>" not in by_actor.split('data-testid="audit-table"')[1]
    async with site.manager.database.session() as session:
        await session.execute(update(AuditEvent).values(at=utcnow() - timedelta(days=2)))
    assert "Nothing matches" in (await admin.get("/audit?range=24h")).text
    assert (await admin.get("/audit?outcome=bogus&range=forever&page=zzz")).status_code == 200
    assert (await analyst.get("/audit")).status_code == 403
