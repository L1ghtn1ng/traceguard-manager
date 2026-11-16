import json

from flasgo import TestClient
from sqlalchemy import func, select

from traceguard_manager import fleet
from traceguard_manager.models import Agent, Alert

from .conftest import Site
from .helpers import blocked, data, detection, heartbeat, telemetry


async def _count_alerts(site: Site) -> int:
    async with site.manager.database.session() as session:
        return await session.scalar(select(func.count()).select_from(Alert)) or 0


async def test_rejects_missing_and_unknown_tokens(site: Site) -> None:
    client = site.agent_client()
    missing = await client.arequest("POST", "/api/v1/events", json=[detection()])
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"

    unknown = await site.ingest([detection()], token="tgm_" + "x" * 43)
    assert unknown.status_code == 401
    assert await _count_alerts(site) == 0


async def test_stores_alerts_and_updates_the_agent(site: Site) -> None:
    response = await site.ingest([heartbeat(), detection(), blocked(), telemetry(), "junk"])
    assert response.status_code == 200
    assert response.json() == {"received": 5, "stored": 2, "duplicates": 0, "ignored": 1, "invalid": 1}

    async with site.manager.database.session() as session:
        agent = (await session.scalars(select(Agent))).one()
        alerts = list(await session.scalars(select(Alert).order_by(Alert.kind)))
    assert agent.hostname == "web-01"
    assert agent.healthy is True
    assert agent.policy_sha256 == "a" * 64
    assert agent.detection_rules == 14
    assert agent.last_seen_at is not None
    assert agent.events_received == 5
    assert [alert.kind for alert in alerts] == ["blocked", "detection"]
    assert alerts[1].severity_rank == 5
    assert alerts[1].status == "open"


async def test_replayed_batches_are_idempotent(site: Site) -> None:
    batch = [detection("A"), detection("B"), blocked()]
    assert data(await site.ingest(batch))["stored"] == 3
    replay = await site.ingest(batch)
    assert replay.status_code == 200
    assert data(replay)["stored"] == 0
    assert data(replay)["duplicates"] == 3
    assert await _count_alerts(site) == 3


async def test_agent_identity_comes_from_the_token_not_the_payload(site: Site) -> None:
    async with site.manager.database.session() as session:
        other, other_token = await fleet.enroll_agent(session, name="db-01")
    # db-01 claims to be web-01; the alert must still be filed under db-01.
    await site.ingest([detection("SPOOF", hostname="web-01")], token=other_token)
    async with site.manager.database.session() as session:
        alert = (await session.scalars(select(Alert))).one()
    assert alert.agent_id == other.id


async def test_disabled_agent_is_rejected(site: Site) -> None:
    async with site.manager.database.session() as session:
        agent = (await session.scalars(select(Agent))).one()
        agent.enabled = False
    assert (await site.ingest([detection()])).status_code == 401


async def test_rejects_wrong_shape_and_content_type(site: Site) -> None:
    auth = {"authorization": f"Bearer {site.agent_token}"}
    client = site.agent_client()

    not_array = await client.arequest("POST", "/api/v1/events", json={"event": "x"}, headers=auth)
    assert not_array.status_code == 400

    bad_json = await client.arequest(
        "POST", "/api/v1/events", body=b"[{", headers=auth | {"content-type": "application/json"}
    )
    assert bad_json.status_code == 400

    wrong_type = await client.arequest(
        "POST",
        "/api/v1/events",
        body=json.dumps([detection()]).encode(),
        headers=auth | {"content-type": "text/plain"},
    )
    assert wrong_type.status_code == 415
    assert await _count_alerts(site) == 0


async def test_rejects_batches_over_the_record_and_size_limits(site: Site) -> None:
    too_many = await site.ingest([telemetry()] * (site.manager.config.ingest_max_records + 1))
    assert too_many.status_code == 413

    huge = await site.agent_client().arequest(
        "POST",
        "/api/v1/events",
        body=b"[" + b" " * (2 * 1024 * 1024) + b"]",
        headers={"authorization": f"Bearer {site.agent_token}", "content-type": "application/json"},
    )
    assert huge.status_code == 413


async def test_only_post_is_allowed_and_errors_are_generic(site: Site) -> None:
    response = await site.agent_client().arequest("GET", "/api/v1/events")
    assert response.status_code == 405
    assert "Traceback" not in response.text


async def test_ingest_is_rate_limited_per_agent(config, tmp_path) -> None:
    from dataclasses import replace

    from traceguard_manager.asgi import create_app

    manager = create_app(replace(config, ingest_requests_per_minute=3))
    await manager.database.create_all()
    try:
        async with manager.database.session() as session:
            _, token = await fleet.enroll_agent(session, name="chatty")
        client = TestClient(manager.api)
        codes = [
            (
                await client.arequest(
                    "POST", "/api/v1/events", json=[telemetry()], headers={"authorization": f"Bearer {token}"}
                )
            ).status_code
            for _ in range(5)
        ]
        assert codes == [200, 200, 200, 429, 429]
    finally:
        await manager.database.dispose()


async def test_api_app_never_sets_cookies(site: Site) -> None:
    response = await site.ingest([detection()])
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"].startswith("no-store")
    assert response.headers["x-content-type-options"] == "nosniff"
