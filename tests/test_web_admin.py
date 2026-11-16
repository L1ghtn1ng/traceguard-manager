from sqlalchemy import func, select

from traceguard_manager.models import Agent, Alert, AuditEvent, User

from .conftest import Site
from .helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, data, detection, heartbeat

NEW_PASSWORD = "freshly-minted-passphrase-9"


async def test_fleet_page_lists_agents_with_status(site: Site) -> None:
    browser = await site.viewer()
    before = await browser.get("/agents")
    assert "web-01" in before.text
    assert "state-pending" in before.text

    await site.ingest([heartbeat()])
    after = await browser.get("/agents")
    assert "state-online" in after.text
    assert "aaaaaaaaaaaa" in after.text
    assert "Enrol agent" not in after.text  # viewers get no management controls


async def test_degraded_and_drift_are_surfaced(site: Site) -> None:
    admin = await site.admin()
    tokens = {}
    for name in ("db-01", "db-02"):
        created = await admin.post("/agents", {"name": name})
        tokens[name] = data(created)["token"]
    await site.ingest([heartbeat()])
    await site.ingest([heartbeat("db-01")], token=tokens["db-01"])
    await site.ingest(
        [heartbeat("db-02", policy_sha256="b" * 64, healthy=False, unavailable_hooks=["lsm/file_open"])],
        token=tokens["db-02"],
    )
    page = await admin.get("/agents")
    assert page.text.count("state-online") == 2
    assert page.text.count("state-degraded") == 1
    assert "1 agent reports a policy that differs" in page.text
    assert 'status-drift">drift' in page.text


async def test_admin_enrols_agent_and_token_works_once_shown(site: Site) -> None:
    admin = await site.admin()
    created = await admin.post("/agents", {"name": "edge-07"})
    assert created.status_code == 201
    token = data(created)["token"]
    assert token.startswith("tgm_")

    async with site.manager.database.session() as session:
        agent = await session.scalar(select(Agent).where(Agent.name == "edge-07"))
        audit = await session.scalar(select(AuditEvent).where(AuditEvent.action == "agent.enroll"))
    assert agent is not None
    assert audit is not None
    assert token not in agent.token_hash  # only a digest is kept
    assert token not in str(audit.detail)
    assert token not in (await admin.get(f"/agents/{agent.id}")).text

    assert (await site.ingest([detection("E1", hostname="edge-07")], token=token)).status_code == 200


async def test_agent_name_validation(site: Site) -> None:
    admin = await site.admin()
    duplicate = await admin.post("/agents", {"name": "web-01"})
    assert duplicate.status_code == 400
    assert "already exists" in data(duplicate)["error"]
    for bad in ("", "   ", "has space", "<script>", "x" * 101, "../etc"):
        assert (await admin.post("/agents", {"name": bad})).status_code == 400, bad


async def test_rotate_revokes_the_old_token(site: Site) -> None:
    admin = await site.admin()
    rotated = await admin.post(f"/agents/{site.agent_id}/rotate")
    assert rotated.status_code == 200
    new_token = data(rotated)["token"]
    assert new_token != site.agent_token
    assert (await site.ingest([detection("A")])).status_code == 401
    assert (await site.ingest([detection("A")], token=new_token)).status_code == 200


async def test_disable_enable_and_delete_agent(site: Site) -> None:
    admin = await site.admin()
    await site.ingest([detection("A")])

    assert (await admin.post(f"/agents/{site.agent_id}/enabled", {"enabled": False})).status_code == 200
    assert (await site.ingest([detection("B")])).status_code == 401
    assert "state-disabled" in (await admin.get("/agents")).text

    assert (await admin.post(f"/agents/{site.agent_id}/enabled", {"enabled": True})).status_code == 200
    assert (await site.ingest([detection("B")])).status_code == 200

    deleted = await admin.send("DELETE", f"/agents/{site.agent_id}")
    assert deleted.json() == {"redirect": "/agents"}
    async with site.manager.database.session() as session:
        assert await session.scalar(select(func.count()).select_from(Agent)) == 0
        assert await session.scalar(select(func.count()).select_from(Alert)) == 0  # alerts go with the agent
    assert (await admin.get(f"/agents/{site.agent_id}")).status_code == 404


async def test_non_admins_cannot_manage_agents(site: Site) -> None:
    for browser in (await site.viewer(), await site.analyst()):
        assert (await browser.post("/agents", {"name": "rogue"})).status_code == 403
        assert (await browser.post(f"/agents/{site.agent_id}/rotate")).status_code == 403
        assert (await browser.post(f"/agents/{site.agent_id}/enabled", {"enabled": False})).status_code == 403
        assert (await browser.send("DELETE", f"/agents/{site.agent_id}")).status_code == 403
    assert (await site.ingest([detection("A")])).status_code == 200  # the original token still works


async def test_non_admins_cannot_reach_admin_pages(site: Site) -> None:
    for browser in (await site.viewer(), await site.analyst()):
        for path in ("/users", "/audit"):
            page = await browser.get(path)
            assert page.status_code == 403
            assert "You do not have access" in page.text
        assert (
            await browser.post("/users", {"username": "x1", "password": NEW_PASSWORD, "role": "admin"})
        ).status_code == 403
        nav = (await browser.get("/")).text
        assert 'href="/users"' not in nav
        assert 'href="/audit"' not in nav


async def test_admin_creates_user_who_can_sign_in(site: Site) -> None:
    admin = await site.admin()
    created = await admin.post("/users", {"username": "Dana", "password": NEW_PASSWORD, "role": "analyst"})
    assert created.status_code == 201
    assert data(created)["username"] == "dana"
    assert "dana" in (await admin.get("/users")).text
    assert (await site.browser().login("dana", NEW_PASSWORD)).status_code == 200

    async with site.manager.database.session() as session:
        user = await session.scalar(select(User).where(User.username == "dana"))
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert NEW_PASSWORD not in user.password_hash


async def test_user_creation_validation(site: Site) -> None:
    admin = await site.admin()
    cases = [
        {"username": "admin", "password": NEW_PASSWORD, "role": "viewer"},  # duplicate
        {"username": "ab", "password": NEW_PASSWORD, "role": "viewer"},  # too short
        {"username": "bad name", "password": NEW_PASSWORD, "role": "viewer"},
        {"username": "weakling", "password": "short", "role": "viewer"},
        {"username": "weakling", "password": "passwordpassword", "role": "viewer"},
        {"username": "weakling", "password": NEW_PASSWORD, "role": "superuser"},
    ]
    for body in cases:
        response = await admin.post("/users", body)
        assert response.status_code == 400, body
        assert NEW_PASSWORD not in response.text


async def test_role_change_signs_the_user_out_and_applies(site: Site) -> None:
    admin = await site.admin()
    analyst = await site.analyst()
    async with site.manager.database.session() as session:
        analyst_id = await session.scalar(select(User.id).where(User.username == "analyst"))

    assert (await admin.send("PATCH", f"/users/{analyst_id}", {"role": "viewer"})).status_code == 200
    assert (await analyst.get("/")).status_code == 303  # old session carried the old role

    demoted = await site.signed_in("analyst", ANALYST_PASSWORD)
    assert (await demoted.post("/alerts/status", {"ids": [], "status": "resolved"})).status_code == 403


async def test_disabled_user_is_signed_out_and_cannot_sign_in(site: Site) -> None:
    admin = await site.admin()
    analyst = await site.analyst()
    async with site.manager.database.session() as session:
        analyst_id = await session.scalar(select(User.id).where(User.username == "analyst"))
    assert (await admin.send("PATCH", f"/users/{analyst_id}", {"is_active": False})).status_code == 200
    assert (await analyst.get("/")).status_code == 303
    assert (await site.browser().login("analyst", ANALYST_PASSWORD)).status_code == 401


async def test_last_admin_cannot_be_removed(site: Site) -> None:
    admin = await site.admin()
    async with site.manager.database.session() as session:
        admin_id = await session.scalar(select(User.id).where(User.username == "admin"))
    for body in ({"role": "viewer"}, {"is_active": False}):
        response = await admin.send("PATCH", f"/users/{admin_id}", body)
        assert response.status_code == 400
        assert "At least one active administrator" in data(response)["error"]
    assert (await admin.get("/users")).status_code == 200


async def test_admin_password_reset_ends_sessions(site: Site) -> None:
    admin = await site.admin()
    analyst = await site.analyst()
    async with site.manager.database.session() as session:
        analyst_id = await session.scalar(select(User.id).where(User.username == "analyst"))
    assert (await admin.post(f"/users/{analyst_id}/password", {"password": NEW_PASSWORD})).status_code == 200
    assert (await analyst.get("/")).status_code == 303
    assert (await site.browser().login("analyst", ANALYST_PASSWORD)).status_code == 401
    assert (await site.browser().login("analyst", NEW_PASSWORD)).status_code == 200


async def test_audit_log_shows_actions_without_secrets(site: Site) -> None:
    admin = await site.admin()
    token = data(await admin.post("/agents", {"name": "audited-01"}))["token"]
    await admin.post("/users", {"username": "eve", "password": NEW_PASSWORD, "role": "viewer"})
    page = await admin.get("/audit")
    assert page.status_code == 200
    for expected in ("auth.login", "agent.enroll", "user.create", "audited-01", "eve"):
        assert expected in page.text
    for secret in (token, NEW_PASSWORD, ADMIN_PASSWORD):
        assert secret not in page.text


async def test_unknown_ids_are_404_for_admin_actions(site: Site) -> None:
    admin = await site.admin()
    missing = "00000000-0000-7000-8000-000000000000"
    assert (await admin.post(f"/agents/{missing}/rotate")).status_code == 404
    assert (await admin.send("PATCH", f"/users/{missing}", {"role": "viewer"})).status_code == 404
    assert (await admin.post("/agents/not-a-uuid/rotate")).status_code == 404
