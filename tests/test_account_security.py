"""Forced password changes, lockouts, sessions, account deletion and two-step sign-in."""

import base64
import re
from datetime import timedelta

from sqlalchemy import select, update

from traceguard_manager import totp
from traceguard_manager.models import Alert, AuditEvent, User, UserSession, utcnow
from traceguard_manager.webcontext import BACKGROUND_HEADER

from .conftest import Site
from .helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, VIEWER_PASSWORD, Browser, data, detection

TEMPORARY = "temporary-passphrase-77"
CHOSEN = "my-own-long-passphrase-88"


async def _user(site: Site, username: str) -> User:
    async with site.manager.database.session() as session:
        user = await session.scalar(select(User).where(User.username == username))
    assert user is not None
    return user


async def _login(site: Site, username: str, password: str, code: str | None = None) -> tuple[Browser, int, dict[str, object]]:
    browser = site.browser()
    await browser.get("/login")
    body = {"username": username, "password": password} | ({"code": code} if code is not None else {})
    response = await browser.post("/auth/login", body)
    return browser, response.status_code, data(response)


# ---- forced password change -------------------------------------------------


async def test_password_set_by_an_admin_must_be_replaced_first(site: Site) -> None:
    admin = await site.admin()
    assert (await admin.post("/users", {"username": "newhire", "password": TEMPORARY, "role": "analyst"})).status_code == 201

    browser, status, body = await _login(site, "newhire", TEMPORARY)
    assert (status, body) == (200, {"redirect": "/account"})
    # Nothing else is reachable: pages send them back, actions are refused.
    for path in ("/", "/alerts", "/agents", "/mutes"):
        page = await browser.get(path)
        assert (page.status_code, page.headers["location"]) == (303, "/account"), path
    refused = await browser.post("/alerts/status", {"ids": ["0" * 32], "status": "resolved"})
    assert refused.status_code == 403
    assert "new password" in str(data(refused)["error"])
    assert (await browser.get("/stream", accept="text/event-stream")).status_code == 403
    assert 'data-testid="must-change"' in (await browser.get("/account")).text

    same = await browser.post("/account/password", {"current_password": TEMPORARY, "new_password": TEMPORARY})
    assert same.status_code == 400  # choosing the same one again is not a change
    changed = await browser.post("/account/password", {"current_password": TEMPORARY, "new_password": CHOSEN})
    assert changed.status_code == 200
    assert (await browser.get("/alerts")).status_code == 200
    assert (await _user(site, "newhire")).must_change_password is False


async def test_admin_reset_requires_a_new_password_too(site: Site) -> None:
    admin = await site.admin()
    analyst = await _user(site, "analyst")
    assert (await admin.post(f"/users/{analyst.id}/password", {"password": TEMPORARY})).status_code == 200
    browser, status, body = await _login(site, "analyst", TEMPORARY)
    assert (status, body) == (200, {"redirect": "/account"})
    assert (await browser.get("/")).status_code == 303
    assert "must choose a new password" in (await admin.get("/users")).text


# ---- lockouts -----------------------------------------------------------------


async def test_lockout_is_visible_and_can_be_lifted(site: Site) -> None:
    for _ in range(site.manager.config.login_max_failures):
        await _login(site, "analyst", "wrong-password-000")
    admin = await site.admin()
    page = (await admin.get("/users")).text
    assert "locked until" in page
    analyst = await _user(site, "analyst")
    assert (await _login(site, "analyst", ANALYST_PASSWORD))[1] == 401

    assert (await admin.send("PATCH", f"/users/{analyst.id}", {"unlock": True})).status_code == 200
    assert (await _login(site, "analyst", ANALYST_PASSWORD))[1] == 200
    assert "locked until" not in (await admin.get("/users")).text
    async with site.manager.database.session() as session:
        assert await session.scalar(select(AuditEvent.id).where(AuditEvent.action == "user.unlock")) is not None


# ---- sessions -----------------------------------------------------------------


async def test_own_sessions_can_be_listed_and_ended(site: Site) -> None:
    first = await site.analyst()
    second = await site.analyst()
    other = await site.viewer()
    page = (await first.get("/account")).text
    assert page.count("last used") == 2
    assert page.count(">this browser</span>") == 1

    async with site.manager.database.session() as session:
        analyst = await session.scalar(select(User).where(User.username == "analyst"))
        assert analyst is not None
        sessions = list(
            await session.scalars(select(UserSession).where(UserSession.user_id == analyst.id).order_by(UserSession.id))
        )
    # Someone else's session identifier is simply not found.
    assert (await other.send("DELETE", f"/account/sessions/{sessions[0].id}")).status_code == 404
    assert (await first.get("/")).status_code == 200

    assert (await first.post("/account/sessions/end-others")).status_code == 200
    assert (await second.get("/")).status_code == 303
    assert (await first.get("/")).status_code == 200
    assert (await other.get("/")).status_code == 200


async def test_only_what_the_person_does_keeps_a_session_alive(site: Site) -> None:
    browser = await site.viewer()
    two_minutes_ago = utcnow() - timedelta(minutes=2)

    async def last_seen() -> object:
        async with site.manager.database.session() as session:
            return await session.scalar(select(UserSession.last_seen_at))

    async with site.manager.database.session() as session:
        await session.execute(update(UserSession).values(last_seen_at=two_minutes_ago))
    # The page's own traffic: the session probe, and refreshes marked as background.
    assert (await browser.get("/auth/session", accept="application/json")).status_code == 200
    refresh = await browser.client.arequest("GET", "/alerts", headers={"accept": "text/html", BACKGROUND_HEADER: "1"})
    assert refresh.status_code == 200
    assert await last_seen() == two_minutes_ago

    assert (await browser.get("/alerts")).status_code == 200  # the person clicking something
    assert await last_seen() != two_minutes_ago

    # So a tab left open still reaches the idle timeout, however much it refreshes itself.
    async with site.manager.database.session() as session:
        await session.execute(update(UserSession).values(last_seen_at=utcnow() - timedelta(hours=1)))
    expired = await browser.client.arequest("GET", "/alerts", headers={"accept": "text/html", BACKGROUND_HEADER: "1"})
    assert expired.status_code == 303


# ---- deleting accounts ----------------------------------------------------------


async def test_deleting_a_user(site: Site) -> None:
    await site.ingest([detection("A", detection_message="Owned")])
    analyst_browser = await site.analyst()
    async with site.manager.database.session() as session:
        alert_id = str(await session.scalar(select(Alert.id)))
    assert (await analyst_browser.post("/alerts/assign", {"ids": [alert_id], "assignee": "me"})).status_code == 200
    admin = await site.admin()
    analyst, me = await _user(site, "analyst"), await _user(site, "admin")

    assert (await admin.send("DELETE", f"/users/{me.id}")).status_code == 400  # not yourself
    assert (await analyst_browser.send("DELETE", f"/users/{analyst.id}")).status_code == 403
    assert (await admin.send("DELETE", f"/users/{analyst.id}")).status_code == 200

    assert (await analyst_browser.get("/")).status_code == 303  # signed out with the account
    assert (await _login(site, "analyst", ANALYST_PASSWORD))[1] == 401
    async with site.manager.database.session() as session:
        alert = await session.scalar(select(Alert))
        assert alert is not None and alert.assignee_id is None  # their alerts go back to nobody
        trail = list(await session.scalars(select(AuditEvent.actor).where(AuditEvent.action == "alert.assign")))
    assert trail == ["analyst"]  # what they did stays on the record


# ---- two-step sign-in -------------------------------------------------------------


async def _turn_on_two_step(site: Site, browser: Browser, password: str) -> tuple[str, list[str]]:
    assert (await browser.post("/account/two-step/start", {"current_password": "not-the-password-0"})).status_code == 400
    assert data(await browser.post("/account/two-step/start", {"current_password": password})) == {
        "redirect": "/account/two-step"
    }
    page = (await browser.get("/account/two-step")).text
    shown = re.search(r'data-testid="two-step-secret">([A-Z2-7 ]+)<', page)
    assert shown is not None
    secret = shown.group(1).replace(" ", "")
    qr = page.split('data-testid="two-step-qr">')[1].split("</div>")[0]
    assert qr.startswith("<svg") and "style=" not in qr and "<script" not in qr  # drawn here, and allowed by the CSP

    wrong = await browser.post("/account/two-step/confirm", {"code": "000000"})
    assert wrong.status_code == 400
    confirmed = await browser.post(
        "/account/two-step/confirm", {"code": totp.code_at(secret, totp.step_at(utcnow().timestamp()))}
    )
    assert confirmed.status_code == 200
    codes = data(confirmed)["recovery_codes"]
    assert isinstance(codes, list) and len(codes) == totp.RECOVERY_CODE_COUNT
    return secret, [str(code) for code in codes]


async def test_two_step_sign_in_end_to_end(site: Site) -> None:
    secret, recovery = await _turn_on_two_step(site, await site.analyst(), ANALYST_PASSWORD)
    stored = await _user(site, "analyst")
    assert stored.totp_enabled_at is not None
    assert all(code not in str(stored.recovery_codes) for code in recovery)  # only hashes are kept

    _, status, body = await _login(site, "analyst", ANALYST_PASSWORD)
    assert status == 401 and body["mfa_required"] is True
    # A wrong password still gets the generic answer, so the second step leaks nothing about it.
    assert (await _login(site, "analyst", "wrong-password-000"))[2] == {"error": "Invalid username or password."}
    assert (await _login(site, "analyst", ANALYST_PASSWORD, "000000"))[1] == 401

    # Rewind the replay guard so the current code is usable, then use it twice.
    async with site.manager.database.session() as session:
        await session.execute(update(User).where(User.username == "analyst").values(totp_last_step=None))
    code = totp.code_at(secret, totp.step_at(utcnow().timestamp()))
    browser, status, _ = await _login(site, "analyst", ANALYST_PASSWORD, code)
    assert status == 200
    assert (await browser.get("/alerts")).status_code == 200
    assert (await _login(site, "analyst", ANALYST_PASSWORD, code))[1] == 401  # a code works once

    assert (await _login(site, "analyst", ANALYST_PASSWORD, recovery[0].upper()))[1] == 200
    assert (await _login(site, "analyst", ANALYST_PASSWORD, recovery[0]))[1] == 401  # so does a recovery code
    assert len((await _user(site, "analyst")).recovery_codes) == totp.RECOVERY_CODE_COUNT - 1

    page = (await browser.get("/account")).text
    assert "9 recovery codes left" in page
    assert (await browser.post("/account/two-step/disable", {"current_password": "not-the-password-0"})).status_code == 400
    assert (await browser.post("/account/two-step/disable", {"current_password": ANALYST_PASSWORD})).status_code == 200
    assert (await _login(site, "analyst", ANALYST_PASSWORD))[1] == 200


async def test_wrong_codes_lock_the_account_like_wrong_passwords(site: Site) -> None:
    await _turn_on_two_step(site, await site.viewer(), VIEWER_PASSWORD)
    for _ in range(site.manager.config.login_max_failures):
        assert (await _login(site, "viewer", VIEWER_PASSWORD, "000000"))[1] == 401
    assert (await _user(site, "viewer")).locked_until is not None


async def test_admin_can_reset_two_step_for_a_lost_device(site: Site) -> None:
    analyst_browser = await site.analyst()
    await _turn_on_two_step(site, analyst_browser, ANALYST_PASSWORD)
    admin = await site.admin()
    analyst = await _user(site, "analyst")
    assert '<span class="chip status-resolved">on</span>' in (await admin.get("/users")).text
    assert (await analyst_browser.post(f"/users/{analyst.id}/two-step/reset")).status_code == 403
    assert (await admin.post(f"/users/{analyst.id}/two-step/reset")).status_code == 200
    assert (await analyst_browser.get("/")).status_code == 303  # signed out everywhere
    assert (await _login(site, "analyst", ANALYST_PASSWORD))[1] == 200
    stored = await _user(site, "analyst")
    assert stored.totp_secret is None and stored.recovery_codes == []


def test_totp_matches_the_rfc_and_allows_for_clock_drift() -> None:
    secret = base64.b32encode(b"12345678901234567890").decode()
    # RFC 6238 appendix B, truncated from 8 digits to the 6 that apps show.
    for timestamp, expected in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")):
        assert totp.code_at(secret, totp.step_at(timestamp)) == expected
    now = 1_700_000_000.0
    step = totp.step_at(now)
    assert totp.verify(secret, totp.code_at(secret, step - 1), timestamp=now, last_step=None) == step - 1
    assert totp.verify(secret, totp.code_at(secret, step + 1), timestamp=now, last_step=None) == step + 1
    assert totp.verify(secret, totp.code_at(secret, step - 2), timestamp=now, last_step=None) is None
    assert totp.verify(secret, totp.code_at(secret, step), timestamp=now, last_step=step) is None
    assert totp.verify(secret, "12345", timestamp=now, last_step=None) is None
    assert totp.verify(secret, "abcdef", timestamp=now, last_step=None) is None
    uri = totp.provisioning_uri(secret, "analyst")
    assert uri.startswith("otpauth://totp/TraceGuard%20Manager%3Aanalyst?") and f"secret={secret}" in uri


async def test_admin_password_is_still_asked_for_by_name(site: Site) -> None:
    """The seeded admin was not created through the dashboard, so nothing forces a change."""
    browser, status, body = await _login(site, "admin", ADMIN_PASSWORD)
    assert (status, body) == (200, {"redirect": "/"})
    assert (await browser.get("/")).status_code == 200
