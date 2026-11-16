from dataclasses import replace
from datetime import timedelta

from flasgo import TestClient
from sqlalchemy import select, update

from traceguard_manager.asgi import create_app
from traceguard_manager.config import Config
from traceguard_manager.models import AuditEvent, User, UserSession, utcnow

from .conftest import Site
from .helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, data


async def test_anonymous_page_request_redirects_to_login(site: Site) -> None:
    response = await site.browser().get("/alerts?status=open")
    assert response.status_code == 303
    assert response.location == "/login?next=%2Falerts%3Fstatus%3Dopen"


async def test_anonymous_json_request_gets_401(site: Site) -> None:
    response = await site.browser().get("/alerts", accept="application/json")
    assert response.status_code == 401
    assert data(response)["error"] == "Sign in required"


async def test_login_sets_hardened_cookie_and_grants_access(site: Site) -> None:
    browser = site.browser()
    response = await browser.login("admin", ADMIN_PASSWORD)
    assert response.status_code == 200
    assert response.json() == {"redirect": "/"}
    assert "flasgo-session" in browser.client.cookies

    page = await browser.get("/")
    assert page.status_code == 200
    assert 'data-testid="current-user">admin<' in page.text


async def test_session_cookie_flags_in_production_configuration(config: Config) -> None:
    manager = create_app(replace(config, secure_cookies=True))
    try:
        response = await TestClient(manager.web).arequest("GET", "/login", scheme="https")
        cookie = response.headers["set-cookie"]
        assert "Secure" in cookie
        assert "SameSite=Lax" in cookie
    finally:
        await manager.database.dispose()


async def test_login_failure_is_generic_and_audited(site: Site) -> None:
    browser = site.browser()
    wrong_password = await browser.login("admin", "not-the-password-123")
    unknown_user = await browser.login("nobody", "not-the-password-123")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json() == {"error": "Invalid username or password."}
    assert "flasgo-session" not in browser.client.cookies

    async with site.manager.database.session() as session:
        events = list(await session.scalars(select(AuditEvent).where(AuditEvent.action == "auth.login")))
    assert {event.outcome for event in events} == {"failure"}
    assert all("password" not in str(event.detail).lower() for event in events)


async def test_username_is_case_insensitive(site: Site) -> None:
    assert (await site.browser().login("  ADMIN ", ADMIN_PASSWORD)).status_code == 200


async def test_account_locks_after_repeated_failures(site: Site) -> None:
    browser = site.browser()
    for _ in range(site.manager.config.login_max_failures):
        assert (await browser.login("analyst", "wrong-password-000")).status_code == 401
    # Even the correct password is refused while locked, with the same message.
    locked = await browser.login("analyst", ANALYST_PASSWORD)
    assert locked.status_code == 401
    assert locked.json() == {"error": "Invalid username or password."}

    async with site.manager.database.session() as session:
        await session.execute(update(User).where(User.username == "analyst").values(locked_until=utcnow() - timedelta(seconds=1)))
    assert (await site.browser().login("analyst", ANALYST_PASSWORD)).status_code == 200


async def test_login_is_rate_limited_per_client(site: Site) -> None:
    browser = site.browser()
    codes = [(await browser.login(f"user{index}", "wrong-password-000")).status_code for index in range(12)]
    assert codes[:10] == [401] * 10
    assert codes[10:] == [429, 429]


async def test_post_without_csrf_token_is_rejected(site: Site) -> None:
    browser = site.browser()
    await browser.get("/login")
    response = await browser.send("POST", "/auth/login", {"username": "admin", "password": ADMIN_PASSWORD}, csrf=False)
    assert response.status_code == 403
    assert "flasgo-session" not in browser.client.cookies


async def test_post_from_another_origin_is_rejected(site: Site) -> None:
    browser = await site.admin()
    response = await browser.send("POST", "/alerts/status", {"ids": [], "status": "resolved"}, origin="https://evil.example")
    assert response.status_code == 403


async def test_post_without_origin_is_rejected(site: Site) -> None:
    browser = await site.admin()
    response = await browser.send("POST", "/auth/logout", origin=None)
    assert response.status_code == 403


async def test_logout_revokes_the_session_server_side(site: Site) -> None:
    browser = await site.admin()
    stolen = f"flasgo-session={browser.session_cookie()}"
    assert (await site.browser().get("/", cookie=stolen)).status_code == 200  # the copy works while signed in

    assert (await browser.post("/auth/logout")).json() == {"redirect": "/login"}
    assert (await browser.get("/")).status_code == 303
    # Replaying the copied cookie must fail: the session row is gone.
    assert (await site.browser().get("/", cookie=stolen)).status_code == 303


async def test_idle_session_expires(site: Site) -> None:
    browser = await site.admin()
    async with site.manager.database.session() as session:
        await session.execute(update(UserSession).values(last_seen_at=utcnow() - timedelta(hours=2)))
    assert (await browser.get("/")).status_code == 303
    async with site.manager.database.session() as session:
        assert (await session.scalars(select(UserSession))).first() is None


async def test_session_reaches_absolute_limit(site: Site) -> None:
    browser = await site.admin()
    async with site.manager.database.session() as session:
        await session.execute(update(UserSession).values(expires_at=utcnow() - timedelta(seconds=1)))
    assert (await browser.get("/")).status_code == 303


async def test_only_a_hash_of_the_session_token_is_stored(site: Site) -> None:
    cookie = (await site.admin()).session_cookie()
    async with site.manager.database.session() as session:
        stored = (await session.scalars(select(UserSession))).one()
    assert len(stored.token_hash) == 64
    assert stored.token_hash not in cookie


async def test_tampered_session_cookie_is_ignored(site: Site) -> None:
    genuine = (await site.admin()).session_cookie()
    forged = genuine[:-6] + ("AAAAAA" if not genuine.endswith("AAAAAA") else "BBBBBB")
    assert (await site.browser().get("/", cookie=f"flasgo-session={genuine}")).status_code == 200
    assert (await site.browser().get("/", cookie=f"flasgo-session={forged}")).status_code == 303


async def test_duplicate_session_cookies_are_treated_as_signed_out(site: Site) -> None:
    genuine = (await site.admin()).session_cookie()
    doubled = f"flasgo-session={genuine}; flasgo-session={genuine}"
    assert (await site.browser().get("/", cookie=doubled)).status_code == 303


async def test_login_redirect_target_cannot_leave_the_site(site: Site) -> None:
    browser = site.browser()
    page = await browser.get("/login?next=https://evil.example/phish")
    assert 'name="next" value="/"' in page.text

    await browser.get("/login")
    response = await browser.post("/auth/login", {"username": "admin", "password": ADMIN_PASSWORD, "next": "//evil.example"})
    assert response.json() == {"redirect": "/"}


async def test_login_keeps_a_safe_redirect_target(site: Site) -> None:
    browser = site.browser()
    await browser.get("/login")
    response = await browser.post("/auth/login", {"username": "admin", "password": ADMIN_PASSWORD, "next": "/alerts?status=open"})
    assert response.json() == {"redirect": "/alerts?status=open"}


async def test_signed_in_user_is_sent_away_from_login(site: Site) -> None:
    browser = await site.admin()
    response = await browser.get("/login")
    assert response.status_code == 303
    assert response.location == "/"


async def test_security_headers_on_pages(site: Site) -> None:
    response = await site.browser().get("/login")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert response.headers["cache-control"].startswith("no-store")
    assert "max-age=" in response.headers["strict-transport-security"]


async def test_unknown_host_header_is_rejected(site: Site) -> None:
    response = await site.browser().client.arequest("GET", "/login", headers={"host": "evil.example"})
    assert response.status_code == 400


async def test_error_pages_do_not_leak_details(site: Site) -> None:
    browser = await site.admin()
    missing = await browser.get("/no-such-page")
    assert missing.status_code == 404
    assert "Page not found" in missing.text
    assert "Traceback" not in missing.text

    bad_id = await browser.get("/alerts/not-a-uuid")
    assert bad_id.status_code == 404


async def test_health_endpoint_is_public_and_minimal(site: Site) -> None:
    response = await site.browser().get("/healthz", accept="application/json")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_change_password_requires_current_and_signs_out_other_sessions(site: Site) -> None:
    first = await site.analyst()
    second = await site.analyst()
    new_password = "a-brand-new-passphrase-77"

    wrong = await first.post("/account/password", {"current_password": "nope-nope-nope-1", "new_password": new_password})
    assert wrong.status_code == 400

    weak = await first.post("/account/password", {"current_password": ANALYST_PASSWORD, "new_password": "short"})
    assert weak.status_code == 400
    assert "at least 12" in data(weak)["error"]

    changed = await first.post("/account/password", {"current_password": ANALYST_PASSWORD, "new_password": new_password})
    assert changed.status_code == 200
    assert (await first.get("/")).status_code == 200  # this browser stays signed in
    assert (await second.get("/")).status_code == 303  # the other one is signed out
    assert (await site.browser().login("analyst", ANALYST_PASSWORD)).status_code == 401
    assert (await site.browser().login("analyst", new_password)).status_code == 200


async def test_unknown_json_fields_are_rejected(site: Site) -> None:
    browser = site.browser()
    await browser.get("/login")
    response = await browser.post("/auth/login", {"username": "admin", "password": ADMIN_PASSWORD, "is_admin": True})
    assert response.status_code == 422
    assert ADMIN_PASSWORD not in response.text
