import re
import uuid
from collections.abc import Callable

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.helpers import detection, heartbeat

from .conftest import Server, sign_in_through_form

pytestmark = pytest.mark.e2e

type SignIn = Callable[..., None]


def enrol_agent(page: Page, server: Server, name: str) -> str:
    """Enrol an agent through the UI and return the token shown in the dialog."""
    page.goto(f"{server.url}/agents")
    page.get_by_role("button", name="Enrol agent").click()
    page.get_by_label("Agent name").fill(name)
    page.get_by_role("button", name="Create token").click()
    snippet = page.get_by_test_id("token-snippet")
    expect(snippet).to_contain_text("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer tgm_")
    expect(snippet).to_contain_text(f"TRACEGUARD_EVENT_EXPORT_URL={server.url}/api/v1/events")
    match = re.search(r"Bearer (tgm_[A-Za-z0-9_-]+)", snippet.inner_text())
    assert match is not None
    page.get_by_role("button", name="Done").click()
    expect(page.get_by_test_id("agents-table")).to_contain_text(name)
    return match.group(1)


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def test_anonymous_visitor_is_sent_to_sign_in(page: Page, server: Server) -> None:
    page.goto(f"{server.url}/alerts?status=open")
    expect(page).to_have_url(re.compile(r"/login\?next="))
    expect(page.get_by_role("heading", name="TraceGuard Manager")).to_be_visible()


def test_wrong_password_shows_a_generic_error(page: Page, server: Server) -> None:
    page.goto(f"{server.url}/login")
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("definitely-not-right-1")
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("alert")).to_have_text("Invalid username or password.")
    expect(page).to_have_url(re.compile(r"/login$"))


def test_sign_in_returns_to_the_requested_page(page: Page, server: Server) -> None:
    page.goto(f"{server.url}/agents")
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("correct-battery-staple-42")
    page.get_by_role("button", name="Sign in").click()
    expect(page).to_have_url(f"{server.url}/agents")
    expect(page.get_by_role("heading", name="Fleet")).to_be_visible()


def test_enrol_ingest_and_triage_an_alert(
    page: Page, server: Server, sign_in: SignIn, csp_violations: list[str]
) -> None:
    sign_in(page)
    name = unique("web")
    token = enrol_agent(page, server, name)
    title = f"Reverse shell on {name}"

    result = server.ingest(
        token, [heartbeat(name), detection(unique("alert"), name, detection_message=title)]
    )
    assert result["stored"] == 1

    page.goto(f"{server.url}/agents")
    row = page.get_by_test_id("agents-table").get_by_role("row", name=re.compile(name))
    expect(row).to_contain_text("online")

    page.goto(f"{server.url}/alerts?status=open")
    page.get_by_role("link", name=title).click()
    expect(page.get_by_role("heading", name=title)).to_be_visible()
    expect(page.get_by_test_id("alert-status")).to_have_text("open")
    expect(page.locator("dl.facts")).to_contain_text("tg-reverse-shell")

    page.get_by_label("Note").fill("Confirmed test activity; closing.")
    page.get_by_role("button", name="Resolve").click()
    expect(page.get_by_test_id("alert-status")).to_have_text("resolved")
    expect(page.get_by_text("Resolved by admin")).to_be_visible()

    page.goto(f"{server.url}/audit")
    expect(page.get_by_test_id("audit-table")).to_contain_text("alert.status")
    expect(page.get_by_test_id("audit-table")).to_contain_text("agent.enroll")
    assert csp_violations == []


def test_new_alerts_appear_live_without_reloading(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    token = enrol_agent(page, server, unique("live"))
    page.goto(f"{server.url}/")
    expect(page.locator("#live-indicator")).to_have_attribute("data-state", "live")
    before = int(page.get_by_test_id("open-alerts").inner_text())

    title = f"Live alert {uuid.uuid4().hex[:6]}"
    server.ingest(token, [detection(unique("alert"), "live-host", detection_message=title)])

    expect(page.locator(".toast").filter(has_text=title)).to_be_visible()
    expect(page.get_by_test_id("open-alerts")).to_have_text(str(before + 1))


def test_bulk_acknowledge_from_the_alert_list(
    page: Page, browser: Browser, server: Server, sign_in: SignIn
) -> None:
    sign_in(page, "analyst")
    admin_context = browser.new_context()
    admin_page = admin_context.new_page()
    sign_in(admin_page)
    name = unique("bulk")
    token = enrol_agent(admin_page, server, name)
    admin_context.close()

    server.ingest(
        token,
        [detection(unique("alert"), name, detection_message=f"Bulk {name} {index}") for index in range(3)],
    )
    page.goto(f"{server.url}/alerts?status=open&q={name}")
    expect(page.locator(".row-check")).to_have_count(3)
    page.get_by_label("Select all alerts on this page").check()
    expect(page.locator("#bulk-count")).to_have_text("3")
    page.get_by_role("button", name="Acknowledge").click()
    expect(page.get_by_text("No alerts match")).to_be_visible()
    page.goto(f"{server.url}/alerts?status=acknowledged&q={name}")
    expect(page.locator(".row-check")).to_have_count(3)


def test_viewer_sees_no_admin_controls(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page, "viewer")
    expect(page.get_by_role("link", name="Users")).to_have_count(0)
    expect(page.get_by_role("link", name="Audit log")).to_have_count(0)
    page.goto(f"{server.url}/agents")
    expect(page.get_by_role("button", name="Enrol agent")).to_have_count(0)
    response = page.goto(f"{server.url}/users")
    assert response is not None
    assert response.status == 403
    expect(page.get_by_role("heading", name="You do not have access to this page")).to_be_visible()


def test_admin_adds_a_user_who_can_sign_in(
    page: Page, browser: Browser, server: Server, sign_in: SignIn
) -> None:
    sign_in(page)
    username = unique("user")
    password = "an-e2e-only-passphrase-1"
    page.goto(f"{server.url}/users")
    page.get_by_role("button", name="Add user").click()
    page.get_by_label("Username").fill(username)
    page.get_by_label("Temporary password").fill(password)
    page.get_by_role("button", name="Create user").click()
    expect(page.get_by_test_id("users-table")).to_contain_text(username)

    other = browser.new_context()
    other_page = other.new_page()
    other_page.goto(f"{server.url}/login")
    other_page.get_by_label("Username").fill(username)
    other_page.get_by_label("Password").fill(password)
    other_page.get_by_role("button", name="Sign in").click()
    expect(other_page.get_by_test_id("current-user")).to_have_text(username)
    other.close()


def test_sign_out_ends_the_session(page: Page, server: Server) -> None:
    sign_in_through_form(page, server, "analyst")  # its own session, so the shared ones stay valid
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(f"{server.url}/login")
    page.goto(f"{server.url}/")
    expect(page).to_have_url(re.compile(r"/login$"))


def test_pages_render_without_console_errors(
    page: Page, server: Server, sign_in: SignIn, csp_violations: list[str]
) -> None:
    sign_in(page)
    for path in ("/", "/alerts", "/agents", "/users", "/audit", "/account"):
        page.goto(f"{server.url}{path}")
        expect(page.locator("#content")).to_be_visible()
    assert csp_violations == []


def test_layout_adapts_to_a_phone(page: Page, sign_in: SignIn) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    sign_in(page)
    expect(page.locator("#sidebar")).not_to_be_in_viewport()
    page.get_by_role("button", name="Toggle navigation").click()
    expect(page.get_by_role("link", name="Fleet")).to_be_in_viewport()
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0
