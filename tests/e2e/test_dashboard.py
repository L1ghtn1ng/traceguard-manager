import re
import time
import uuid
from collections.abc import Callable

import pytest
from playwright.sync_api import Browser, Page, Route, expect

from tests.helpers import detection, heartbeat
from traceguard_manager import totp

from .conftest import RoleCookies, Server, sign_in_through_form

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


def test_enrol_ingest_and_triage_an_alert(page: Page, server: Server, sign_in: SignIn, csp_violations: list[str]) -> None:
    sign_in(page)
    name = unique("web")
    token = enrol_agent(page, server, name)
    title = f"Reverse shell on {name}"

    result = server.ingest(token, [heartbeat(name), detection(unique("alert"), name, detection_message=title)])
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


def test_bulk_acknowledge_from_the_alert_list(page: Page, browser: Browser, server: Server, sign_in: SignIn) -> None:
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


def sign_in_as(page: Page, server: Server, username: str, password: str) -> None:
    page.goto(f"{server.url}/login")
    page.get_by_label("Username").fill(username)
    page.get_by_label("Password", exact=True).fill(password)
    page.get_by_role("button", name="Sign in").click()


def test_new_user_chooses_a_password_then_turns_on_two_step(
    page: Page, browser: Browser, server: Server, sign_in: SignIn
) -> None:
    sign_in(page)
    username = unique("user")
    temporary, chosen = "an-e2e-only-passphrase-1", "chosen-by-the-user-pass-2"
    page.goto(f"{server.url}/users")
    page.get_by_role("button", name="Add user").click()
    dialog = page.locator("#user-dialog")
    dialog.get_by_label("Username").fill(username)
    dialog.get_by_label("Temporary password").fill(temporary)
    dialog.get_by_role("button", name="Create user").click()
    row = page.get_by_test_id("users-table").get_by_role("row", name=re.compile(username))
    expect(row).to_contain_text("must choose a new password")

    context = browser.new_context()
    theirs = context.new_page()
    sign_in_as(theirs, server, username, temporary)
    # A password someone else chose only gets them as far as replacing it.
    expect(theirs).to_have_url(f"{server.url}/account")
    expect(theirs.get_by_test_id("must-change")).to_be_visible()
    theirs.goto(f"{server.url}/alerts")
    expect(theirs).to_have_url(f"{server.url}/account")
    change_password(theirs, temporary, chosen)
    expect(theirs).to_have_url(f"{server.url}/")
    expect(theirs.get_by_test_id("current-user")).to_have_text(username)

    # Two-step sign-in: scan (here, read) the key, confirm with a code, keep the recovery codes.
    theirs.goto(f"{server.url}/account")
    card = theirs.get_by_test_id("two-step")
    card.get_by_label("Current password").fill(chosen)
    card.get_by_role("button", name="Set up two-step sign-in").click()
    expect(theirs.get_by_test_id("two-step-qr").locator("svg")).to_be_visible()
    secret = theirs.get_by_test_id("two-step-secret").inner_text().replace(" ", "")
    theirs.get_by_label("6-digit code").fill(totp.code_at(secret, totp.step_at(time.time())))
    theirs.get_by_role("button", name="Turn on").click()
    expect(theirs.get_by_test_id("recovery-codes")).to_contain_text("-")
    codes = theirs.get_by_test_id("recovery-codes").inner_text().split()
    assert len(codes) == totp.RECOVERY_CODE_COUNT
    theirs.get_by_role("link", name="I have saved them").click()
    expect(theirs.get_by_test_id("two-step")).to_contain_text("10 recovery codes left")
    theirs.get_by_role("button", name="Sign out").click()

    # Signing in now asks for the second step, and a recovery code stands in for a lost phone.
    sign_in_as(theirs, server, username, chosen)
    code_field = theirs.get_by_label("Code from your authenticator app")
    expect(code_field).to_be_visible()
    expect(theirs.get_by_role("alert")).to_contain_text("6-digit code")
    code_field.fill(codes[0])
    theirs.get_by_role("button", name="Sign in").click()
    expect(theirs.get_by_test_id("current-user")).to_have_text(username)
    context.close()

    page.reload()
    expect(page.get_by_test_id("users-table").get_by_role("row", name=re.compile(username))).to_contain_text("on")


def test_sign_out_ends_the_session(page: Page, server: Server) -> None:
    sign_in_through_form(page, server, "analyst")  # its own session, so the shared ones stay valid
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(f"{server.url}/login")
    page.goto(f"{server.url}/")
    expect(page).to_have_url(re.compile(r"/login$"))


def test_pages_render_without_console_errors(page: Page, server: Server, sign_in: SignIn, csp_violations: list[str]) -> None:
    sign_in(page)
    for path in ("/", "/alerts", "/alerts?group=rule", "/agents", "/mutes", "/users", "/notifications", "/audit", "/account"):
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


def change_password(page: Page, current: str = "whatever-it-was-before-1", new: str = "a-brand-new-passphrase-1") -> None:
    form = page.locator('form[data-api="/account/password"]')
    form.get_by_label("Current password").fill(current)
    form.get_by_label("New password").fill(new)
    form.get_by_role("button", name="Update password").click()


def test_session_ended_by_the_server_is_announced_on_the_next_action(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page, "viewer")
    page.goto(f"{server.url}/account")
    # What the server answers once it has expired or revoked the session.
    refusal = '{"error": "Sign in required"}'
    page.route("**/account/password", lambda route: route.fulfill(status=401, content_type="application/json", body=refusal))
    change_password(page)
    expect(page.locator("#session-banner")).to_be_visible()
    expect(page.locator('form[data-api="/account/password"] .form-error')).to_contain_text("Your session has ended")
    expect(page).to_have_url(f"{server.url}/account")


def test_session_cookie_dropped_by_the_browser_is_announced_on_the_next_action(
    page: Page, server: Server, sign_in: SignIn
) -> None:
    sign_in(page, "viewer")
    page.goto(f"{server.url}/account")
    # Let the stream open first, so nothing still in flight can hand the cookie back.
    expect(page.locator("#live-indicator")).to_have_attribute("data-state", "live")
    page.context.clear_cookies(name="flasgo-session")  # the shared session itself stays valid for other tests

    # The CSRF token no longer matches, so the server answers 403 rather than 401.
    with page.expect_response("**/account/password") as refused:
        change_password(page)
    assert refused.value.status == 403

    banner = page.locator("#session-banner")
    expect(banner).to_be_visible()
    expect(banner.get_by_role("link", name="Sign in")).to_have_attribute("href", "/login?next=%2Faccount")
    expect(page.locator('form[data-api="/account/password"] .form-error')).to_contain_text("Your session has ended")
    expect(page).to_have_url(f"{server.url}/account")  # nothing typed is thrown away by a redirect
    expect(page.locator("#live-indicator")).to_have_attribute("data-state", "ended")


def test_ended_session_is_announced_when_live_updates_are_refused(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page, "viewer")

    def refuse(route: Route) -> None:
        # What the browser sees once the session is gone: the stream is refused outright.
        page.context.clear_cookies(name="flasgo-session")
        route.fulfill(status=401, content_type="application/json", body='{"error": "Sign in required"}')

    page.route("**/stream", refuse)
    page.goto(f"{server.url}/alerts?status=open")
    banner = page.locator("#session-banner")
    expect(banner).to_be_visible()
    expect(banner.get_by_role("link", name="Sign in")).to_have_attribute("href", "/login?next=%2Falerts%3Fstatus%3Dopen")
    expect(page.locator("#live-indicator")).to_have_attribute("data-state", "ended")


def test_refused_live_updates_with_a_valid_session_are_not_called_a_sign_out(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page, "viewer")
    page.route("**/stream", lambda route: route.fulfill(status=503, content_type="application/json", body="{}"))
    with page.expect_response("**/auth/session") as probe:
        page.goto(f"{server.url}/")
    assert probe.value.status == 200
    expect(page.locator("#session-banner")).to_be_hidden()
    expect(page.locator("#live-indicator")).to_have_attribute("data-state", "idle")


def test_enrol_link_from_the_overview_opens_the_dialog(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    page.goto(f"{server.url}/agents?enrol=1")
    expect(page.get_by_label("Agent name")).to_be_visible()
    expect(page).to_have_url(f"{server.url}/agents")  # so a reload does not open it again
    page.get_by_role("button", name="Cancel").click()
    page.reload()
    expect(page.get_by_label("Agent name")).to_be_hidden()


def test_pivot_from_an_alert_and_return_to_the_filtered_list(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name = unique("pivot")
    rule = unique("tg-rule")
    token = enrol_agent(page, server, name)
    title = f"Finding on {name}"
    server.ingest(token, [heartbeat(name), detection(unique("alert"), name, detection_message=title, detection_rule_id=rule)])

    filtered = f"{server.url}/alerts?q={name}&status=open"
    page.goto(filtered)
    page.get_by_role("link", name=title).click()
    expect(page.get_by_role("heading", name=title)).to_be_visible()
    page.get_by_role("link", name="Alerts", exact=True).last.click()
    expect(page).to_have_url(filtered)  # back to the list as it was, not to the default one

    page.get_by_role("link", name=title).click()
    page.locator("dl.facts").get_by_role("link", name=rule).click()
    expect(page).to_have_url(f"{server.url}/alerts?rule={rule}")
    chips = page.get_by_test_id("pivots")
    expect(chips).to_contain_text(rule)
    expect(page.get_by_test_id("alerts-table")).to_contain_text(title)

    page.get_by_label("Status").select_option("resolved")
    page.get_by_role("button", name="Apply").click()
    expect(chips).to_contain_text(rule)  # the form keeps the narrowing it has no control for
    expect(page.get_by_text("No alerts match")).to_be_visible()

    chips.get_by_role("link", name="Remove rule filter").click()
    expect(page).to_have_url(f"{server.url}/alerts?status=resolved")
    expect(page.get_by_test_id("pivots")).to_have_count(0)


def test_chart_hour_links_to_that_hours_alerts(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name = unique("chart")
    token = enrol_agent(page, server, name)
    server.ingest(token, [detection(unique("alert"), name, detection_message=f"Charted {name}")])

    page.goto(f"{server.url}/")
    page.locator("a.chart-hour").last.click()
    expect(page).to_have_url(re.compile(r"/alerts\?hour=\d+$"))
    expect(page.get_by_test_id("pivots")).to_contain_text("UTC")
    expect(page.get_by_test_id("alerts-table")).to_contain_text(f"Charted {name}")


def test_token_dialog_says_when_the_agent_has_connected(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name = unique("connect")
    page.goto(f"{server.url}/agents")
    page.get_by_role("button", name="Enrol agent").click()
    page.get_by_label("Agent name").fill(name)
    page.get_by_role("button", name="Create token").click()
    state = page.locator("#token-state")
    expect(state).to_have_attribute("data-state", "waiting")
    expect(page.get_by_test_id("token-snippet")).to_contain_text("Bearer tgm_")
    token = re.search(r"Bearer (tgm_[A-Za-z0-9_-]+)", page.get_by_test_id("token-snippet").inner_text())
    assert token is not None
    server.ingest(token.group(1), [heartbeat(name)])
    expect(state).to_have_attribute("data-state", "connected")
    expect(state).to_contain_text("Connected")


def test_select_all_matching_resolves_more_than_a_page(page: Page, browser: Browser, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name, rule = unique("flood"), unique("tg-flood")
    token = enrol_agent(page, server, name)
    server.ingest(token, [detection(unique("alert"), name, detection_rule_id=rule) for _ in range(50)])
    server.ingest(token, [detection(unique("alert"), name, detection_rule_id=rule) for _ in range(5)])

    page.goto(f"{server.url}/alerts?group=rule&q={rule}")
    row = page.get_by_test_id("groups-table").get_by_role("row", name=re.compile(rule))
    expect(row).to_contain_text("55")
    row.get_by_role("link", name=rule).click()

    expect(page.locator(".row-check")).to_have_count(50)
    page.get_by_label("Select all alerts on this page").check()
    expect(page.locator("#bulk-count")).to_have_text("50")
    page.get_by_role("button", name="Select all 55 matching").click()
    expect(page.locator("#bulk-count")).to_have_text("55")
    page.get_by_role("button", name="Resolve").click()
    expect(page.locator("#confirm-message")).to_contain_text("all 55 matching alerts as resolved")
    page.get_by_role("button", name="Confirm").click()
    expect(page.get_by_text("55 matching", exact=True)).to_be_visible()
    expect(page.get_by_test_id("alerts-table").get_by_text("open", exact=True)).to_have_count(0)


def test_keyboard_owner_history_and_mute_on_one_alert(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name, rule = unique("triage"), unique("tg-noisy")
    token = enrol_agent(page, server, name)
    first, second = f"First on {name}", f"Second on {name}"
    server.ingest(token, [detection(unique("alert"), name, detection_message=first, detection_rule_id=rule)])
    server.ingest(token, [detection(unique("alert"), name, detection_message=second, detection_rule_id=rule)])

    page.goto(f"{server.url}/alerts?rule={rule}")
    page.keyboard.press("?")
    expect(page.get_by_role("heading", name="Keyboard shortcuts")).to_be_visible()
    page.keyboard.press("Escape")
    page.keyboard.press("j")
    expect(page.locator("tr.is-cursor")).to_contain_text(second)  # newest first
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name=second)).to_be_visible()

    # The list it was opened from provides next and previous.
    expect(page.locator("[data-alert-nav]")).to_contain_text("1 of 2")
    page.keyboard.press("m")
    expect(page.get_by_test_id("alert-owner")).to_have_text("admin")
    page.get_by_label("Note").fill("Checked with the service owner.")
    page.get_by_role("button", name="Add note").click()
    expect(page.get_by_test_id("alert-history")).to_contain_text("Checked with the service owner.")
    expect(page.get_by_test_id("alert-history")).to_contain_text("gave this to admin")
    expect(page.get_by_test_id("alert-status")).to_have_text("open")

    # A toast stays until it is dismissed or times out; here it reports the copy.
    page.get_by_text("Raw record").click()
    page.get_by_role("button", name="Copy").click()
    expect(page.locator(".toast")).to_have_count(1)
    page.get_by_role("button", name="Dismiss").click()
    expect(page.locator(".toast")).to_have_count(0)

    page.keyboard.press("j")
    expect(page.get_by_role("heading", name=first)).to_be_visible()
    expect(page.locator("[data-alert-nav]")).to_contain_text("2 of 2")

    page.get_by_role("button", name="Mute").click()
    dialog = page.locator("#mute-dialog")
    dialog.get_by_label("What to mute").select_option("rule")
    dialog.get_by_label("Reason").fill("Known noisy rule")
    dialog.get_by_role("button", name="Mute").click()
    expect(page.get_by_test_id("alert-status")).to_have_text("muted")
    expect(page.get_by_test_id("muted-by")).to_contain_text("Known noisy rule")

    page.goto(f"{server.url}/mutes")
    row = page.get_by_test_id("mutes-table").get_by_role("row", name=re.compile(rule))
    expect(row).to_contain_text("Known noisy rule")
    row.get_by_role("button", name="Remove").click()
    page.get_by_role("button", name="Confirm").click()
    expect(page.get_by_test_id("mutes-table").get_by_role("row", name=re.compile(rule))).to_have_count(0)


def test_times_are_shown_in_the_viewers_zone(browser: Browser, server: Server, role_cookies: RoleCookies) -> None:
    context = browser.new_context(timezone_id="Asia/Kolkata", locale="en-GB")
    context.add_cookies(role_cookies["admin"])
    page = context.new_page()
    page.goto(f"{server.url}/audit")
    stamp = page.locator("time[data-local]").first
    expect(stamp).to_contain_text("GMT+5:30")
    expect(stamp).to_have_attribute("title", re.compile(r"UTC$"))  # the UTC time is one hover away
    page.goto(f"{server.url}/")
    expect(page.locator("[data-zone-note]")).to_have_text(re.compile(r"^times in Asia/(Kolkata|Calcutta)$"))
    expect(page.locator("text.chart-label").first).to_have_text(re.compile(r":30$"))  # a half-hour zone
    context.close()


def test_notification_channel_shows_its_secret_once(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name = unique("pager")
    page.goto(f"{server.url}/notifications")
    page.get_by_role("button", name="Add channel").click()
    dialog = page.locator("#channel-dialog")
    dialog.get_by_label("Name", exact=True).fill(name)
    dialog.locator('input[name="target"]').fill("https://hooks.example.com/services/very-secret-path")
    dialog.get_by_role("button", name="Add channel").click()
    secret = page.get_by_test_id("secret-value")
    expect(secret).to_have_text(re.compile(r"^[A-Za-z0-9_-]{40,}$"))
    shown = secret.inner_text()
    page.get_by_role("button", name="Done").click()
    row = page.get_by_test_id("channels-table").get_by_role("row", name=re.compile(name))
    expect(row).to_contain_text("hooks.example.com")
    assert "very-secret-path" not in page.content()
    assert shown not in page.content()

    row.get_by_role("button", name="Delete").click()
    page.get_by_role("button", name="Confirm").click()
    expect(page.get_by_test_id("channels-table").get_by_role("row", name=re.compile(name))).to_have_count(0)


def test_alerts_can_be_downloaded_as_csv(page: Page, server: Server, sign_in: SignIn) -> None:
    sign_in(page)
    name = unique("export")
    token = enrol_agent(page, server, name)
    server.ingest(token, [detection(unique("alert"), name, detection_message=f"Exported from {name}")])
    page.goto(f"{server.url}/alerts?q={name}")
    with page.expect_download() as download:
        page.get_by_role("link", name="CSV").click()
    saved = download.value
    assert saved.suggested_filename.startswith("traceguard-alerts-") and saved.suggested_filename.endswith(".csv")
    assert f"Exported from {name}" in open(saved.path(), encoding="utf-8").read()  # noqa: PTH123, SIM115
