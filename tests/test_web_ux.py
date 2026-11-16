"""First-run guidance, links that narrow the alert list, and the session probe."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete

from traceguard_manager.models import Agent

from .conftest import Site
from .helpers import data, detection, heartbeat


async def _remove_all_agents(site: Site) -> None:
    async with site.manager.database.session() as session:
        await session.execute(delete(Agent))


async def test_overview_walks_an_admin_through_the_first_agent(site: Site) -> None:
    await _remove_all_agents(site)
    page = await (await site.admin()).get("/")
    assert 'data-testid="onboarding"' in page.text
    assert 'href="/agents?enrol=1"' in page.text
    assert "All clear" not in page.text  # nothing is reporting, so that would mislead


async def test_overview_tells_other_roles_who_can_enrol(site: Site) -> None:
    await _remove_all_agents(site)
    page = await (await site.viewer()).get("/")
    assert 'data-testid="onboarding"' in page.text
    assert "Ask an administrator" in page.text
    assert "/agents?enrol=1" not in page.text


async def test_overview_waits_for_a_first_heartbeat_then_reports_all_clear(site: Site) -> None:
    browser = await site.viewer()
    waiting = await browser.get("/")
    assert 'data-testid="awaiting-heartbeat"' in waiting.text
    assert 'data-testid="onboarding"' not in waiting.text
    assert "All clear" not in waiting.text

    await site.ingest([heartbeat()])
    reporting = await browser.get("/")
    assert 'data-testid="awaiting-heartbeat"' not in reporting.text
    assert "All clear" in reporting.text


async def test_enrol_link_opens_the_dialog_for_admins_only(site: Site) -> None:
    admin = await site.admin()
    assert "data-auto-open" in (await admin.get("/agents?enrol=1")).text
    assert "data-auto-open" not in (await admin.get("/agents")).text
    assert "data-auto-open" not in (await (await site.viewer()).get("/agents?enrol=1")).text


async def test_alert_list_narrows_by_rule_host_and_hour(site: Site) -> None:
    now = datetime.now(UTC)
    yesterday = now - timedelta(hours=20)
    await site.ingest(
        [
            detection("A", detection_message="Reverse shell"),
            detection("B", detection_message="Odd cron entry", detection_rule_id="tg-cron", hostname="db-01"),
            detection("C", detection_message="Old finding", detection_rule_id="tg-cron-old", timestamp=yesterday.isoformat()),
        ]
    )
    browser = await site.viewer()

    by_rule = await browser.get("/alerts?rule=tg-cron")
    assert "1 matching" in by_rule.text  # exact: "tg-cron-old" is a different rule
    assert "Odd cron entry" in by_rule.text
    assert 'data-testid="pivots"' in by_rule.text
    assert '<input type="hidden" name="rule" value="tg-cron">' in by_rule.text  # kept when the form is applied

    by_host = await browser.get("/alerts?host=db-01")
    assert "1 matching" in by_host.text
    assert "Odd cron entry" in by_host.text

    hour = int(yesterday.timestamp()) // 3600
    by_hour = await browser.get(f"/alerts?hour={hour}&status=open")
    assert "1 matching" in by_hour.text
    assert "Old finding" in by_hour.text
    assert yesterday.strftime("%Y-%m-%d %H:00 UTC") in by_hour.text
    assert 'href="/alerts?status=open"' in by_hour.text  # removing the chip keeps the other filters

    out_of_range = await browser.get("/alerts?hour=-5")
    assert "3 matching" in out_of_range.text
    assert 'data-testid="pivots"' not in out_of_range.text


async def test_overview_and_detail_link_to_narrowed_lists(site: Site) -> None:
    await site.ingest([heartbeat(), detection("A", detection_rule_id="tg odd&rule=1")])
    browser = await site.viewer()

    overview = await browser.get("/")
    hour = int(datetime.now(UTC).timestamp()) // 3600
    # Encoded, so the rule cannot add parameters; limited to the 7 days the overview counts.
    assert 'href="/alerts?range=7d&amp;rule=tg%20odd%26rule%3D1"' in overview.text
    assert 'href="/alerts?range=7d&amp;host=web-01"' in overview.text
    assert f'href="/alerts?hour={hour}"' in overview.text or f'href="/alerts?hour={hour - 1}"' in overview.text
    assert overview.text.count('<a class="chart-hour"') == 1  # empty hours are not links

    listing = await browser.get("/alerts?rule=tg%20odd%26rule%3D1")
    assert "1 matching" in listing.text
    detail_path = listing.text.split('class="row-link" href="')[1].split('"')[0]
    detail = await browser.get(detail_path)
    assert 'href="/alerts?rule=tg%20odd%26rule%3D1"' in detail.text
    assert 'href="/alerts?host=web-01"' in detail.text
    assert "data-back" in detail.text


async def test_session_probe_tells_a_live_session_from_an_ended_one(site: Site) -> None:
    browser = await site.viewer()
    live = await browser.get("/auth/session", accept="application/json")
    assert live.status_code == 200
    assert data(live) == {"username": "viewer"}

    assert (await browser.post("/auth/logout")).status_code == 200
    ended = await browser.get("/auth/session", accept="application/json")
    assert ended.status_code == 401
    assert ended.headers["content-type"].startswith("application/json")  # not a redirect to the sign-in page
