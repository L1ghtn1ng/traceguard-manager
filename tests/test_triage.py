"""Finding alerts (time, order, labels, groups, export) and working them (notes, owners, bulk, mutes)."""

import csv
import io
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from traceguard_manager import alerts as alert_service
from traceguard_manager.models import Alert, AlertEvent, AuditEvent, MuteRule, User, utcnow

from .conftest import Site
from .helpers import blocked, data, detection, heartbeat


async def _ids(site: Site) -> dict[str, str]:
    """Alert ids by title."""
    async with site.manager.database.session() as session:
        return {title: str(alert_id) for title, alert_id in await session.execute(select(Alert.title, Alert.id))}


async def _statuses(site: Site) -> dict[str, str]:
    async with site.manager.database.session() as session:
        return dict((await session.execute(select(Alert.title, Alert.status))).all())


async def test_time_range_limits_the_list(site: Site) -> None:
    old = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    await site.ingest(
        [detection("A", detection_message="Fresh finding"), detection("B", detection_message="Old finding", timestamp=old)]
    )
    browser = await site.viewer()
    assert "2 matching" in (await browser.get("/alerts")).text
    recent = await browser.get("/alerts?range=24h")
    assert "1 matching" in recent.text
    assert "Old finding" not in recent.text
    assert "2 matching" in (await browser.get("/alerts?range=7d")).text
    assert "2 matching" in (await browser.get("/alerts?range=nonsense")).text


async def test_sorting_by_severity_in_both_directions(site: Site) -> None:
    await site.ingest(
        [
            detection("A", severity="notice", detection_message="Low one"),
            detection("B", severity="critical", detection_message="Critical one"),
            detection("C", severity="warning", detection_message="Medium one"),
        ]
    )
    browser = await site.viewer()
    worst_first = (await browser.get("/alerts?sort=severity")).text
    assert worst_first.index("Critical one") < worst_first.index("Medium one") < worst_first.index("Low one")
    assert 'aria-sort="descending"' in worst_first
    least_first = (await browser.get("/alerts?sort=severity&dir=asc")).text
    assert least_first.index("Low one") < least_first.index("Medium one") < least_first.index("Critical one")
    # The heading link flips the direction, and an unknown column falls back to time.
    assert 'href="/alerts?sort=severity&amp;dir=asc"' in worst_first
    assert (await browser.get("/alerts?sort=password_hash")).status_code == 200


async def test_labels_are_links_that_narrow_the_list(site: Site) -> None:
    await site.ingest(
        [
            detection(
                "A", detection_message="Shell", tags=["shell", "execution"], mitre_tactics=["TA0002"], mitre_techniques=["T1059"]
            ),
            detection(
                "B", detection_message="Miner", tags=["cryptomining"], mitre_tactics=["TA0040"], mitre_techniques=["T1496"]
            ),
        ]
    )
    browser = await site.viewer()
    for query, wanted, unwanted in (
        ("tag=shell", "Shell", "Miner"),
        ("tactic=TA0040", "Miner", "Shell"),
        ("technique=T1059", "Shell", "Miner"),
    ):
        page = (await browser.get(f"/alerts?{query}")).text
        assert "1 matching" in page, query
        assert wanted in page and unwanted not in page, query
        assert 'data-testid="pivots"' in page, query
    # A partial value is not a match, and odd input is only ever a bound parameter.
    assert "0 matching" in (await browser.get("/alerts?tag=shel")).text
    assert "0 matching" in (await browser.get("/alerts?tag=%27%20OR%201%3D1--")).text

    detail = (await browser.get(f"/alerts/{(await _ids(site))['Shell']}")).text
    assert 'href="/alerts?tag=shell"' in detail
    assert 'href="/alerts?tactic=TA0002"' in detail
    assert 'href="/alerts?technique=T1059"' in detail


async def test_grouping_collapses_a_noisy_rule(site: Site) -> None:
    await site.ingest(
        [detection(f"N{index}", detection_rule_id="tg-noisy", severity="warning") for index in range(5)]
        + [detection("Q", detection_rule_id="tg-quiet", severity="critical", hostname="db-01"), blocked()]
    )
    browser = await site.viewer()
    by_rule = (await browser.get("/alerts?group=rule")).text
    assert 'data-testid="groups-table"' in by_rule
    assert "7 matching" in by_rule
    assert by_rule.index("tg-noisy") < by_rule.index("tg-quiet")  # busiest first
    assert 'href="/alerts?rule=tg-noisy"' in by_rule
    assert "No rule (enforcement and agent events)" in by_rule
    by_host = (await browser.get("/alerts?group=host&level=critical")).text
    assert 'href="/alerts?level=critical&amp;host=db-01"' in by_host
    assert "web-01" not in by_host.split('data-testid="groups-table"')[1]


async def test_export_as_csv_and_json(site: Site) -> None:
    await site.ingest(
        [
            detection("A", detection_message='=HYPERLINK("http://evil.example","click")', hostname="web-01"),
            detection("B", detection_message="Ordinary finding", severity="warning", hostname="db-01"),
        ]
    )
    browser = await site.viewer()
    exported = await browser.get("/alerts/export?format=csv&host=web-01", accept="text/csv")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    assert "attachment" in exported.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert len(rows) == 1  # the filters apply to the export too
    assert rows[0]["title"].startswith("'=HYPERLINK")  # a spreadsheet must not run agent-supplied text
    assert rows[0]["agent"] == "web-01"
    assert rows[0]["tags"] == "shell execution"

    as_json = await browser.get("/alerts/export?format=json", accept="application/json")
    records = as_json.json()
    assert isinstance(records, list) and len(records) == 2
    assert {record["hostname"] for record in records} == {"web-01", "db-01"}

    async with site.manager.database.session() as session:
        logged = list(await session.scalars(select(AuditEvent).where(AuditEvent.action == "alert.export")))
    assert [event.detail["rows"] for event in logged] == [1, 2]
    assert (await site.browser().get("/alerts/export")).status_code in {303, 401}


async def test_notes_and_status_changes_build_a_history(site: Site) -> None:
    await site.ingest([detection("A", detection_message="Finding")])
    alert_id = (await _ids(site))["Finding"]
    analyst = await site.analyst()

    assert (await analyst.post("/alerts/status", {"ids": [alert_id], "note": "Looking into it."})).status_code == 200
    assert (await _statuses(site))["Finding"] == "open"  # a note alone changes nothing else
    assert (
        await analyst.post("/alerts/status", {"ids": [alert_id], "status": "resolved", "note": "False positive."})
    ).status_code == 200
    assert data(await analyst.post("/alerts/status", {"ids": [alert_id], "status": "resolved"}))["changed"] == 0

    async with site.manager.database.session() as session:
        events = list(await session.scalars(select(AlertEvent).order_by(AlertEvent.at, AlertEvent.id)))
    assert [(event.action, event.status, event.note) for event in events] == [
        ("note", None, "Looking into it."),
        ("status", "resolved", "False positive."),
    ]
    page = (await analyst.get(f"/alerts/{alert_id}")).text
    assert 'data-testid="alert-history"' in page
    assert "Looking into it." in page and "False positive." in page

    empty = await analyst.post("/alerts/status", {"ids": [alert_id], "note": "   "})
    assert empty.status_code == 400
    assert (await (await site.viewer()).post("/alerts/status", {"ids": [alert_id], "note": "Not allowed"})).status_code == 403


async def test_alerts_can_be_given_an_owner(site: Site) -> None:
    await site.ingest([detection("A", detection_message="Mine"), detection("B", detection_message="Nobody's")])
    ids = await _ids(site)
    analyst = await site.analyst()
    async with site.manager.database.session() as session:
        users = {user.username: str(user.id) for user in await session.scalars(select(User))}

    assert data(await analyst.post("/alerts/assign", {"ids": [ids["Mine"]], "assignee": "me"})) == {
        "changed": 1,
        "assignee": "analyst",
    }
    assert 'data-testid="alert-owner">analyst<' in (await analyst.get(f"/alerts/{ids['Mine']}")).text
    mine = (await analyst.get("/alerts?owner=me")).text
    assert "1 matching" in mine and "Mine" in mine
    unowned = (await analyst.get("/alerts?owner=none")).text
    assert "1 matching" in unowned and "Nobody" in unowned
    # "Mine" means whoever is looking, so the same link shows the admin nothing.
    assert "0 matching" in (await (await site.admin()).get("/alerts?owner=me")).text
    assert "1 matching" in (await (await site.admin()).get(f"/alerts?owner={users['analyst']}")).text

    # Read-only accounts cannot be given work, and cannot hand it out.
    assert (await analyst.post("/alerts/assign", {"ids": [ids["Mine"]], "assignee": users["viewer"]})).status_code == 400
    assert (await (await site.viewer()).post("/alerts/assign", {"ids": [ids["Mine"]], "assignee": "me"})).status_code == 403

    assert data(await analyst.post("/alerts/assign", {"ids": [ids["Mine"]], "assignee": ""}))["assignee"] is None
    async with site.manager.database.session() as session:
        handovers = list(
            await session.scalars(select(AlertEvent.assignee).where(AlertEvent.action == "assign").order_by(AlertEvent.at))
        )
    assert handovers == ["analyst", None]


async def test_related_alerts_are_listed_on_the_detail_page(site: Site) -> None:
    await site.ingest(
        [
            detection("A", detection_message="The one being read"),
            detection("B", detection_message="Same rule elsewhere", hostname="db-01"),
            detection("C", detection_message="Same host other rule", detection_rule_id="tg-other"),
            detection("D", detection_message="Unrelated", detection_rule_id="tg-other", hostname="db-01"),
        ]
    )
    page = (await (await site.viewer()).get(f"/alerts/{(await _ids(site))['The one being read']}")).text
    related = page.split("<h2>Related</h2>")[1].split("<h2>Triage</h2>")[0]
    assert "Same rule elsewhere" in related or "db-01" in related
    assert "Same host other rule" in related
    assert "Unrelated" not in related


async def test_select_all_matching_changes_more_than_one_page(site: Site) -> None:
    await site.ingest(
        [detection(f"N{index}", detection_rule_id="tg-noisy") for index in range(60)]
        + [detection("K", detection_rule_id="tg-keep")]
    )
    analyst = await site.analyst()
    listing = (await analyst.get("/alerts?rule=tg-noisy")).text
    assert "60 matching" in listing
    assert "Select all 60 matching" in listing

    changed = await analyst.post("/alerts/status", {"filter": {"rule": "tg-noisy"}, "status": "resolved"})
    assert data(changed)["changed"] == 60
    async with site.manager.database.session() as session:
        counts = dict((await session.execute(select(Alert.status, func.count()).group_by(Alert.status))).all())
        assert await session.scalar(select(func.count()).select_from(AlertEvent)) == 60
    assert counts == {"resolved": 60, "open": 1}

    assert (await analyst.post("/alerts/status", {"filter": {"rule": "tg-noisy"}})).status_code == 400  # a status is required
    assert (await (await site.viewer()).post("/alerts/status", {"filter": {}, "status": "resolved"})).status_code == 403


async def test_muting_a_rule_on_one_host(site: Site) -> None:
    await site.ingest(
        [
            heartbeat(),
            detection("A", detection_message="Noisy here", detection_rule_id="tg-noisy"),
            detection("B", detection_message="Noisy there", detection_rule_id="tg-noisy", hostname="db-01"),
        ]
    )
    ids = await _ids(site)
    analyst = await site.analyst()
    body = {"alert_id": ids["Noisy here"], "scope": "rule_host", "duration": "24h", "reason": "Known batch job"}
    created = await analyst.post("/mutes", body)
    assert created.status_code == 201
    assert data(created)["muted"] == 1  # the open alert it covers is moved out of the way at once

    await site.ingest(
        [
            detection("C", detection_message="Noisy here again", detection_rule_id="tg-noisy"),
            detection("D", detection_message="Other rule here", detection_rule_id="tg-other"),
        ]
    )
    statuses = await _statuses(site)
    assert statuses == {"Noisy here": "muted", "Noisy there": "open", "Noisy here again": "muted", "Other rule here": "open"}

    listing = (await analyst.get("/alerts")).text
    assert "2 matching" in listing and "Noisy here again" not in listing  # muted alerts stay out of the way
    assert "2 matching" in (await analyst.get("/alerts?status=muted")).text
    assert 'data-testid="open-alerts">2<' in (await analyst.get("/")).text
    assert 'data-testid="muted-by"' in (await analyst.get(f"/alerts/{ids['Noisy here']}")).text
    async with site.manager.database.session() as session:
        announced = await alert_service.alerts_after(session, None)
    assert {alert.title for alert in announced} == {"Noisy there", "Other rule here"}  # no live toast for muted alerts

    page = (await analyst.get("/mutes")).text
    assert "Known batch job" in page and "tg-noisy" in page
    async with site.manager.database.session() as session:
        rule_id = str(await session.scalar(select(MuteRule.id)))
    assert (await (await site.viewer()).send("DELETE", f"/mutes/{rule_id}")).status_code == 403
    assert (await analyst.send("DELETE", f"/mutes/{rule_id}")).status_code == 200
    await site.ingest([detection("E", detection_message="Noisy after unmute", detection_rule_id="tg-noisy")])
    assert (await _statuses(site))["Noisy after unmute"] == "open"


async def test_mute_rules_expire_and_need_a_reason(site: Site) -> None:
    analyst = await site.analyst()
    assert (await analyst.post("/mutes", {"rule_id": "tg-noisy", "reason": "  ", "duration": "1h"})).status_code == 400
    assert (await analyst.post("/mutes", {"reason": "Nothing chosen", "duration": "1h"})).status_code == 400
    assert (await analyst.post("/mutes", {"rule_id": "tg-noisy", "reason": "Why", "duration": "a while"})).status_code == 400
    assert (
        await (await site.viewer()).post("/mutes", {"rule_id": "tg-noisy", "reason": "Why", "duration": "1h"})
    ).status_code == 403

    assert (
        await analyst.post("/mutes", {"rule_id": "tg-noisy", "reason": "Short maintenance", "duration": "1h"})
    ).status_code == 201
    async with site.manager.database.session() as session:
        rule = await session.scalar(select(MuteRule))
        assert rule is not None
        rule.expires_at = utcnow() - timedelta(seconds=1)
    await site.ingest([detection("A", detection_message="After expiry", detection_rule_id="tg-noisy")])
    assert (await _statuses(site))["After expiry"] == "open"
    assert "Short maintenance" not in (await analyst.get("/mutes")).text
