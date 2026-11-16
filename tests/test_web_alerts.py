import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from traceguard_manager import alerts as alert_service
from traceguard_manager.models import Alert, AuditEvent

from .conftest import Site
from .helpers import blocked, detection, heartbeat

XSS = '<script>alert("xss")</script><img src=x onerror=alert(1)>'


async def _alert_ids(site: Site) -> list[str]:
    async with site.manager.database.session() as session:
        return [str(value) for value in await session.scalars(select(Alert.id).order_by(Alert.id))]


async def test_dashboard_shows_counts_and_recent_alerts(site: Site) -> None:
    await site.ingest([heartbeat(), detection("A"), detection("B", severity="warning"), blocked()])
    page = await (await site.viewer()).get("/")
    assert page.status_code == 200
    assert 'data-testid="open-alerts">3<' in page.text
    assert "Interactive shell spawned by a network service" in page.text
    assert "tg-reverse-shell" in page.text
    assert page.text.count('class="chart-bar') >= 1


async def test_alert_list_filters(site: Site) -> None:
    await site.ingest(
        [
            detection("A", detection_message="Reverse shell"),
            detection(
                "B", severity="warning", detection_message="Odd cron entry", detection_rule_id="tg-cron"
            ),
            blocked(),
        ]
    )
    browser = await site.viewer()

    everything = await browser.get("/alerts")
    assert "3 matching" in everything.text

    critical = await browser.get("/alerts?level=critical")
    assert "Reverse shell" in critical.text
    assert "Odd cron entry" not in critical.text

    by_kind = await browser.get("/alerts?kind=blocked")
    assert "egress blocked: evil.example" in by_kind.text
    assert "Reverse shell" not in by_kind.text

    search = await browser.get("/alerts?q=tg-cron")
    assert "Odd cron entry" in search.text
    assert "Reverse shell" not in search.text

    by_agent = await browser.get(f"/alerts?agent={site.agent_id}")
    assert "3 matching" in by_agent.text

    nonsense = await browser.get("/alerts?status=bogus&level=nope&agent=not-a-uuid&page=-4")
    assert nonsense.status_code == 200
    assert "3 matching" in nonsense.text


async def test_search_treats_wildcards_and_sql_as_plain_text(site: Site) -> None:
    await site.ingest(
        [detection("A", detection_message="100% CPU miner"), detection("B", detection_message="Other")]
    )
    browser = await site.viewer()

    percent = await browser.get("/alerts?q=%25")
    assert "1 matching" in percent.text
    assert "100% CPU miner" in percent.text

    underscore = await browser.get("/alerts?q=_")
    assert "0 matching" in underscore.text

    injection = await browser.get("/alerts?q=%27%20OR%201%3D1%20--")
    assert injection.status_code == 200
    assert "0 matching" in injection.text


async def test_pagination(site: Site) -> None:
    for start in range(0, 60, 30):
        await site.ingest([detection(f"ID{index}") for index in range(start, start + 30)])
    browser = await site.viewer()
    first = await browser.get("/alerts")
    assert "Page 1 of 2" in first.text
    assert first.text.count('class="row-level-') == alert_service.PAGE_SIZE
    second = await browser.get("/alerts?page=2")
    assert second.text.count('class="row-level-') == 10
    beyond = await browser.get("/alerts?page=99999999")
    assert beyond.status_code == 200


async def test_agent_supplied_text_is_escaped_everywhere(site: Site) -> None:
    await site.ingest(
        [
            heartbeat(hostname=XSS, policy_mode=XSS),
            detection(
                "A",
                hostname=XSS,
                detection_message=XSS,
                detection_rule_id=XSS,
                tags=[XSS],
                mitre_tactics=[XSS],
                exe=XSS,
                **{XSS: "key"},
            ),
        ]
    )
    browser = await site.admin()
    (alert_id,) = await _alert_ids(site)
    for path in ("/", "/alerts", f"/alerts/{alert_id}", "/agents", f"/agents/{site.agent_id}"):
        page = await browser.get(path)
        assert page.status_code == 200, path
        assert "<script>alert(" not in page.text, path
        assert "<img src=x" not in page.text, path
    detail = await browser.get(f"/alerts/{alert_id}")
    assert "&lt;script&gt;alert(" in detail.text


async def test_pages_have_no_inline_script_or_style(site: Site) -> None:
    await site.ingest([heartbeat(), detection("A")])
    browser = await site.admin()
    (alert_id,) = await _alert_ids(site)
    paths = [
        "/",
        "/alerts",
        f"/alerts/{alert_id}",
        "/agents",
        f"/agents/{site.agent_id}",
        "/users",
        "/audit",
        "/account",
    ]
    for path in paths:
        text = (await browser.get(path)).text
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path
        assert "<style" not in text, path
        assert not re.search(r"\sstyle=", text), path
        assert not re.search(r"\son[a-z]+=", text), path


async def test_alert_detail_shows_fields(site: Site) -> None:
    await site.ingest([detection("A")])
    (alert_id,) = await _alert_ids(site)
    page = await (await site.viewer()).get(f"/alerts/{alert_id}")
    assert page.status_code == 200
    for expected in ("tg-reverse-shell", "TA0002", "T1059", "/usr/bin/bash", "4242", "web-01"):
        assert expected in page.text
    assert "Your role is read-only" in page.text


async def test_unknown_alert_is_404(site: Site) -> None:
    browser = await site.viewer()
    assert (await browser.get("/alerts/00000000-0000-7000-8000-000000000000")).status_code == 404


async def test_analyst_can_triage_and_it_is_audited(site: Site) -> None:
    await site.ingest([detection("A")])
    (alert_id,) = await _alert_ids(site)
    browser = await site.analyst()

    response = await browser.post(
        "/alerts/status", {"ids": [alert_id], "status": "acknowledged", "note": "Looking into it"}
    )
    assert response.status_code == 200
    assert response.json() == {"changed": 1}

    async with site.manager.database.session() as session:
        alert = (await session.scalars(select(Alert))).one()
        audit = (await session.scalars(select(AuditEvent).where(AuditEvent.action == "alert.status"))).one()
    assert alert.status == "acknowledged"
    assert alert.status_changed_by == "analyst"
    assert alert.note == "Looking into it"
    assert audit.actor == "analyst"
    assert audit.detail == {"status": "acknowledged", "changed": 1}

    page = await browser.get(f"/alerts/{alert_id}")
    assert "Acknowledged by analyst" in page.text


async def test_bulk_status_change(site: Site) -> None:
    await site.ingest([detection("A"), detection("B"), detection("C")])
    ids = await _alert_ids(site)
    browser = await site.analyst()
    response = await browser.post("/alerts/status", {"ids": ids[:2], "status": "resolved"})
    assert response.json() == {"changed": 2}
    open_page = await browser.get("/alerts?status=open")
    assert "1 matching" in open_page.text


async def test_viewer_cannot_triage(site: Site) -> None:
    await site.ingest([detection("A")])
    (alert_id,) = await _alert_ids(site)
    browser = await site.viewer()
    response = await browser.post("/alerts/status", {"ids": [alert_id], "status": "resolved"})
    assert response.status_code == 403
    async with site.manager.database.session() as session:
        assert (await session.scalars(select(Alert))).one().status == "open"


async def test_status_change_validation(site: Site) -> None:
    await site.ingest([detection("A")])
    (alert_id,) = await _alert_ids(site)
    browser = await site.analyst()

    bad_status = await browser.post("/alerts/status", {"ids": [alert_id], "status": "deleted"})
    assert bad_status.status_code == 400
    assert bad_status.json() == {"error": "Unknown status."}

    bad_id = await browser.post("/alerts/status", {"ids": ["1 OR 1=1"], "status": "resolved"})
    assert bad_id.status_code == 400

    empty = await browser.post("/alerts/status", {"ids": [], "status": "resolved"})
    assert empty.status_code == 400

    too_many = await browser.post("/alerts/status", {"ids": [alert_id] * 500, "status": "resolved"})
    assert too_many.status_code == 400

    long_note = await browser.post(
        "/alerts/status", {"ids": [alert_id], "status": "resolved", "note": "x" * 2001}
    )
    assert long_note.status_code == 400

    wrong_type = await browser.post("/alerts/status", {"ids": "nope", "status": "resolved"})
    assert wrong_type.status_code == 422


async def test_retention_removes_only_old_alerts(site: Site) -> None:
    old = (datetime.now(UTC) - timedelta(days=120)).isoformat()
    await site.ingest([detection("OLD", timestamp=old), detection("NEW")])
    async with site.manager.database.session() as session:
        removed = await alert_service.purge_older_than(session, cutoff=datetime.now(UTC) - timedelta(days=90))
    assert removed == 1
    assert len(await _alert_ids(site)) == 1
