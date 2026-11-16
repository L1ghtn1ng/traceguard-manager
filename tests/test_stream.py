import asyncio
import json

import pytest
from flasgo import TestClient

from traceguard_manager.signals import ChangeSignal

from .conftest import Site
from .helpers import ADMIN_PASSWORD, detection


async def test_signal_wakes_every_waiter() -> None:
    signal = ChangeSignal()
    waiters = [asyncio.create_task(signal.wait()) for _ in range(3)]
    await asyncio.sleep(0)
    signal.notify()
    async with asyncio.timeout(1):
        await asyncio.gather(*waiters)


async def test_signal_wait_can_be_bounded_and_leaves_nothing_behind() -> None:
    signal = ChangeSignal()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await signal.wait()
    assert not signal._waiters


async def test_stream_requires_a_session(site: Site) -> None:
    response = await site.browser().get("/stream", accept="text/event-stream")
    assert response.status_code == 401


async def test_stream_delivers_new_alerts(site: Site) -> None:
    await site.ingest([detection("BEFORE", detection_message="Old alert")])
    browser = await site.signed_in("admin", ADMIN_PASSWORD)
    cookie = f"flasgo-session={browser.session_cookie()}"

    async with TestClient(site.manager.web) as client:  # noqa: SIM117
        async with client.astream("GET", "/stream", headers={"cookie": cookie}) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            chunks = response.iter_bytes()
            await site.ingest([detection("AFTER", detection_message="Fresh <b>alert</b>")])
            received = b""
            async with asyncio.timeout(10):
                while b"\n\n" not in received or b"event: alert" not in received:
                    received += await anext(chunks)

    text = received.decode()
    assert "event: alert" in text
    data = next(line for line in text.splitlines() if line.startswith("data: "))
    event = json.loads(data.removeprefix("data: "))
    assert event["title"] == "Fresh <b>alert</b>"  # sent as JSON data; the client renders it as text
    assert event["level"] == "critical"
    assert event["hostname"] == "web-01"
    assert "Old alert" not in text  # only alerts created after connecting
