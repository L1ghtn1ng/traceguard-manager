"""Commands: queued from the console, fetched by an agent's long-poll, and reported back."""

import asyncio
import uuid
from collections.abc import Mapping
from datetime import timedelta

import pytest
from sqlalchemy import select

from traceguard_manager import commands
from traceguard_manager.models import AgentCommand, Alert, AuditEvent, CommandStatus, utcnow

from .conftest import Site
from .helpers import data, detection


async def _poll(site: Site, wait: int = 0, *, token: str | None = None):
    return await site.agent_client().arequest(
        "GET", f"/api/v1/commands?wait={wait}", headers={"authorization": f"Bearer {token or site.agent_token}"}
    )


async def _report(site: Site, command_id: str, body: object, *, token: str | None = None):
    return await site.agent_client().arequest(
        "POST",
        f"/api/v1/commands/{command_id}/result",
        json=body,
        headers={"authorization": f"Bearer {token or site.agent_token}"},
    )


async def _send(site: Site, body: Mapping[str, object]):
    browser = await site.admin()
    return await browser.post(f"/agents/{site.agent_id}/commands", body)


async def _command(site: Site, command_id: str) -> AgentCommand:
    async with site.manager.database.session() as session:
        command = await session.get(AgentCommand, uuid.UUID(command_id))
        assert command is not None
        return command


async def test_a_queued_command_is_fetched_run_and_reported(site: Site) -> None:
    sent = await _send(site, {"action": "block_peer", "target": "::ffff:203.0.113.7", "duration": "1h"})
    assert sent.status_code == 201, sent.text
    command_id = data(sent)["id"]

    polled = await _poll(site)
    assert polled.status_code == 200
    [wired] = polled.json()["commands"]
    assert wired == {
        "id": command_id,
        "action": "block_peer",
        "target": "203.0.113.7",
        "duration_seconds": 3600,
        "expires_at": wired["expires_at"],
    }
    assert (await _command(site, command_id)).status == CommandStatus.DELIVERED.value
    # Delivered once: the next poll has nothing until the redelivery window passes.
    assert (await _poll(site)).status_code == 204

    reported = await _report(site, command_id, {"status": "done"})
    assert reported.status_code == 204
    command = await _command(site, command_id)
    assert command.status == "done" and command.completed_at is not None
    # A repeated report changes nothing.
    assert (await _report(site, command_id, {"status": "failed", "detail": "late"})).status_code == 204
    assert (await _command(site, command_id)).status == "done"

    page = (await (await site.admin()).get(f"/agents/{site.agent_id}")).text
    assert "Block peer 203.0.113.7 for 1 h" in page and "command-done" in page
    async with site.manager.database.session() as session:
        actions = list(await session.scalars(select(AuditEvent.action)))
    assert "agent.command" in actions


async def test_failures_and_refusals_are_shown(site: Site) -> None:
    command_id = data(await _send(site, {"action": "freeze_cgroup", "target": "4242", "duration": "15m"}))["id"]
    await _poll(site)
    detail = "refusing to freeze: it contains TraceGuard"
    assert (await _report(site, command_id, {"status": "failed", "detail": detail})).status_code == 204
    page = (await (await site.admin()).get(f"/agents/{site.agent_id}")).text
    assert detail in page and "command-failed" in page


async def test_a_waiting_poll_wakes_when_a_command_is_queued(site: Site) -> None:
    async def queue_soon() -> None:
        await asyncio.sleep(0.3)
        await _send(site, {"action": "refresh_policy"})

    started = asyncio.get_running_loop().time()
    polled, _ = await asyncio.gather(_poll(site, wait=10), queue_soon())
    assert polled.status_code == 200
    assert polled.json()["commands"][0]["action"] == "refresh_policy"
    assert asyncio.get_running_loop().time() - started < 5


async def test_an_unreported_command_is_sent_again_and_old_ones_expire(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    await _poll(site)
    async with site.manager.database.session() as session:
        command = await session.get(AgentCommand, uuid.UUID(command_id))
        assert command is not None
        command.delivered_at = utcnow() - commands.REDELIVER_AFTER - timedelta(seconds=1)
    again = await _poll(site)
    assert again.status_code == 200 and again.json()["commands"][0]["id"] == command_id

    async with site.manager.database.session() as session:
        command = await session.get(AgentCommand, uuid.UUID(command_id))
        assert command is not None
        command.expires_at = utcnow() - timedelta(seconds=1)
    # Past its deadline it is not sent again, but the agent may still be reporting.
    assert (await _poll(site)).status_code == 204
    assert (await _command(site, command_id)).status == CommandStatus.DELIVERED.value
    async with site.manager.database.session() as session:
        await commands.expire_stale(session, now=utcnow() + commands.RESULT_GRACE)
    command = await _command(site, command_id)
    assert command.status == CommandStatus.EXPIRED.value and "never reported" in (command.detail or "")
    # A result that still arrives says what really happened.
    assert (await _report(site, command_id, {"status": "done"})).status_code == 204
    assert (await _command(site, command_id)).status == "done"


async def test_a_never_fetched_command_expires_at_its_deadline(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    async with site.manager.database.session() as session:
        await commands.expire_stale(session, now=utcnow() + commands.COMMAND_LIFETIME)
    command = await _command(site, command_id)
    assert command.status == CommandStatus.EXPIRED.value and "did not pick it up" in (command.detail or "")
    assert (await _report(site, command_id, {"status": "done"})).status_code == 204
    assert (await _command(site, command_id)).status == CommandStatus.EXPIRED.value


async def test_queued_commands_can_be_cancelled(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    browser = await site.admin()
    assert (await browser.send("DELETE", f"/agents/{site.agent_id}/commands/{command_id}")).status_code == 200
    assert (await _poll(site)).status_code == 204
    assert (await _command(site, command_id)).status == CommandStatus.CANCELLED.value
    # Once fetched it cannot be called back.
    second = data(await _send(site, {"action": "refresh_policy"}))["id"]
    await _poll(site)
    refused = await browser.send("DELETE", f"/agents/{site.agent_id}/commands/{second}")
    assert refused.status_code == 400


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"action": "block_peer", "target": "not-an-ip", "duration": "1h"}, "IP address"),
        ({"action": "block_peer", "target": "127.0.0.1", "duration": "1h"}, "Loopback"),
        ({"action": "block_peer", "target": "203.0.113.7"}, "how long"),
        ({"action": "block_peer", "target": "203.0.113.7", "duration": "99y"}, "how long"),
        ({"action": "freeze_cgroup", "target": "-1", "duration": "1h"}, "cgroup ID"),
        ({"action": "freeze_cgroup", "target": str(2**64), "duration": "1h"}, "cgroup ID"),
        ({"action": "lift_response", "target": "203.0.113.7", "response_action": "reboot"}, "kind of response"),
        ({"action": "run_shell", "target": "id"}, "Unknown command"),
    ],
)
async def test_commands_are_checked_before_queueing(site: Site, body: dict[str, object], message: str) -> None:
    response = await _send(site, body)
    assert response.status_code == 400 and message in response.text


async def test_only_admins_send_commands(site: Site) -> None:
    for role in ("analyst", "viewer"):
        browser = await getattr(site, role)()
        refused = await browser.post(f"/agents/{site.agent_id}/commands", {"action": "refresh_policy"})
        assert refused.status_code == 403
        assert 'data-testid="command-form"' not in (await browser.get(f"/agents/{site.agent_id}")).text


async def test_an_agent_sees_and_reports_only_its_own_commands(site: Site) -> None:
    browser = await site.admin()
    created = data(await browser.post("/agents", {"name": "db-01"}))
    other_token = created["token"]
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    assert (await _poll(site, token=other_token)).status_code == 204
    assert (await _report(site, command_id, {"status": "done"}, token=other_token)).status_code == 404
    assert (await _command(site, command_id)).status == CommandStatus.QUEUED.value
    assert (await _report(site, command_id, {"status": "launched"})).status_code == 400
    assert (await _report(site, "not-a-uuid", {"status": "done"})).status_code == 404
    unauthenticated = await site.agent_client().arequest("GET", "/api/v1/commands")
    assert unauthenticated.status_code == 401


async def test_a_disabled_agent_gets_no_commands(site: Site) -> None:
    browser = await site.admin()
    await browser.post(f"/agents/{site.agent_id}/enabled", {"enabled": False})
    response = await browser.post(f"/agents/{site.agent_id}/commands", {"action": "refresh_policy"})
    assert response.status_code == 400 and "disabled" in response.text
    # Its token no longer works either.
    assert (await _poll(site)).status_code == 401


async def test_outstanding_commands_are_bounded(site: Site) -> None:
    browser = await site.admin()
    path = f"/agents/{site.agent_id}/commands"
    for _ in range(commands.MAX_OUTSTANDING):
        assert (await browser.post(path, {"action": "refresh_policy"})).status_code == 201
    response = await browser.post(path, {"action": "refresh_policy"})
    assert response.status_code == 400 and "already has" in response.text
    # One poll hands over at most a bounded batch.
    assert len((await _poll(site)).json()["commands"]) == commands.MAX_PER_POLL


async def test_a_command_from_an_alert_is_linked_to_it(site: Site) -> None:
    await site.ingest([detection("A1", peer_address="198.51.100.20")])
    async with site.manager.database.session() as session:
        alert = await session.scalar(select(Alert))
        assert alert is not None
    body = {"action": "block_peer", "target": "198.51.100.20", "duration": "15m", "alert_id": str(alert.id)}
    command_id = data(await _send(site, body))["id"]
    assert (await _command(site, command_id)).alert_id == alert.id
    page = (await (await site.admin()).get(f"/alerts/{alert.id}")).text
    assert "Sent from here" in page and "Block peer 198.51.100.20 for 15 min" in page
    # An alert from another agent cannot be named.
    foreign = body | {"alert_id": str(uuid.uuid4())}
    assert (await _send(site, foreign)).status_code == 404


async def test_cancelling_after_delivery_loses_cleanly(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    browser = await site.admin()
    async with site.manager.database.session() as session:
        command = await commands.get(session, uuid.UUID(command_id))
        assert command is not None
        # The agent claims it between the page loading and the cancel landing.
        await commands.take(session, agent_id=command.agent_id, now=utcnow())
    refused = await browser.send("DELETE", f"/agents/{site.agent_id}/commands/{command_id}")
    assert refused.status_code == 400
    assert (await _command(site, command_id)).status == CommandStatus.DELIVERED.value


async def test_a_result_is_never_overwritten_by_a_redelivery(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    await _poll(site)
    async with site.manager.database.session() as session:
        command = await session.get(AgentCommand, uuid.UUID(command_id))
        assert command is not None
        command.delivered_at = utcnow() - commands.REDELIVER_AFTER - timedelta(seconds=1)
    await _report(site, command_id, {"status": "done"})
    assert (await _poll(site)).status_code == 204
    assert (await _command(site, command_id)).status == "done"


async def test_a_rotated_token_stops_a_waiting_poll(site: Site) -> None:
    browser = await site.admin()

    async def rotate_then_queue() -> None:
        await asyncio.sleep(0.3)
        await browser.post(f"/agents/{site.agent_id}/rotate")
        await browser.post(f"/agents/{site.agent_id}/commands", {"action": "refresh_policy"})

    polled, _ = await asyncio.gather(_poll(site, wait=10), rotate_then_queue())
    assert polled.status_code == 401


async def test_waiting_polls_per_agent_are_capped(site: Site) -> None:
    waiting = [asyncio.create_task(_poll(site, wait=2)) for _ in range(commands.MAX_WAITERS_PER_AGENT)]
    await asyncio.sleep(0.3)
    extra = await _poll(site, wait=2)
    assert extra.status_code == 429
    assert {response.status_code for response in await asyncio.gather(*waiting)} == {204}


@pytest.mark.parametrize("wait", ["²", "1" * 5000, "-3", "abc"])
async def test_odd_wait_values_are_treated_as_no_wait(site: Site, wait: str) -> None:
    response = await site.agent_client().arequest(
        "GET", f"/api/v1/commands?wait={wait}", headers={"authorization": f"Bearer {site.agent_token}"}
    )
    assert response.status_code == 204


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"action": "freeze_cgroup", "target": "²", "duration": "1h"}, "cgroup ID"),
        ({"action": "block_peer", "target": "fe80::1%eth0", "duration": "1h"}, "zone"),
        ({"action": "block_peer", "target": "fe80::1%" + "x" * 300, "duration": "1h"}, "limited"),
    ],
)
async def test_odd_targets_are_refused_cleanly(site: Site, body: dict[str, object], message: str) -> None:
    response = await _send(site, body)
    assert response.status_code == 400 and message in response.text


async def test_every_cancellable_command_is_listed(site: Site) -> None:
    browser = await site.admin()
    path = f"/agents/{site.agent_id}/commands"
    for _ in range(25):
        assert (await browser.post(path, {"action": "refresh_policy"})).status_code == 201
    page = (await browser.get(f"/agents/{site.agent_id}")).text
    assert page.count('data-testid="command-row"') == 25
    assert page.count('data-method="DELETE" data-then="reload">Cancel</button>') == 25


async def test_a_claim_loses_to_a_rotation_that_commits_first(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    async with site.manager.database.session() as session:
        command = await session.get(AgentCommand, uuid.UUID(command_id))
        assert command is not None
        claimed = await commands.take(session, agent_id=command.agent_id, now=utcnow(), token_hash="not-the-current-token")
    assert claimed == []
    assert (await _command(site, command_id)).status == CommandStatus.QUEUED.value


async def test_a_result_for_a_command_never_delivered_is_ignored(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    assert (await _report(site, command_id, {"status": "done"})).status_code == 204
    assert (await _command(site, command_id)).status == CommandStatus.QUEUED.value


async def test_a_head_request_never_claims_commands(site: Site) -> None:
    command_id = data(await _send(site, {"action": "refresh_policy"}))["id"]
    response = await site.agent_client().arequest(
        "HEAD", "/api/v1/commands?wait=0", headers={"authorization": f"Bearer {site.agent_token}"}
    )
    assert response.status_code == 204
    assert (await _command(site, command_id)).status == CommandStatus.QUEUED.value


async def test_a_failed_body_read_releases_the_poll_slot(site: Site) -> None:
    async def disconnected_poll() -> int:
        sent: list[dict[str, object]] = []

        async def receive() -> dict[str, object]:
            return {"type": "http.disconnect"}

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/commands",
            "raw_path": b"/api/v1/commands",
            "query_string": b"wait=25",
            "headers": [(b"host", b"localhost"), (b"authorization", f"Bearer {site.agent_token}".encode())],
            "scheme": "http",
            "server": ("localhost", 80),
            "client": ("127.0.0.1", 1234),
            "http_version": "1.1",
            "root_path": "",
        }
        await site.manager.api(scope, receive, send)
        start = next(message for message in sent if message["type"] == "http.response.start")
        return int(start["status"])  # ty: ignore[invalid-argument-type]

    for _ in range(commands.MAX_WAITERS_PER_AGENT + 2):
        assert await disconnected_poll() != 429
    # A normal poll still gets a slot.
    assert (await _poll(site)).status_code == 204
