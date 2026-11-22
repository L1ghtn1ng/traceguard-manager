"""Notification channels: what is sent, to whom, once, and never to somewhere it should not go."""

import hashlib
import hmac
import http.server
import ipaddress
import json
import ssl
import subprocess
import threading
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from flasgo.ssrf import SSRFConfig, SSRFGuard
from sqlalchemy import select, update

from traceguard_manager import notify
from traceguard_manager.config import Config, ConfigError
from traceguard_manager.models import Alert, AuditEvent, NotificationChannel, utcnow

from .conftest import Site
from .helpers import data, detection

HOOK = "https://hooks.example.com/services/T000/secret-path"
KEY = "k" * 48


async def _add_channel(site: Site, **overrides: str) -> dict[str, object]:
    body = {"name": "Pager", "kind": "webhook", "target": HOOK, "min_level": "high"} | overrides
    response = await (await site.admin()).post("/notifications", body)
    assert response.status_code == 201, response.text
    return data(response)


async def test_signed_webhook_carries_new_alerts_once(site: Site) -> None:
    created = await _add_channel(site)
    secret = created["secret"]
    assert isinstance(secret, str) and len(secret) >= 32

    await site.ingest([detection("A", detection_message="Reverse shell", severity="critical")])
    assert await site.dispatch() == 1
    ((url, body, headers),) = site.transport.posts
    assert url == HOOK
    payload = json.loads(body)
    assert payload["version"] == 1
    assert [alert["title"] for alert in payload["alerts"]] == ["Reverse shell"]
    assert payload["alerts"][0]["level"] == "critical"

    # A receiver can check the delivery is genuine and recent from the two headers alone.
    signed = f"{headers['x-traceguard-timestamp']}.".encode() + body
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    assert headers["x-traceguard-signature"] == f"sha256={expected}"

    assert await site.dispatch() == 0  # already announced
    assert len(site.transport.posts) == 1


async def test_only_alerts_at_or_above_the_channel_severity_are_sent(site: Site) -> None:
    await _add_channel(site, min_level="high")
    await site.ingest(
        [
            detection("A", detection_message="Low noise", severity="notice"),
            detection("B", detection_message="Medium", severity="warning"),
            detection("C", detection_message="High", severity="error"),
        ]
    )
    await site.dispatch()
    ((_, body, _),) = site.transport.posts
    assert [alert["title"] for alert in json.loads(body)["alerts"]] == ["High"]


async def test_muted_resolved_and_old_alerts_are_not_announced(site: Site) -> None:
    await _add_channel(site, min_level="low")
    analyst = await site.analyst()
    assert (await analyst.post("/mutes", {"rule_id": "tg-muted", "reason": "Known", "duration": "1h"})).status_code == 201
    await site.ingest(
        [
            detection("A", detection_message="Muted", detection_rule_id="tg-muted"),
            detection("B", detection_message="Stale"),
            detection("C", detection_message="Fresh"),
        ]
    )
    async with site.manager.database.session() as session:
        # Give one alert an identifier from two hours ago, as if it had been stored then.
        stale = notify._floor_id(utcnow() - timedelta(hours=2))
        await session.execute(update(Alert).where(Alert.title == "Stale").values(id=stale))
    await site.dispatch()
    ((_, body, _),) = site.transport.posts
    assert [alert["title"] for alert in json.loads(body)["alerts"]] == ["Fresh"]


async def test_nothing_is_claimed_until_a_channel_exists(site: Site) -> None:
    await site.ingest([detection("A", detection_message="Before any channel")])
    assert await site.dispatch() == 0
    await _add_channel(site, min_level="low")
    # Still inside the announcement window, so the new channel hears about it.
    assert await site.dispatch() == 1


async def test_failures_are_recorded_on_the_channel_and_cleared_by_success(site: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    await _add_channel(site, min_level="low")
    monkeypatch.setattr(notify, "ATTEMPTS", 1)
    site.transport.fail_with = "The destination answered HTTP 500."
    await site.ingest([detection("A")])
    await site.dispatch()
    admin = await site.admin()
    page = (await admin.get("/notifications")).text
    assert "failed" in page and "The destination answered HTTP 500." in page

    site.transport.fail_with = None
    await site.ingest([detection("B")])
    await site.dispatch()
    page = (await admin.get("/notifications")).text
    assert "delivered" in page and "HTTP 500" not in page


async def test_delivery_is_retried_before_giving_up(site: Site) -> None:
    attempts = 0

    class Flaky:
        async def post(self, url: str, body: bytes, headers: dict[str, str]) -> None:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise notify.DeliveryError("temporarily unavailable")

        async def email(self, recipients: list[str], subject: str, body: str) -> None:
            raise AssertionError("not an email channel")

    destination = notify.Destination(id=uuid.uuid7(), name="x", kind="slack", target=HOOK, secret=None, min_rank=0)
    summary = notify.Summary("id", "Title", "error", "high", 4, "detection", None, "host", utcnow().isoformat(), None)
    error = await notify.deliver(destination, [summary], config=site.manager.config, transport=Flaky(), backoff_seconds=0)
    assert error is None and attempts == 3


async def test_chat_webhook_text_is_escaped_and_summarised(site: Site) -> None:
    await _add_channel(site, kind="slack", min_level="low")
    await site.ingest(
        [detection("A", detection_message="<!channel> & <https://evil.example|click>", severity="critical")]
        + [detection(f"N{index}", detection_message=f"Finding {index}", severity="warning") for index in range(12)]
    )
    await site.dispatch()
    ((_, body, headers),) = site.transport.posts
    text = json.loads(body)["text"]
    assert "x-traceguard-signature" not in headers  # chat webhooks authenticate by their URL
    assert text.startswith("*13 new alerts (1 critical)*")
    assert "&lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;" in text  # cannot ping a channel or forge a link
    assert text.endswith("and 3 more")


def test_email_text_cannot_be_used_to_add_headers() -> None:
    # Titles come from agents. summarise() flattens them to one line before they reach a header.
    title = notify._one_line("Shell\r\nBcc: attacker@example.com", 300)
    summary = notify.Summary("id", title, "critical", "critical", 5, "detection", "tg-shell", "web-01", "t", None)
    subject, body = notify.email_content([summary])
    assert "\r" not in subject and "\n" not in subject  # an agent cannot add headers to the message
    assert subject == "[TraceGuard] critical: Shell Bcc: attacker@example.com on web-01"
    assert "rule: tg-shell" in body
    assert notify.parse_recipients("a@example.com; b@example.com") == ["a@example.com", "b@example.com"]
    with pytest.raises(notify.NotifyError):
        notify.parse_recipients("not-an-address")


async def test_email_channel_through_the_dashboard(site: Site) -> None:
    refused = await (await site.admin()).post("/notifications", {"name": "Mail", "kind": "email", "target": "soc@example.com"})
    assert refused.status_code == 400
    assert "TGM_SMTP_HOST" in data(refused)["error"]


def test_smtp_settings_are_validated() -> None:
    ok = Config.from_env({"TGM_SECRET_KEY": KEY, "TGM_SMTP_HOST": "smtp.example.com", "TGM_SMTP_FROM": "tg@example.com"})
    assert (ok.smtp_port, ok.smtp_tls) == (587, "starttls")
    for env in (
        {"TGM_SMTP_HOST": "smtp.example.com"},  # no sender address
        {"TGM_SMTP_HOST": "smtp.example.com", "TGM_SMTP_FROM": "tg@example.com", "TGM_SMTP_TLS": "maybe"},
        # A password must not cross the network unencrypted.
        {
            "TGM_SMTP_HOST": "smtp.example.com",
            "TGM_SMTP_FROM": "tg@example.com",
            "TGM_SMTP_TLS": "none",
            "TGM_SMTP_USERNAME": "u",
        },
        {"TGM_PUBLIC_URL": "manager.example.com"},
    ):
        with pytest.raises(ConfigError):
            Config.from_env({"TGM_SECRET_KEY": KEY} | env)
    secret = Config.from_env(
        {"TGM_SECRET_KEY": KEY, "TGM_SMTP_HOST": "h", "TGM_SMTP_FROM": "f@example.com", "TGM_SMTP_PASSWORD": "hunter2-hunter2"}
    )
    assert "hunter2" not in repr(secret)


async def test_channel_management_rules(site: Site) -> None:
    admin = await site.admin()
    for target in ("http://hooks.example.com/x", "https://user:pw@hooks.example.com/x", "ftp://hooks.example.com", "not a url"):
        assert (await admin.post("/notifications", {"name": "Bad", "kind": "webhook", "target": target})).status_code == 400, (
            target
        )
    assert (await admin.post("/notifications", {"name": "Bad", "kind": "carrier-pigeon", "target": HOOK})).status_code == 400

    created = await _add_channel(site)
    assert (
        await admin.post("/notifications", {"name": "Pager", "kind": "webhook", "target": HOOK})
    ).status_code == 400  # duplicate name
    page = (await admin.get("/notifications")).text
    assert "hooks.example.com" in page
    assert "secret-path" not in page  # a webhook URL is a credential; only the host is shown again
    assert str(created["secret"]) not in page

    channel_id = created["id"]
    assert (await admin.send("PATCH", f"/notifications/{channel_id}", {"enabled": False})).status_code == 200
    await site.ingest([detection("A", severity="critical")])
    assert await site.dispatch() == 0  # a channel that is off is not used
    assert (await admin.send("PATCH", f"/notifications/{channel_id}", {"min_level": "extreme"})).status_code == 400

    for browser in (await site.analyst(), await site.viewer()):
        assert (await browser.get("/notifications")).status_code == 403
        assert (await browser.post("/notifications", {"name": "Mine", "kind": "webhook", "target": HOOK})).status_code == 403
        assert (await browser.send("DELETE", f"/notifications/{channel_id}")).status_code == 403

    assert (await admin.send("DELETE", f"/notifications/{channel_id}")).status_code == 200
    async with site.manager.database.session() as session:
        assert (await session.scalars(select(NotificationChannel))).first() is None
        details = [event.detail for event in await session.scalars(select(AuditEvent).where(AuditEvent.action.like("channel.%")))]
    assert "secret-path" not in json.dumps(details)  # nor does the URL reach the audit log


async def test_send_test_reports_the_outcome(site: Site) -> None:
    created = await _add_channel(site)
    admin = await site.admin()
    assert (await admin.post(f"/notifications/{created['id']}/test")).status_code == 200
    ((_, body, _),) = site.transport.posts
    assert json.loads(body)["alerts"][0]["title"] == "Test notification from TraceGuard Manager"

    site.transport.fail_with = "The destination's TLS certificate could not be verified."
    failed = await admin.post(f"/notifications/{created['id']}/test")
    assert failed.status_code == 400
    assert "TLS certificate" in data(failed)["error"]


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/hook",  # the manager itself
        "https://169.254.169.254/latest/meta-data/",  # cloud instance metadata
        "https://10.0.0.5/hook",  # the private network the manager sits on
        "https://[::1]/hook",
        "https://[fd00::1]/hook",
    ],
)
async def test_real_transport_refuses_internal_addresses(config: Config, url: str) -> None:
    transport = notify.NetworkTransport(config)
    with pytest.raises(notify.DeliveryError, match="Refused to send there"):
        await transport.post(url, b"{}", {})


# ---- the pinned HTTPS connection, against a real TLS server ----------------


class _Receiver(http.server.BaseHTTPRequestHandler):
    received: list[tuple[str, bytes, str]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["content-length"]))
        type(self).received.append((self.path, body, self.headers["host"]))
        self.send_response(302 if self.path == "/redirect" else 204)
        if self.path == "/redirect":
            self.send_header("location", "https://elsewhere.example/")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def tls_receiver(tmp_path: Path) -> Iterator[tuple[int, ssl.SSLContext]]:
    """A local HTTPS server with a certificate for hooks.test, and a context that trusts it."""
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=hooks.test"]
    command += ["-addext", "subjectAltName=DNS:hooks.test", "-keyout", str(key), "-out", str(cert)]
    made = subprocess.run(command, capture_output=True, check=False)
    if made.returncode != 0:
        pytest.skip("openssl is not available to make a test certificate")
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(cert, key)
    _Receiver.received = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Receiver)
    server.socket = server_tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], ssl.create_default_context(cafile=str(cert))
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _resolved(url: str) -> notify.SSRFResolvedURL:
    # Stand in for DNS: the name "resolves" to this machine, which only a test may allow.
    guard = SSRFGuard(SSRFConfig(allowed_schemes=frozenset({"https"}), allow_unresolvable_hosts=True))
    checked = guard.resolve_url(url)
    return notify.SSRFResolvedURL(
        original_url=url,
        url=url,
        hostname=checked.hostname,
        port=checked.port,
        address=ipaddress.ip_address("127.0.0.1"),
        host_header=checked.host_header,
    )


def test_pinned_connection_delivers_and_checks_the_certificate_by_name(tls_receiver: tuple[int, ssl.SSLContext]) -> None:
    port, trusted = tls_receiver
    notify._post_pinned(
        _resolved(f"https://hooks.test:{port}/in?team=soc"), b'{"ok":true}', {"content-type": "application/json"}, tls=trusted
    )
    ((path, body, host),) = _Receiver.received
    assert (path, body) == ("/in?team=soc", b'{"ok":true}')
    assert host == f"hooks.test:{port}"  # the name, not the address it was pinned to

    # The same server under another name must fail certificate verification.
    with pytest.raises(notify.DeliveryError, match="TLS certificate"):
        notify._post_pinned(_resolved(f"https://other.test:{port}/in"), b"{}", {}, tls=trusted)
    # And without trusting the test authority, the default trust store rejects it.
    with pytest.raises(notify.DeliveryError, match="TLS certificate"):
        notify._post_pinned(_resolved(f"https://hooks.test:{port}/in"), b"{}", {})


def test_redirects_are_reported_not_followed(tls_receiver: tuple[int, ssl.SSLContext]) -> None:
    port, trusted = tls_receiver
    with pytest.raises(notify.DeliveryError, match="HTTP 302"):
        notify._post_pinned(_resolved(f"https://hooks.test:{port}/redirect"), b"{}", {}, tls=trusted)
    assert len(_Receiver.received) == 1


async def test_a_burst_of_batches_becomes_one_message_per_channel(site: Site) -> None:
    import asyncio

    from traceguard_manager.signals import ChangeSignal

    await _add_channel(site)
    signal = ChangeSignal()
    runner = asyncio.create_task(notify.run(site.manager.database, site.manager.config, signal, transport=site.transport))
    try:
        for index in range(5):
            await site.ingest([detection(f"F{index}", detection_message=f"Flood {index}", severity="critical")])
            signal.notify()
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.3)
    finally:
        runner.cancel()
    # The first batch is sent at once; the rest wait for the next pass, together.
    assert len(site.transport.posts) == 1
