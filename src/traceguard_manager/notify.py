"""Outbound notifications for new alerts: signed webhooks, chat webhooks and email.

Each new alert is claimed exactly once across all worker processes, then sent
to every enabled channel whose severity threshold it meets. Delivery is
best-effort with a few retries; the outcome is recorded on the channel so a
broken destination is visible in the dashboard.
"""

import asyncio
import hashlib
import hmac
import http.client
import json
import logging
import re
import secrets
import smtplib
import socket
import ssl
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlsplit

from flasgo.ssrf import SSRFConfig, SSRFGuard, SSRFResolvedURL, SSRFViolation
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from . import __version__
from .alerts import LEVELS, level_for_severity, min_rank_for_level
from .config import Config
from .db import Database
from .errors import DomainError
from .models import Alert, AlertStatus, ChannelKind, NotificationChannel, utcnow
from .signals import ChangeSignal

logger = logging.getLogger("traceguard_manager.notify")

POLL_SECONDS = 5.0
# After a pass that sent something, wait this long before the next, so a burst
# of batches (or an agent flooding alerts) becomes one digest per channel, not
# one message per batch. Nothing is lost: the next pass picks up the rest.
MIN_PASS_SECONDS = 10.0
CLAIM_LIMIT = 200
# Alerts older than this are never announced, so enabling a channel does not replay history.
CLAIM_WINDOW = timedelta(hours=1)
SEND_TIMEOUT_SECONDS = 10
ATTEMPTS = 3
MAX_LISTED = 10
MAX_URL_LENGTH = 2_000
MAX_RECIPIENTS = 20
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}")


class NotifyError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


class DeliveryError(Exception):
    """A destination refused or could not be reached. The message is safe to store and show."""


@dataclass(frozen=True, slots=True)
class Summary:
    """What a notification says about one alert. Plain data, so sending needs no database session."""

    id: str
    title: str
    severity: str
    level: str
    rank: int
    kind: str
    rule_id: str | None
    hostname: str
    occurred_at: str
    url: str | None

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "level": self.level,
            "kind": self.kind,
            "rule_id": self.rule_id,
            "hostname": self.hostname,
            "occurred_at": self.occurred_at,
            "url": self.url,
        }


@dataclass(frozen=True, slots=True)
class Destination:
    id: uuid.UUID
    name: str
    kind: str
    target: str
    secret: str | None
    min_rank: int


class Transport(Protocol):
    """How bytes leave the process. Tests swap this for a recorder."""

    async def post(self, url: str, body: bytes, headers: dict[str, str]) -> None: ...

    async def email(self, recipients: list[str], subject: str, body: str) -> None: ...


# ---- channel management ---------------------------------------------------


def _check_url(target: str) -> str:
    target = target.strip()
    if len(target) > MAX_URL_LENGTH:
        raise NotifyError("That URL is too long.")
    try:
        parsed = urlsplit(target)
    except ValueError:
        raise NotifyError("That is not a valid URL.") from None
    if parsed.scheme != "https" or not parsed.hostname:
        raise NotifyError("Notifications are only sent to https:// URLs.")
    if parsed.username or parsed.password:
        raise NotifyError("Put credentials in the path or query, not before the host name.")
    return target


def parse_recipients(target: str) -> list[str]:
    recipients = [item for item in re.split(r"[,;\s]+", target.strip()) if item]
    if not recipients:
        raise NotifyError("Enter at least one email address.")
    if len(recipients) > MAX_RECIPIENTS:
        raise NotifyError(f"A channel can have at most {MAX_RECIPIENTS} recipients.")
    for recipient in recipients:
        if not _EMAIL_RE.fullmatch(recipient):
            raise NotifyError("One of those is not a valid email address.")
    return recipients


def display_target(channel: NotificationChannel) -> str:
    """What a page may show. A webhook URL is a credential, so only its host is shown."""
    if channel.kind == ChannelKind.EMAIL.value:
        return channel.target
    return urlsplit(channel.target).hostname or "unknown host"


async def list_channels(session: AsyncSession) -> list[NotificationChannel]:
    return list(await session.scalars(select(NotificationChannel).order_by(NotificationChannel.name)))


async def get_channel(session: AsyncSession, channel_id: uuid.UUID) -> NotificationChannel | None:
    return await session.get(NotificationChannel, channel_id)


async def create_channel(
    session: AsyncSession, config: Config, *, name: str, kind: str, target: str, min_level: str, actor: str
) -> NotificationChannel:
    name = name.strip()
    if not 1 <= len(name) <= 100:
        raise NotifyError("Give the channel a name of up to 100 characters.")
    if kind not in set(ChannelKind):
        raise NotifyError("Unknown channel type.")
    if min_level not in LEVELS:
        raise NotifyError("Unknown severity.")
    if kind == ChannelKind.EMAIL.value:
        if not config.smtp_host:
            raise NotifyError("Email is not configured. Set TGM_SMTP_HOST and TGM_SMTP_FROM, then restart the manager.")
        target = ", ".join(parse_recipients(target))
    else:
        target = _check_url(target)
    if await session.scalar(select(NotificationChannel.id).where(NotificationChannel.name == name)) is not None:
        raise NotifyError("A channel with that name already exists.")
    channel = NotificationChannel(
        name=name,
        kind=kind,
        target=target,
        # The receiver checks this to know a webhook really came from this manager.
        secret=secrets.token_urlsafe(32) if kind == ChannelKind.WEBHOOK.value else None,
        min_level=min_level,
        created_by=actor,
    )
    session.add(channel)
    await session.flush()
    return channel


def update_channel(channel: NotificationChannel, *, enabled: bool | None, min_level: str | None) -> None:
    if min_level is not None:
        if min_level not in LEVELS:
            raise NotifyError("Unknown severity.")
        channel.min_level = min_level
    if enabled is not None:
        channel.enabled = enabled


def _destination(channel: NotificationChannel) -> Destination:
    return Destination(
        id=channel.id,
        name=channel.name,
        kind=channel.kind,
        target=channel.target,
        secret=channel.secret,
        min_rank=min_rank_for_level(channel.min_level),
    )


# ---- what gets sent -------------------------------------------------------


def summarise(alert: Alert, config: Config) -> Summary:
    return Summary(
        id=str(alert.id),
        title=_one_line(alert.title, 300),
        severity=alert.severity,
        level=level_for_severity(alert.severity),
        rank=alert.severity_rank,
        kind=alert.kind,
        rule_id=alert.rule_id,
        hostname=_one_line(alert.hostname, 255),
        occurred_at=alert.occurred_at.isoformat(),
        url=f"{config.public_url}/alerts/{alert.id}" if config.public_url else None,
    )


def _one_line(text: str, limit: int) -> str:
    """Agents choose these strings; keep them to one printable line wherever they end up."""
    return " ".join("".join(char if char.isprintable() else " " for char in text).split())[:limit]


def _headline(summaries: Sequence[Summary]) -> str:
    if len(summaries) == 1:
        only = summaries[0]
        return f"{only.severity}: {only.title} on {only.hostname}"
    critical = sum(1 for item in summaries if item.level == "critical")
    return f"{len(summaries)} new alerts" + (f" ({critical} critical)" if critical else "")


def webhook_request(summaries: Sequence[Summary], *, secret: str, now: datetime, config: Config) -> tuple[bytes, dict[str, str]]:
    """The body and headers of a signed webhook.

    The signature covers the timestamp and the exact body bytes, so a receiver
    can reject both forged and replayed deliveries.
    """
    body = json.dumps(
        {
            "version": 1,
            "sent_at": now.isoformat(),
            "manager_url": config.public_url,
            "alerts": [item.as_json() for item in summaries],
        },
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(now.timestamp()))
    signature = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {
        "content-type": "application/json",
        "x-traceguard-timestamp": timestamp,
        "x-traceguard-signature": f"sha256={signature}",
    }


def _chat_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def chat_request(summaries: Sequence[Summary]) -> tuple[bytes, dict[str, str]]:
    """An incoming-webhook message in the format Slack, Mattermost and Teams workflows accept."""
    lines = [f"*{_chat_escape(_headline(summaries))}*"] if len(summaries) > 1 else []
    for item in summaries[:MAX_LISTED]:
        line = f"`{item.severity}` {_chat_escape(item.title)} on {_chat_escape(item.hostname)}"
        lines.append(f"{line} <{item.url}|open>" if item.url else line)
    if len(summaries) > MAX_LISTED:
        lines.append(f"and {len(summaries) - MAX_LISTED} more")
    return json.dumps({"text": "\n".join(lines)}).encode(), {"content-type": "application/json"}


def email_content(summaries: Sequence[Summary]) -> tuple[str, str]:
    lines: list[str] = []
    for item in summaries[:MAX_LISTED]:
        lines.append(f"[{item.severity}] {item.title}")
        lines.append(f"  host: {item.hostname}" + (f"   rule: {item.rule_id}" if item.rule_id else ""))
        lines.append(f"  time: {item.occurred_at}")
        if item.url:
            lines.append(f"  {item.url}")
        lines.append("")
    if len(summaries) > MAX_LISTED:
        lines.append(f"and {len(summaries) - MAX_LISTED} more")
    return f"[TraceGuard] {_headline(summaries)}"[:200], "\n".join(lines)


# ---- transport ------------------------------------------------------------


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to an address that has already been vetted, while still checking the certificate by name.

    Resolving the name again at connect time would let DNS answer differently
    from when it was checked (DNS rebinding).
    """

    def __init__(self, resolved: SSRFResolvedURL, *, tls: ssl.SSLContext) -> None:
        super().__init__(resolved.hostname, resolved.port, timeout=SEND_TIMEOUT_SECONDS, context=tls)
        self._address = str(resolved.address)
        self._tls = tls

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)


def _post_pinned(resolved: SSRFResolvedURL, body: bytes, headers: dict[str, str], *, tls: ssl.SSLContext | None = None) -> None:
    """POST to a vetted address. ``tls`` exists so tests can trust their own certificate authority."""
    parsed = urlsplit(resolved.original_url)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    connection = _PinnedHTTPSConnection(resolved, tls=tls or ssl.create_default_context())
    try:
        connection.request("POST", path, body=body, headers=headers | {"user-agent": f"traceguard-manager/{__version__}"})
        response = connection.getresponse()
        response.read(1024)
        # Redirects are not followed: the new location has not been vetted.
        if not 200 <= response.status < 300:
            raise DeliveryError(f"The destination answered HTTP {response.status}.")
    except ssl.SSLError as error:
        raise DeliveryError("The destination's TLS certificate could not be verified.") from error
    except (OSError, http.client.HTTPException) as error:
        raise DeliveryError(f"Could not reach the destination ({type(error).__name__}).") from error
    finally:
        connection.close()


def _send_email(config: Config, recipients: list[str], subject: str, body: str) -> None:
    host = config.smtp_host
    if host is None or config.smtp_from is None:
        raise DeliveryError("Email is not configured on this manager.")
    message = EmailMessage()
    message["From"] = config.smtp_from
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)
    tls = ssl.create_default_context()
    try:
        if config.smtp_tls == "implicit":
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, config.smtp_port, timeout=SEND_TIMEOUT_SECONDS, context=tls)
        else:
            server = smtplib.SMTP(host, config.smtp_port, timeout=SEND_TIMEOUT_SECONDS)
        with server:
            if config.smtp_tls == "starttls":
                server.starttls(context=tls)
            if config.smtp_username:
                server.login(config.smtp_username, config.smtp_password)
            server.send_message(message)
    except smtplib.SMTPAuthenticationError as error:
        raise DeliveryError("The mail server rejected the username or password.") from error
    except (OSError, smtplib.SMTPException) as error:
        raise DeliveryError(f"Could not send through the mail server ({type(error).__name__}).") from error


class NetworkTransport:
    """Real delivery: HTTPS to vetted addresses, and SMTP as configured."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._guard = SSRFGuard(
            SSRFConfig(allowed_schemes=frozenset({"https"}), allow_private_networks=config.notify_allow_private_networks)
        )

    async def post(self, url: str, body: bytes, headers: dict[str, str]) -> None:
        try:
            resolved = await self._guard.aresolve_url(url)
        except SSRFViolation as error:
            # The reason names an internal address at most; it never includes the URL's path or query.
            raise DeliveryError(f"Refused to send there: {error}") from error
        if resolved.address is None:
            raise DeliveryError("The destination host name did not resolve.")
        await asyncio.to_thread(_post_pinned, resolved, body, headers)

    async def email(self, recipients: list[str], subject: str, body: str) -> None:
        if not self._config.smtp_host:
            raise DeliveryError("Email is not configured on this manager.")
        await asyncio.to_thread(_send_email, self._config, recipients, subject, body)


# ---- delivery -------------------------------------------------------------


async def _send(
    destination: Destination, summaries: Sequence[Summary], *, config: Config, transport: Transport, now: datetime
) -> None:
    match destination.kind:
        case ChannelKind.WEBHOOK.value:
            body, headers = webhook_request(summaries, secret=destination.secret or "", now=now, config=config)
            await transport.post(destination.target, body, headers)
        case ChannelKind.SLACK.value:
            body, headers = chat_request(summaries)
            await transport.post(destination.target, body, headers)
        case ChannelKind.EMAIL.value:
            subject, text = email_content(summaries)
            await transport.email(parse_recipients(destination.target), subject, text)
        case _:
            raise DeliveryError("Unknown channel type.")


async def deliver(
    destination: Destination,
    summaries: Sequence[Summary],
    *,
    config: Config,
    transport: Transport,
    attempts: int = ATTEMPTS,
    backoff_seconds: float = 1.0,
) -> str | None:
    """Send to one destination with retries. Returns None on success, or why it failed."""
    error = "Not attempted."
    for attempt in range(attempts):
        try:
            await _send(destination, summaries, config=config, transport=transport, now=utcnow())
        except DeliveryError as failure:
            error = str(failure)
            if attempt + 1 < attempts:
                await asyncio.sleep(backoff_seconds * 4**attempt)
        else:
            return None
    return error


def _floor_id(moment: datetime) -> uuid.UUID:
    """The smallest UUIDv7 a row created at ``moment`` could have, for range scans on the primary key."""
    return uuid.UUID(int=(int(moment.timestamp() * 1000) & ((1 << 48) - 1)) << 80)


async def claim_new_alerts(session: AsyncSession, *, now: datetime) -> list[Alert]:
    """Mark recent, open, unannounced alerts as taken and return them.

    The conditional update is what makes this safe with several workers: only
    one of them can flip ``notified_at`` from NULL for any given row.
    """
    candidates = list(
        await session.scalars(
            select(Alert.id)
            .where(
                Alert.id >= _floor_id(now - CLAIM_WINDOW),
                Alert.notified_at.is_(None),
                Alert.status == AlertStatus.OPEN.value,
            )
            .order_by(Alert.id)
            .limit(CLAIM_LIMIT)
        )
    )
    if not candidates:
        return []
    claimed = list(
        await session.scalars(
            update(Alert).where(Alert.id.in_(candidates), Alert.notified_at.is_(None)).values(notified_at=now).returning(Alert.id)
        )
    )
    if not claimed:
        return []
    return list(await session.scalars(select(Alert).where(Alert.id.in_(claimed)).order_by(Alert.severity_rank.desc(), Alert.id)))


async def _record(database: Database, outcomes: dict[uuid.UUID, str | None], *, now: datetime) -> None:
    async with database.session() as session:
        for channel_id, error in outcomes.items():
            values: dict[str, object] = (
                {"last_success_at": now, "last_error": None, "last_error_at": None}
                if error is None
                else {"last_error_at": now, "last_error": error[:300]}
            )
            await session.execute(update(NotificationChannel).where(NotificationChannel.id == channel_id).values(**values))


async def dispatch_once(database: Database, config: Config, *, transport: Transport) -> int:
    """Announce any new alerts. Returns how many alerts were picked up."""
    now = utcnow()
    async with database.session() as session:
        channels = await session.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True)))
        destinations = [_destination(channel) for channel in channels]
        if not destinations:
            return 0
        summaries = [summarise(alert, config) for alert in await claim_new_alerts(session, now=now)]
    if not summaries:
        return 0

    async def one(destination: Destination) -> tuple[uuid.UUID, str | None] | None:
        wanted = [item for item in summaries if item.rank >= destination.min_rank]
        if not wanted:
            return None
        error = await deliver(destination, wanted, config=config, transport=transport)
        if error:
            logger.warning("notification failed channel=%s reason=%s", destination.name, error)
        return destination.id, error

    results = await asyncio.gather(*(one(destination) for destination in destinations))
    outcomes = dict(result for result in results if result is not None)
    if outcomes:
        await _record(database, outcomes, now=utcnow())
    return len(summaries)


async def send_test(database: Database, config: Config, channel: NotificationChannel, *, transport: Transport) -> str | None:
    """Send one sample alert to a channel right now. Returns None on success, or why it failed."""
    now = utcnow()
    sample = Summary(
        id="00000000-0000-7000-8000-000000000000",
        title="Test notification from TraceGuard Manager",
        severity="notice",
        level="low",
        rank=2,
        kind="detection",
        rule_id="tg-test",
        hostname="example-host",
        occurred_at=now.isoformat(),
        url=config.public_url,
    )
    error = await deliver(_destination(channel), [sample], config=config, transport=transport, attempts=1)
    await _record(database, {channel.id: error}, now=now)
    return error


async def run(database: Database, config: Config, signal: ChangeSignal, *, transport: Transport) -> None:
    """Announce new alerts until cancelled. Wakes at once for alerts stored by this process."""
    while True:
        sent = 0
        try:
            sent = await dispatch_once(database, config, transport=transport)
        except Exception:
            # Keep the loop alive; whatever was not claimed is picked up on the next pass.
            logger.exception("notification pass failed")
        if sent:
            await asyncio.sleep(MIN_PASS_SECONDS)
        try:
            async with asyncio.timeout(POLL_SECONDS):
                await signal.wait()
        except TimeoutError:
            pass
