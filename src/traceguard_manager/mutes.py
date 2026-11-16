"""Mute rules: silence a noisy rule, a host, or a rule on one host.

A muted alert is still stored, so nothing is lost, but it starts life in the
``muted`` status: out of the open counts, the live toasts and notifications.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import DomainError
from .models import Alert, AlertStatus, MuteRule

MAX_REASON_LENGTH = 500
# How long a mute lasts, by the value the form sends. None never expires.
DURATIONS: dict[str, timedelta | None] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "forever": None,
}
DURATION_LABELS: dict[str, str] = {
    "1h": "1 hour",
    "24h": "24 hours",
    "7d": "7 days",
    "30d": "30 days",
    "forever": "Until removed",
}


class MuteError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


def matches(rules: Sequence[MuteRule], *, rule_id: str | None, hostname: str) -> bool:
    """True when any rule covers an alert. A rule's empty side matches everything."""
    return any(
        (rule.rule_id is None or rule.rule_id == rule_id) and (rule.hostname is None or rule.hostname == hostname)
        for rule in rules
    )


async def active(session: AsyncSession, *, now: datetime) -> list[MuteRule]:
    return list(
        await session.scalars(
            select(MuteRule)
            .where(or_(MuteRule.expires_at.is_(None), MuteRule.expires_at > now))
            .order_by(MuteRule.created_at.desc())
        )
    )


async def get(session: AsyncSession, mute_id: uuid.UUID) -> MuteRule | None:
    return await session.get(MuteRule, mute_id)


async def create(
    session: AsyncSession,
    *,
    rule_id: str | None,
    hostname: str | None,
    reason: str,
    duration: str,
    actor: str,
    now: datetime,
) -> tuple[MuteRule, int]:
    """Add a mute rule and move the open alerts it covers out of the way.

    Returns the rule and how many existing alerts it muted.
    """
    rule_id = (rule_id or "").strip()[:200] or None
    hostname = (hostname or "").strip()[:255] or None
    reason = reason.strip()
    if rule_id is None and hostname is None:
        raise MuteError("Choose a rule, a host, or both to mute.")
    if not reason:
        raise MuteError("Say why this is being muted, so the next person knows.")
    if len(reason) > MAX_REASON_LENGTH:
        raise MuteError(f"Reasons are limited to {MAX_REASON_LENGTH} characters.")
    if duration not in DURATIONS:
        raise MuteError("Unknown duration.")
    length = DURATIONS[duration]
    rule = MuteRule(
        rule_id=rule_id,
        hostname=hostname,
        reason=reason,
        created_by=actor,
        created_at=now,
        expires_at=now + length if length else None,
    )
    session.add(rule)

    scope = [Alert.status == AlertStatus.OPEN.value]
    if rule_id is not None:
        scope.append(Alert.rule_id == rule_id)
    if hostname is not None:
        scope.append(Alert.hostname == hostname)
    result = await session.execute(
        update(Alert).where(*scope).values(status=AlertStatus.MUTED.value, status_changed_at=now, status_changed_by=actor)
    )
    return rule, max(getattr(result, "rowcount", 0), 0)


async def remove(session: AsyncSession, rule: MuteRule) -> None:
    await session.delete(rule)


async def purge_expired(session: AsyncSession, *, now: datetime) -> None:
    await session.execute(delete(MuteRule).where(MuteRule.expires_at.is_not(None), MuteRule.expires_at <= now))
