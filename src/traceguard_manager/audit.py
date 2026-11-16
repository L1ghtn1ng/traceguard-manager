"""Security audit trail: one database row and one log line per action."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent

logger = logging.getLogger("traceguard_manager.audit")

OUTCOMES: tuple[str, ...] = ("success", "failure", "challenge")
RANGES: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

# Keys whose values must never reach the audit trail.
_SECRET_KEYS = frozenset({"password", "new_password", "current_password", "token", "secret", "authorization"})


def _clean(value: str | None, limit: int) -> str | None:
    """Strip control characters so attacker-supplied text cannot forge log lines."""
    if value is None:
        return None
    return "".join(char if char.isprintable() else "?" for char in value)[:limit]


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    outcome: str = "success",
    client_ip: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    safe_detail = {key: value for key, value in (detail or {}).items() if key.lower() not in _SECRET_KEYS}
    event = AuditEvent(
        actor=_clean(actor, 64) or "unknown",
        action=action,
        target=_clean(target, 200),
        outcome=outcome,
        client_ip=_clean(client_ip, 64),
        request_id=_clean(request_id, 64),
        detail=safe_detail,
    )
    session.add(event)
    logger.log(
        logging.INFO if outcome == "success" else logging.WARNING,
        "audit action=%s outcome=%s actor=%s target=%s ip=%s request_id=%s",
        action,
        outcome,
        event.actor,
        event.target,
        event.client_ip,
        event.request_id,
    )


@dataclass(frozen=True, slots=True)
class AuditSearch:
    actor: str | None = None
    action: str | None = None
    outcome: str | None = None
    time_range: str | None = None

    @classmethod
    def from_params(cls, params: Mapping[str, str]) -> AuditSearch:
        def text(name: str, limit: int) -> str | None:
            return params.get(name, "").strip()[:limit] or None

        outcome, time_range = text("outcome", 16), text("range", 8)
        return cls(
            actor=text("actor", 64),
            action=text("action", 64),
            outcome=outcome if outcome in OUTCOMES else None,
            time_range=time_range if time_range in RANGES else None,
        )

    def to_query(self) -> dict[str, str]:
        values = {"actor": self.actor, "action": self.action, "outcome": self.outcome, "range": self.time_range}
        return {key: value for key, value in values.items() if value}


async def search(
    session: AsyncSession, query: AuditSearch, *, now: datetime, limit: int, offset: int
) -> tuple[list[AuditEvent], int]:
    clauses: list[ColumnElement[bool]] = []
    if query.actor:
        clauses.append(AuditEvent.actor == query.actor.lower())
    if query.action:
        clauses.append(AuditEvent.action == query.action)
    if query.outcome:
        clauses.append(AuditEvent.outcome == query.outcome)
    if query.time_range:
        clauses.append(AuditEvent.at >= now - RANGES[query.time_range])
    total = await session.scalar(select(func.count()).select_from(AuditEvent).where(*clauses)) or 0
    rows = await session.scalars(
        select(AuditEvent).where(*clauses).order_by(AuditEvent.at.desc(), AuditEvent.id.desc()).limit(limit).offset(offset)
    )
    return list(rows), total


async def known_actions(session: AsyncSession) -> list[str]:
    """Every action that appears in the log, for the filter's list."""
    return list(await session.scalars(select(AuditEvent.action).distinct().order_by(AuditEvent.action)))
