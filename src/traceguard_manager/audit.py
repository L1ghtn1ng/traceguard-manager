"""Security audit trail: one database row and one log line per action."""

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent

logger = logging.getLogger("traceguard_manager.audit")

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


async def recent(session: AsyncSession, *, limit: int, offset: int) -> tuple[list[AuditEvent], int]:
    total = await session.scalar(select(func.count()).select_from(AuditEvent)) or 0
    rows = await session.scalars(
        select(AuditEvent).order_by(AuditEvent.at.desc(), AuditEvent.id.desc()).limit(limit).offset(offset)
    )
    return list(rows), total
