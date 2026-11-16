"""Dashboard users, sign-in, and server-side sessions."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import security
from .config import Config
from .errors import DomainError
from .models import Role, User, UserSession, utcnow

# Writing last_seen on every request would turn each page view into a write.
_TOUCH_INTERVAL = timedelta(seconds=60)

ROLE_SCOPES: dict[str, frozenset[str]] = {
    Role.VIEWER.value: frozenset({"alerts:read", "agents:read"}),
    Role.ANALYST.value: frozenset({"alerts:read", "agents:read", "alerts:write"}),
    Role.ADMIN.value: frozenset(
        {"alerts:read", "agents:read", "alerts:write", "agents:write", "users:manage", "audit:read"}
    ),
}


class AccountError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


@dataclass(frozen=True, slots=True)
class LoginResult:
    user: User | None
    reason: str  # "ok", "invalid", or "locked"; never shown to the client verbatim


def normalise_username(username: str) -> str:
    return username.strip().lower()


async def create_user(session: AsyncSession, *, username: str, password: str, role: str) -> User:
    username = normalise_username(username)
    if not security.USERNAME_RE.fullmatch(username):
        raise AccountError(
            "Username must be 3-64 characters: lowercase letters, digits, dot, dash or underscore."
        )
    if role not in ROLE_SCOPES:
        raise AccountError("Unknown role.")
    try:
        security.check_password_policy(password, username=username)
    except security.PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    if await session.scalar(select(User.id).where(User.username == username)) is not None:
        raise AccountError("That username is already in use.")
    user = User(username=username, password_hash=await security.hash_password(password), role=role)
    session.add(user)
    await session.flush()
    return user


async def authenticate(session: AsyncSession, config: Config, *, username: str, password: str) -> LoginResult:
    """Check credentials with per-account lockout.

    The password is always verified, including for unknown or locked accounts,
    so response time does not reveal which usernames exist.
    """
    now = utcnow()
    user = await session.scalar(
        select(User).where(User.username == normalise_username(username)).with_for_update()
    )
    if user is None or not user.is_active:
        await security.verify_password(None, password)
        return LoginResult(None, "invalid")
    if user.locked_until is not None and user.locked_until > now:
        await security.verify_password(None, password)
        return LoginResult(None, "locked")

    if not await security.verify_password(user.password_hash, password):
        user.failed_logins += 1
        if user.failed_logins >= config.login_max_failures:
            user.locked_until = now + timedelta(seconds=config.login_lockout_seconds)
            user.failed_logins = 0
            return LoginResult(None, "locked")
        return LoginResult(None, "invalid")

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if security.password_needs_rehash(user.password_hash):
        user.password_hash = await security.hash_password(password)
    return LoginResult(user, "ok")


async def start_session(session: AsyncSession, config: Config, *, user: User, client_ip: str | None) -> str:
    """Create a session and return its token. The token itself is never stored."""
    token = security.new_session_token()
    now = utcnow()
    session.add(
        UserSession(
            token_hash=security.hash_token(token),
            user_id=user.id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=config.session_absolute_seconds),
            client_ip=client_ip,
        )
    )
    return token


async def resolve_session(session: AsyncSession, config: Config, token: str) -> User | None:
    """Return the user for a live session, enforcing idle and absolute timeouts."""
    row = (
        await session.execute(
            select(UserSession, User)
            .join(User, User.id == UserSession.user_id)
            .where(UserSession.token_hash == security.hash_token(token))
        )
    ).first()
    if row is None:
        return None
    user_session, user = row
    now = utcnow()
    idle_deadline = user_session.last_seen_at + timedelta(seconds=config.session_idle_seconds)
    if not user.is_active or now >= user_session.expires_at or now >= idle_deadline:
        await session.delete(user_session)
        return None
    if now - user_session.last_seen_at >= _TOUCH_INTERVAL:
        user_session.last_seen_at = now
    return user


async def end_session(session: AsyncSession, token: str) -> None:
    await session.execute(delete(UserSession).where(UserSession.token_hash == security.hash_token(token)))


async def end_all_sessions(
    session: AsyncSession, user_id: uuid.UUID, *, keep_token: str | None = None
) -> None:
    statement = delete(UserSession).where(UserSession.user_id == user_id)
    if keep_token is not None:
        statement = statement.where(UserSession.token_hash != security.hash_token(keep_token))
    await session.execute(statement)


async def purge_expired_sessions(session: AsyncSession, config: Config, *, now: datetime) -> None:
    idle_cutoff = now - timedelta(seconds=config.session_idle_seconds)
    await session.execute(
        delete(UserSession).where((UserSession.expires_at <= now) | (UserSession.last_seen_at <= idle_cutoff))
    )


async def change_password(session: AsyncSession, *, user: User, new_password: str) -> None:
    try:
        security.check_password_policy(new_password, username=user.username)
    except security.PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    user.password_hash = await security.hash_password(new_password)
    user.password_changed_at = utcnow()
    user.failed_logins = 0
    user.locked_until = None
    session.add(user)


async def get_user(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.get(User, user_id)


async def list_users(session: AsyncSession) -> list[User]:
    return list(await session.scalars(select(User).order_by(User.username)))


async def _other_active_admins(session: AsyncSession, user_id: uuid.UUID) -> int:
    return (
        await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN.value, User.is_active.is_(True), User.id != user_id)
        )
        or 0
    )


async def update_user(session: AsyncSession, *, user: User, role: str | None, is_active: bool | None) -> None:
    """Change a role or activation state without ever leaving zero active admins."""
    if role is not None and role not in ROLE_SCOPES:
        raise AccountError("Unknown role.")
    new_role = user.role if role is None else role
    new_active = user.is_active if is_active is None else is_active
    loses_admin = (
        user.role == Role.ADMIN.value and user.is_active and (new_role != Role.ADMIN.value or not new_active)
    )
    if loses_admin and await _other_active_admins(session, user.id) == 0:
        raise AccountError("At least one active administrator is required.")
    user.role = new_role
    user.is_active = new_active
    if not new_active or role is not None:
        # Permissions changed: force a fresh sign-in so old sessions cannot keep the old role.
        await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
