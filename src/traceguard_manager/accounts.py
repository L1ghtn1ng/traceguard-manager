"""Dashboard users, sign-in, and server-side sessions."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import security, totp
from .config import Config
from .errors import DomainError
from .models import Role, User, UserSession, utcnow

# Writing last_seen on every request would turn each page view into a write.
_TOUCH_INTERVAL = timedelta(seconds=60)

ROLE_SCOPES: dict[str, frozenset[str]] = {
    Role.VIEWER.value: frozenset({"alerts:read", "agents:read"}),
    Role.ANALYST.value: frozenset({"alerts:read", "agents:read", "alerts:write"}),
    Role.ADMIN.value: frozenset(
        {"alerts:read", "agents:read", "alerts:write", "agents:write", "users:manage", "audit:read", "notify:manage"}
    ),
}


class AccountError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


@dataclass(frozen=True, slots=True)
class LoginResult:
    user: User | None
    # "ok", "invalid", "locked", "mfa_required" or "mfa_invalid"; never shown to the client verbatim
    reason: str


def normalise_username(username: str) -> str:
    return username.strip().lower()


async def create_user(session: AsyncSession, *, username: str, password: str, role: str, must_change: bool = False) -> User:
    username = normalise_username(username)
    if not security.USERNAME_RE.fullmatch(username):
        raise AccountError("Username must be 3-64 characters: lowercase letters, digits, dot, dash or underscore.")
    if role not in ROLE_SCOPES:
        raise AccountError("Unknown role.")
    try:
        security.check_password_policy(password, username=username)
    except security.PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    if await session.scalar(select(User.id).where(User.username == username)) is not None:
        raise AccountError("That username is already in use.")
    user = User(
        username=username,
        password_hash=await security.hash_password(password),
        role=role,
        must_change_password=must_change,
        recovery_codes=[],
    )
    session.add(user)
    await session.flush()
    return user


def _count_failure(user: User, config: Config, *, now: datetime) -> bool:
    """Record a failed attempt. Returns True when it locked the account."""
    user.failed_logins += 1
    if user.failed_logins >= config.login_max_failures:
        user.locked_until = now + timedelta(seconds=config.login_lockout_seconds)
        user.failed_logins = 0
        return True
    return False


def _second_factor_ok(user: User, code: str, *, now: datetime) -> bool:
    """Accept a current authenticator code, or spend one recovery code."""
    if user.totp_secret is None:
        return False
    step = totp.verify(user.totp_secret, code, timestamp=now.timestamp(), last_step=user.totp_last_step)
    if step is not None:
        user.totp_last_step = step
        return True
    digest = totp.hash_recovery_code(code)
    if digest in user.recovery_codes:
        # Reassign rather than mutate, so the change to the JSON column is noticed.
        user.recovery_codes = [item for item in user.recovery_codes if item != digest]
        return True
    return False


async def authenticate(
    session: AsyncSession, config: Config, *, username: str, password: str, code: str | None = None
) -> LoginResult:
    """Check credentials with per-account lockout.

    The password is always verified, including for unknown or locked accounts,
    so response time does not reveal which usernames exist. A wrong second
    factor counts towards the lockout exactly as a wrong password does.
    """
    now = utcnow()
    user = await session.scalar(select(User).where(User.username == normalise_username(username)).with_for_update())
    if user is None or not user.is_active:
        await security.verify_password(None, password)
        return LoginResult(None, "invalid")
    if user.locked_until is not None and user.locked_until > now:
        await security.verify_password(None, password)
        return LoginResult(None, "locked")

    if not await security.verify_password(user.password_hash, password):
        return LoginResult(None, "locked" if _count_failure(user, config, now=now) else "invalid")
    if user.totp_enabled_at is not None:
        if not code:
            return LoginResult(None, "mfa_required")
        if not _second_factor_ok(user, code, now=now):
            return LoginResult(None, "locked" if _count_failure(user, config, now=now) else "mfa_invalid")

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if security.password_needs_rehash(user.password_hash):
        user.password_hash = await security.hash_password(password)
    return LoginResult(user, "ok")


async def start_session(
    session: AsyncSession, config: Config, *, user: User, client_ip: str | None, user_agent: str | None = None
) -> str:
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
            user_agent=_printable(user_agent, 200),
        )
    )
    return token


def _printable(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    return "".join(char if char.isprintable() else "?" for char in value)[:limit]


async def resolve_session(session: AsyncSession, config: Config, token: str, *, touch: bool = True) -> User | None:
    """Return the user for a live session, enforcing idle and absolute timeouts.

    ``touch`` is False for requests the page makes by itself (the live stream,
    background refreshes). Only things the person does count as activity, so
    an unattended tab still reaches the idle timeout.
    """
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
    if touch and now - user_session.last_seen_at >= _TOUCH_INTERVAL:
        user_session.last_seen_at = now
    return user


async def list_sessions(session: AsyncSession, config: Config, user_id: uuid.UUID, *, now: datetime) -> list[UserSession]:
    """A user's live sessions, most recently used first."""
    idle_cutoff = now - timedelta(seconds=config.session_idle_seconds)
    return list(
        await session.scalars(
            select(UserSession)
            .where(UserSession.user_id == user_id, UserSession.expires_at > now, UserSession.last_seen_at > idle_cutoff)
            .order_by(UserSession.last_seen_at.desc())
        )
    )


async def end_session_by_id(session: AsyncSession, *, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
    """End one of a user's own sessions. The owner check stops anyone ending someone else's."""
    result = await session.execute(delete(UserSession).where(UserSession.id == session_id, UserSession.user_id == user_id))
    return bool(getattr(result, "rowcount", 0))


async def end_session(session: AsyncSession, token: str) -> None:
    await session.execute(delete(UserSession).where(UserSession.token_hash == security.hash_token(token)))


async def end_all_sessions(session: AsyncSession, user_id: uuid.UUID, *, keep_token: str | None = None) -> None:
    statement = delete(UserSession).where(UserSession.user_id == user_id)
    if keep_token is not None:
        statement = statement.where(UserSession.token_hash != security.hash_token(keep_token))
    await session.execute(statement)


async def purge_expired_sessions(session: AsyncSession, config: Config, *, now: datetime) -> None:
    idle_cutoff = now - timedelta(seconds=config.session_idle_seconds)
    await session.execute(delete(UserSession).where((UserSession.expires_at <= now) | (UserSession.last_seen_at <= idle_cutoff)))


async def change_password(session: AsyncSession, *, user: User, new_password: str, by_admin: bool = False) -> None:
    """Set a new password. One chosen by an administrator must be replaced at the next sign-in."""
    try:
        security.check_password_policy(new_password, username=user.username)
    except security.PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    user.password_hash = await security.hash_password(new_password)
    user.password_changed_at = utcnow()
    user.failed_logins = 0
    user.locked_until = None
    user.must_change_password = by_admin
    session.add(user)


def unlock(user: User) -> None:
    user.failed_logins = 0
    user.locked_until = None


def is_locked(user: User, *, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


async def delete_user(session: AsyncSession, *, user: User, acting_user_id: uuid.UUID) -> None:
    """Remove an account and its sessions. Audit entries keep the username as text."""
    if user.id == acting_user_id:
        raise AccountError("You cannot delete your own account.")
    if user.role == Role.ADMIN.value and user.is_active and await _other_active_admins(session, user.id) == 0:
        raise AccountError("At least one active administrator is required.")
    await session.delete(user)


def begin_totp(user: User) -> str:
    """Start two-step setup. Nothing is enforced until a code from the app confirms it."""
    if user.totp_enabled_at is not None:
        raise AccountError("Two-step sign-in is already on.")
    secret = totp.new_secret()
    user.totp_secret = secret
    user.totp_last_step = None
    return secret


def confirm_totp(user: User, code: str, *, now: datetime) -> list[str]:
    """Turn two-step sign-in on and return the recovery codes, which are shown once."""
    if user.totp_enabled_at is not None:
        raise AccountError("Two-step sign-in is already on.")
    if user.totp_secret is None:
        raise AccountError("Start the setup again.")
    step = totp.verify(user.totp_secret, code, timestamp=now.timestamp(), last_step=None)
    if step is None:
        raise AccountError("That code is not right. Check the time on your phone and try the next code.")
    codes = totp.new_recovery_codes()
    user.totp_enabled_at = now
    user.totp_last_step = step
    user.recovery_codes = [totp.hash_recovery_code(item) for item in codes]
    return codes


def disable_totp(user: User) -> None:
    user.totp_secret = None
    user.totp_enabled_at = None
    user.totp_last_step = None
    user.recovery_codes = []


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
    loses_admin = user.role == Role.ADMIN.value and user.is_active and (new_role != Role.ADMIN.value or not new_active)
    if loses_admin and await _other_active_admins(session, user.id) == 0:
        raise AccountError("At least one active administrator is required.")
    user.role = new_role
    user.is_active = new_active
    if not new_active or role is not None:
        # Permissions changed: force a fresh sign-in so old sessions cannot keep the old role.
        await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
