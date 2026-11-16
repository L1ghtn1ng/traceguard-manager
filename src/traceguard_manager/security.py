"""Password hashing, token generation, and input rules for credentials."""

import asyncio
import hashlib
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2-cffi defaults follow RFC 9106's low-memory profile (Argon2id, 64 MiB, t=3, p=4).
_hasher = PasswordHasher()
# Verified against when the user does not exist, so both paths cost the same.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

AGENT_TOKEN_PREFIX = "tgm_"  # noqa: S105 - a public prefix, not a credential
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
AGENT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")

_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "administrator",
        "adminadminadmin",
        "changemechangeme",
        "correcthorsebatterystaple",
        "letmeinletmein",
        "password1234",
        "password12345",
        "passwordpassword",
        "qwertyuiop123",
        "qwertyuiopasdf",
        "traceguard123",
        "traceguardmanager",
        "welcome12345",
    }
)


class PasswordPolicyError(ValueError):
    """The proposed password does not meet the policy."""


def check_password_policy(password: str, *, username: str) -> None:
    """Length-based policy in the spirit of NIST SP 800-63B: no composition rules."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters.")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(lowered)) < 5:
        raise PasswordPolicyError("Password is too common or too repetitive.")
    if username and username.lower() in lowered:
        raise PasswordPolicyError("Password must not contain the username.")


async def hash_password(password: str) -> str:
    """Hash off the event loop; Argon2 is deliberately expensive."""
    return await asyncio.to_thread(_hasher.hash, password)


def _verify(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError, InvalidHashError:
        return False


async def verify_password(password_hash: str | None, password: str) -> bool:
    """Check a password. A missing hash still performs a full verification."""
    if len(password) > PASSWORD_MAX_LENGTH:
        password = password[:PASSWORD_MAX_LENGTH] + "\x00"  # bounded work, can never match
    if password_hash is None:
        await asyncio.to_thread(_verify, _DUMMY_HASH, password)
        return False
    return await asyncio.to_thread(_verify, password_hash, password)


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def hash_token(token: str) -> str:
    """Hash a high-entropy random token for storage and lookup.

    Tokens carry 256 bits of randomness, so a fast digest is appropriate here;
    slow password hashing is reserved for human-chosen secrets.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def new_agent_token() -> str:
    return AGENT_TOKEN_PREFIX + secrets.token_urlsafe(32)


def token_display_prefix(token: str) -> str:
    """The first characters of a token, kept so operators can tell tokens apart."""
    return token[: len(AGENT_TOKEN_PREFIX) + 6]
