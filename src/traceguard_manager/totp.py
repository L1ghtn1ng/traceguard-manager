"""Time-based one-time passwords (RFC 6238) and recovery codes for two-step sign-in."""

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
# One step either side allows for clock drift between the phone and the server.
DRIFT_STEPS = 1
ISSUER = "TraceGuard Manager"
RECOVERY_CODE_COUNT = 10


def new_secret() -> str:
    """A 160-bit secret, base32 encoded as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def step_at(timestamp: float) -> int:
    return int(timestamp) // STEP_SECONDS


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    # SHA-1 is what RFC 6238 specifies and what every authenticator app implements; HMAC-SHA1 is not broken.
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, *, timestamp: float, last_step: int | None) -> int | None:
    """Return the time step a code matches, or None.

    A step at or before ``last_step`` is refused, so a code that has been used
    once cannot be used again while it is still inside its window.
    """
    cleaned = code.replace(" ", "")
    if len(cleaned) != DIGITS or not cleaned.isdigit():
        return None
    current = step_at(timestamp)
    matched: int | None = None
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        # Compare every candidate so timing does not reveal which step matched.
        if hmac.compare_digest(code_at(secret, step), cleaned) and (last_step is None or step > last_step):
            matched = step
    return matched


def provisioning_uri(secret: str, username: str) -> str:
    """The otpauth:// address an authenticator app reads from a QR code."""
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?" + urlencode({"secret": secret, "issuer": ISSUER, "digits": DIGITS, "period": STEP_SECONDS})


def new_recovery_codes() -> list[str]:
    """One-time codes for when the phone is lost. 60 bits each, grouped for reading aloud."""
    codes: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(8)[:15]
        codes.append("-".join(raw[index : index + 5] for index in range(0, 15, 5)))
    return codes


def normalise_recovery_code(code: str) -> str:
    return code.strip().lower().replace(" ", "")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalise_recovery_code(code).encode()).hexdigest()
