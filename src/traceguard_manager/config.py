"""Runtime configuration, loaded once from the environment."""

import difflib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Self

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_ALLOWED_DRIVERS = ("sqlite+aiosqlite://", "postgresql+asyncpg://")
MIN_SECRET_KEY_LENGTH = 32
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_PREFIX = "TGM_"
# Every variable the manager reads. Anything else starting with TGM_ is a mistake.
SETTINGS = frozenset(
    {
        "TGM_SECRET_KEY",
        "TGM_DATABASE_URL",
        "TGM_ALLOWED_HOSTS",
        "TGM_CSRF_TRUSTED_ORIGINS",
        "TGM_DEBUG",
        "TGM_SECURE_COOKIES",
        "TGM_LOG_FORMAT",
        "TGM_LOG_LEVEL",
        "TGM_SESSION_IDLE_SECONDS",
        "TGM_SESSION_ABSOLUTE_SECONDS",
        "TGM_AGENT_OFFLINE_SECONDS",
        "TGM_LOGIN_MAX_FAILURES",
        "TGM_LOGIN_LOCKOUT_SECONDS",
        "TGM_LOGIN_REQUESTS_PER_MINUTE",
        "TGM_INGEST_MAX_RECORDS",
        "TGM_INGEST_REQUESTS_PER_MINUTE",
        "TGM_ALERT_RETENTION_DAYS",
        "TGM_PUBLIC_URL",
        "TGM_NOTIFY_ALLOW_PRIVATE_NETWORKS",
        "TGM_SMTP_HOST",
        "TGM_SMTP_PORT",
        "TGM_SMTP_USERNAME",
        "TGM_SMTP_PASSWORD",
        "TGM_SMTP_FROM",
        "TGM_SMTP_TLS",
    }
)
_SMTP_TLS_MODES = frozenset({"starttls", "implicit", "none"})
# Read by the test suite, never by the manager.
_TEST_ONLY_PREFIXES = ("TGM_E2E_", "TGM_TEST_")


class ConfigError(ValueError):
    """Raised when the environment holds an unusable setting."""


def _reject_unknown(env: Mapping[str, str]) -> None:
    """Refuse a misspelt setting rather than silently running on the default.

    A typo in ``TGM_ALLOWED_HOSTS`` or ``TGM_SECURE_COOKIES`` would otherwise
    leave a weaker value in force with nothing to show for it. Only names are
    reported, never values.
    """
    unknown = sorted(
        name for name in env if name.startswith(_PREFIX) and name not in SETTINGS and not name.startswith(_TEST_ONLY_PREFIXES)
    )
    if not unknown:
        return
    parts: list[str] = []
    for name in unknown:
        close = difflib.get_close_matches(name, SETTINGS, n=1)
        parts.append(f"{name} (did you mean {close[0]}?)" if close else name)
    noun = "setting" if len(parts) == 1 else "settings"
    raise ConfigError(f"Unknown {noun}: {', '.join(parts)}. Fix the name or remove it.")


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of true/false, got an unrecognised value")


def _int(env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _csv(env: Mapping[str, str], name: str, default: frozenset[str]) -> frozenset[str]:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """Settings for one manager process."""

    secret_key: str = field(repr=False)
    database_url: str = field(default="sqlite+aiosqlite:///./traceguard-manager.db", repr=False)
    allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
    csrf_trusted_origins: frozenset[str] = frozenset()
    debug: bool = False
    secure_cookies: bool = True
    log_format: str = "json"
    log_level: str = "INFO"
    # A session ends after this long without a request, or at the absolute limit.
    session_idle_seconds: int = 30 * 60
    session_absolute_seconds: int = 12 * 60 * 60
    # An agent is offline once nothing has arrived for this long. TraceGuard
    # heartbeats every five minutes by default, so this allows two misses.
    agent_offline_seconds: int = 15 * 60
    login_max_failures: int = 5
    login_lockout_seconds: int = 15 * 60
    # Sign-in attempts allowed per client address per minute, whoever they are for.
    login_requests_per_minute: int = 10
    ingest_max_records: int = 500
    ingest_requests_per_minute: int = 240
    alert_retention_days: int = 90
    # Where people reach the dashboard, for links in notifications. No trailing slash.
    public_url: str | None = None
    # Webhooks to private addresses are refused unless this is set; loopback and
    # link-local (cloud metadata) addresses are refused either way.
    notify_allow_private_networks: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str = field(default="", repr=False)
    smtp_from: str | None = None
    smtp_tls: str = "starttls"

    def __post_init__(self) -> None:
        if len(self.secret_key) < MIN_SECRET_KEY_LENGTH:
            raise ConfigError(f"TGM_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        if not self.database_url.startswith(_ALLOWED_DRIVERS):
            raise ConfigError("TGM_DATABASE_URL must start with sqlite+aiosqlite:// or postgresql+asyncpg://")
        if self.log_format not in {"json", "text"}:
            raise ConfigError("TGM_LOG_FORMAT must be json or text")
        if self.log_level not in _LOG_LEVELS:
            raise ConfigError("TGM_LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR or CRITICAL")
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ConfigError("TGM_SESSION_IDLE_SECONDS must not exceed TGM_SESSION_ABSOLUTE_SECONDS")
        if self.public_url is not None and not self.public_url.startswith(("https://", "http://")):
            raise ConfigError("TGM_PUBLIC_URL must start with https:// (or http:// for local development)")
        if self.smtp_tls not in _SMTP_TLS_MODES:
            raise ConfigError("TGM_SMTP_TLS must be starttls, implicit or none")
        if self.smtp_host and not self.smtp_from:
            raise ConfigError("TGM_SMTP_FROM is required when TGM_SMTP_HOST is set")
        if self.smtp_tls == "none" and self.smtp_username:
            # A password sent over an unencrypted connection is readable by anything on the path.
            raise ConfigError("TGM_SMTP_TLS=none cannot be combined with TGM_SMTP_USERNAME")
        if self.debug and self.secure_cookies:
            # Debug pages expose stack traces; never combine them with a production cookie posture.
            raise ConfigError("TGM_DEBUG=true requires TGM_SECURE_COOKIES=false and must not be used in production")

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Self:
        env = os.environ if env is None else env
        _reject_unknown(env)
        secret_key = env.get("TGM_SECRET_KEY", "").strip()
        if not secret_key:
            raise ConfigError(
                "TGM_SECRET_KEY is not set. Generate one with "
                "`python -c 'import secrets; print(secrets.token_urlsafe(48))'` "
                "and keep it in a secret store."
            )
        defaults = cls(secret_key=secret_key)
        return cls(
            secret_key=secret_key,
            database_url=env.get("TGM_DATABASE_URL", "").strip() or defaults.database_url,
            allowed_hosts=_csv(env, "TGM_ALLOWED_HOSTS", defaults.allowed_hosts),
            csrf_trusted_origins=_csv(env, "TGM_CSRF_TRUSTED_ORIGINS", defaults.csrf_trusted_origins),
            debug=_bool(env, "TGM_DEBUG", defaults.debug),
            secure_cookies=_bool(env, "TGM_SECURE_COOKIES", defaults.secure_cookies),
            log_format=env.get("TGM_LOG_FORMAT", defaults.log_format).strip().lower(),
            log_level=env.get("TGM_LOG_LEVEL", defaults.log_level).strip().upper(),
            session_idle_seconds=_int(env, "TGM_SESSION_IDLE_SECONDS", defaults.session_idle_seconds, minimum=60, maximum=86_400),
            session_absolute_seconds=_int(
                env,
                "TGM_SESSION_ABSOLUTE_SECONDS",
                defaults.session_absolute_seconds,
                minimum=300,
                maximum=604_800,
            ),
            agent_offline_seconds=_int(
                env, "TGM_AGENT_OFFLINE_SECONDS", defaults.agent_offline_seconds, minimum=30, maximum=86_400
            ),
            login_max_failures=_int(env, "TGM_LOGIN_MAX_FAILURES", defaults.login_max_failures, minimum=3, maximum=20),
            login_lockout_seconds=_int(
                env, "TGM_LOGIN_LOCKOUT_SECONDS", defaults.login_lockout_seconds, minimum=60, maximum=86_400
            ),
            login_requests_per_minute=_int(
                env, "TGM_LOGIN_REQUESTS_PER_MINUTE", defaults.login_requests_per_minute, minimum=3, maximum=1_000
            ),
            ingest_max_records=_int(env, "TGM_INGEST_MAX_RECORDS", defaults.ingest_max_records, minimum=1, maximum=5_000),
            ingest_requests_per_minute=_int(
                env,
                "TGM_INGEST_REQUESTS_PER_MINUTE",
                defaults.ingest_requests_per_minute,
                minimum=1,
                maximum=100_000,
            ),
            alert_retention_days=_int(env, "TGM_ALERT_RETENTION_DAYS", defaults.alert_retention_days, minimum=1, maximum=3_650),
            public_url=env.get("TGM_PUBLIC_URL", "").strip().rstrip("/") or None,
            notify_allow_private_networks=_bool(env, "TGM_NOTIFY_ALLOW_PRIVATE_NETWORKS", defaults.notify_allow_private_networks),
            smtp_host=env.get("TGM_SMTP_HOST", "").strip() or None,
            smtp_port=_int(env, "TGM_SMTP_PORT", defaults.smtp_port, minimum=1, maximum=65_535),
            smtp_username=env.get("TGM_SMTP_USERNAME", "").strip() or None,
            smtp_password=env.get("TGM_SMTP_PASSWORD", ""),
            smtp_from=env.get("TGM_SMTP_FROM", "").strip() or None,
            smtp_tls=env.get("TGM_SMTP_TLS", defaults.smtp_tls).strip().lower(),
        )

    @classmethod
    def for_testing(cls, **overrides: object) -> Self:
        """Build a throwaway configuration with a random key and plain-HTTP cookies."""
        values: dict[str, object] = {
            "secret_key": secrets.token_urlsafe(48),
            "secure_cookies": False,
            "log_format": "text",
            "log_level": "WARNING",
        }
        values.update(overrides)
        return cls(**values)  # ty: ignore[invalid-argument-type]
