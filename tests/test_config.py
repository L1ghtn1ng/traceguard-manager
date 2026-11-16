import pytest

from traceguard_manager.config import Config, ConfigError

KEY = "k" * 48


def test_requires_secret_key() -> None:
    with pytest.raises(ConfigError, match="TGM_SECRET_KEY is not set"):
        Config.from_env({})


def test_rejects_short_secret_key() -> None:
    with pytest.raises(ConfigError, match="at least 32"):
        Config.from_env({"TGM_SECRET_KEY": "short"})


def test_production_defaults_are_secure() -> None:
    config = Config.from_env({"TGM_SECRET_KEY": KEY})
    assert config.secure_cookies is True
    assert config.debug is False
    assert config.allowed_hosts == frozenset({"127.0.0.1", "localhost"})
    assert config.log_format == "json"


def test_secret_key_is_not_in_repr() -> None:
    config = Config.from_env({"TGM_SECRET_KEY": KEY, "TGM_DATABASE_URL": "postgresql+asyncpg://u:pw@db/tgm"})
    assert KEY not in repr(config)
    assert "pw@db" not in repr(config)


def test_parses_lists_and_booleans() -> None:
    config = Config.from_env(
        {
            "TGM_SECRET_KEY": KEY,
            "TGM_ALLOWED_HOSTS": "manager.example.com, 10.0.0.5",
            "TGM_SECURE_COOKIES": "false",
            "TGM_AGENT_OFFLINE_SECONDS": "120",
        }
    )
    assert config.allowed_hosts == frozenset({"manager.example.com", "10.0.0.5"})
    assert config.secure_cookies is False
    assert config.agent_offline_seconds == 120


@pytest.mark.parametrize(
    "env",
    [
        {"TGM_SECURE_COOKIES": "maybe"},
        {"TGM_DATABASE_URL": "mysql://nope"},
        {"TGM_DATABASE_URL": "sqlite:///sync-driver.db"},
        {"TGM_LOG_FORMAT": "xml"},
        {"TGM_AGENT_OFFLINE_SECONDS": "five"},
        {"TGM_LOGIN_MAX_FAILURES": "1"},
        {"TGM_DEBUG": "true"},  # debug with secure cookies is a production foot-gun
        {"TGM_SESSION_IDLE_SECONDS": "7200", "TGM_SESSION_ABSOLUTE_SECONDS": "3600"},
    ],
)
def test_rejects_invalid_values(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Config.from_env({"TGM_SECRET_KEY": KEY} | env)
