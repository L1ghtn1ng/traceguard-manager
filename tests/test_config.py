import re
from pathlib import Path

import pytest

from traceguard_manager.config import SETTINGS, Config, ConfigError

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
        {"TGM_LOG_LEVEL": "verbose"},
        {"TGM_AGENT_OFFLINE_SECONDS": "five"},
        {"TGM_LOGIN_MAX_FAILURES": "1"},
        {"TGM_DEBUG": "true"},  # debug with secure cookies is a production foot-gun
        {"TGM_SESSION_IDLE_SECONDS": "7200", "TGM_SESSION_ABSOLUTE_SECONDS": "3600"},
    ],
)
def test_rejects_invalid_values(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Config.from_env({"TGM_SECRET_KEY": KEY} | env)


def test_log_level_is_case_insensitive() -> None:
    assert Config.from_env({"TGM_SECRET_KEY": KEY, "TGM_LOG_LEVEL": "debug"}).log_level == "DEBUG"


def test_misspelt_setting_is_rejected_with_a_suggestion() -> None:
    with pytest.raises(ConfigError, match=r"TGM_ALLOWED_HOST \(did you mean TGM_ALLOWED_HOSTS\?\)") as raised:
        Config.from_env({"TGM_SECRET_KEY": KEY, "TGM_ALLOWED_HOST": "manager.example.com"})
    assert "manager.example.com" not in str(raised.value)  # names only, never values


def test_unrelated_and_test_only_variables_are_ignored() -> None:
    Config.from_env({"TGM_SECRET_KEY": KEY, "PATH": "/usr/bin", "TGM_E2E_BROWSER": "/usr/bin/chromium"})


def test_example_file_only_names_real_settings() -> None:
    example = (Path(__file__).resolve().parent.parent / ".env.example").read_text()
    named = set(re.findall(r"^#?\s*(TGM_[A-Z_]+)=", example, flags=re.MULTILINE))
    assert named
    assert named <= SETTINGS
