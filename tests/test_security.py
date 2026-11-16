import pytest

from traceguard_manager import security


async def test_password_round_trip() -> None:
    hashed = await security.hash_password("correct-battery-staple-42")
    assert hashed.startswith("$argon2id$")
    assert await security.verify_password(hashed, "correct-battery-staple-42")
    assert not await security.verify_password(hashed, "wrong-battery-staple-42")


async def test_missing_hash_never_verifies() -> None:
    assert not await security.verify_password(None, "anything-at-all-123")


async def test_overlong_password_is_rejected_without_hashing_it_whole() -> None:
    hashed = await security.hash_password("x" * 128)
    assert not await security.verify_password(hashed, "x" * 5000)


async def test_malformed_hash_is_a_failed_verification() -> None:
    assert not await security.verify_password("not-a-hash", "whatever-password")


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("short", "at least 12"),
        ("x" * 129, "at most 128"),
        ("passwordpassword", "too common"),
        ("aaaaaaaaaaaaaaaa", "too common or too repetitive"),
        ("my-jsmith-password", "must not contain the username"),
    ],
)
def test_password_policy_rejections(password: str, message: str) -> None:
    with pytest.raises(security.PasswordPolicyError, match=message):
        security.check_password_policy(password, username="jsmith")


def test_password_policy_accepts_a_passphrase() -> None:
    security.check_password_policy("four random words together", username="jsmith")


def test_agent_tokens_are_unique_prefixed_and_hashed() -> None:
    first, second = security.new_agent_token(), security.new_agent_token()
    assert first != second
    assert first.startswith(security.AGENT_TOKEN_PREFIX)
    assert len(first) >= 40
    assert security.hash_token(first) != first
    assert len(security.hash_token(first)) == 64
    assert security.token_display_prefix(first) == first[:10]
