"""Central policy: validation, assignment by tag and priority, signing, serving and the key CLI."""

import base64
import dataclasses
import os
import stat
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from traceguard_manager import accounts, cli, fleet, policies
from traceguard_manager.asgi import create_app
from traceguard_manager.config import Config, ConfigError
from traceguard_manager.models import Agent

from .conftest import RecordingTransport, Site
from .helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, VIEWER_PASSWORD, data, heartbeat

WEB_POLICY = "version: 1\ndns:\n  block: [web.example]\n"
PROD_POLICY = "version: 1\ndns:\n  block: [prod.example]\n"
DEFAULT_POLICY = "version: 1\ndns:\n  block: [default.example]\n"


@pytest.fixture
async def signed(config: Config, tmp_path: Path) -> AsyncIterator[Site]:
    """A site with central policy on."""
    key_path = tmp_path / "policy.key"
    policies.generate_key(str(key_path))
    manager = create_app(dataclasses.replace(config, policy_signing_key_file=str(key_path)), transport=RecordingTransport())
    await manager.database.create_all()
    async with manager.database.session() as session:
        await accounts.create_user(session, username="admin", password=ADMIN_PASSWORD, role="admin")
        await accounts.create_user(session, username="analyst", password=ANALYST_PASSWORD, role="analyst")
        await accounts.create_user(session, username="viewer", password=VIEWER_PASSWORD, role="viewer")
        agent, token = await fleet.enroll_agent(session, name="web-01")
    try:
        yield Site(manager=manager, agent_id=str(agent.id), agent_token=token, transport=RecordingTransport())
    finally:
        await manager.database.dispose()


async def _fetch(site: Site, path: str = "/api/v1/policy", **headers: str):
    return await site.agent_client().arequest("GET", path, headers={"authorization": f"Bearer {site.agent_token}", **headers})


async def _public_key(site: Site) -> Ed25519PublicKey:
    response = await (await site.admin()).get("/policies/public-key", accept="*/*")
    assert response.status_code == 200
    key = load_pem_public_key(response.body)
    assert isinstance(key, Ed25519PublicKey)
    return key


async def _create(browser, **fields) -> str:
    body = {"name": "web", "content": WEB_POLICY, "description": "", "tags": "", "priority": "0", "is_default": False}
    response = await browser.post("/policies", body | fields)
    assert response.status_code == 201, response.text
    return data(response)["id"]


async def _tag_agent(site: Site, *tags: str) -> None:
    async with site.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(site.agent_id))
        assert agent is not None
        agent.tags = list(tags)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "empty"),
        ("dns: [unclosed", "not valid YAML"),
        ("version: 1\n---\nversion: 1\n", "exactly one"),
        ("- a\n- b\n", "mapping"),
        ("version: 2\n", "version: 1"),
        ("version: 1\nfirewall: {}\n", "Unknown top-level keys: firewall"),
        (
            "version: 1\nresponses:\n  - id: manager-command\n    rules: [x]\n    action: block_peer\n    duration: 1h\n",
            "reserved",
        ),
    ],
)
def test_documents_are_checked_before_saving(content: str, message: str) -> None:
    with pytest.raises(policies.PolicyError, match=message):
        policies.validate_content(content)


def test_documents_over_the_agent_limit_are_refused() -> None:
    with pytest.raises(policies.PolicyError, match="MiB"):
        policies.validate_content("version: 1\n# " + "x" * policies.MAX_POLICY_BYTES)


def test_the_highest_priority_tagged_policy_wins_then_the_default() -> None:
    def make(name: str, tags: list[str], priority: int = 0, default: bool = False) -> policies.Policy:
        return policies.Policy(name=name, tags=tags, priority=priority, is_default=default, content="", sha256="")

    web, prod, fallback = make("web", ["web"], 5), make("prod", ["prod"], 10), make("default", [], default=True)
    tie = make("another-web", ["web"], 5)
    every = [web, prod, fallback, tie]
    assert policies.choose(every, ["web", "prod"]) is prod
    assert policies.choose(every, ["web"]) is tie  # equal priority: the name decides, so it is stable
    assert policies.choose(every, ["db"]) is fallback
    assert policies.choose([web, prod], ["db"]) is None


async def test_agents_fetch_their_policy_signed_with_an_etag(signed: Site) -> None:
    browser = await signed.admin()
    await _create(browser, name="web", content=WEB_POLICY, tags="web", priority="5")
    await _create(browser, name="everyone", content=DEFAULT_POLICY, is_default=True)
    key = await _public_key(signed)

    response = await _fetch(signed)
    assert response.status_code == 200
    assert response.text == DEFAULT_POLICY
    signature = (await _fetch(signed, "/api/v1/policy.sig")).text
    key.verify(base64.b64decode(signature), response.body)  # raises if it does not verify

    await _tag_agent(signed, "web")
    response = await _fetch(signed)
    assert response.text == WEB_POLICY
    key.verify(base64.b64decode((await _fetch(signed, "/api/v1/policy.sig")).text), response.body)
    etag = response.headers["etag"]
    assert etag == f'"{policies.digest(WEB_POLICY)}"'
    unchanged = await _fetch(signed, **{"if-none-match": etag})
    assert unchanged.status_code == 304 and unchanged.body == b""

    async with signed.manager.database.session() as session:
        agent = await session.get(Agent, uuid.UUID(signed.agent_id))
        assert agent is not None
        assert agent.policy_served_sha256 == policies.digest(WEB_POLICY) and agent.policy_fetched_at is not None


async def test_an_agent_no_policy_applies_to_gets_an_empty_one(signed: Site) -> None:
    response = await _fetch(signed)
    assert response.status_code == 200 and response.text == policies.EMPTY_POLICY
    key = await _public_key(signed)
    key.verify(base64.b64decode((await _fetch(signed, "/api/v1/policy.sig")).text), response.body)


async def test_policy_endpoints_need_a_token(signed: Site) -> None:
    anonymous = await signed.agent_client().arequest("GET", "/api/v1/policy")
    assert anonymous.status_code == 401
    wrong = await signed.agent_client().arequest("GET", "/api/v1/policy", headers={"authorization": "Bearer tgm_nope"})
    assert wrong.status_code == 401


async def test_without_a_signing_key_nothing_is_served(site: Site) -> None:
    assert (await _fetch(site)).status_code == 404
    assert (await _fetch(site, "/api/v1/policy.sig")).status_code == 404
    page = (await (await site.admin()).get("/policies")).text
    assert 'data-testid="policy-off"' in page


async def test_agent_page_shows_whether_the_agent_took_its_policy(signed: Site) -> None:
    browser = await signed.admin()
    await _create(browser, name="everyone", content=DEFAULT_POLICY, is_default=True)
    page = (await browser.get(f"/agents/{signed.agent_id}")).text
    assert "never fetched" in page
    await _fetch(signed)
    await signed.ingest([heartbeat(policy_remote_sha256="c" * 64)])
    assert "not yet" in (await browser.get(f"/agents/{signed.agent_id}")).text
    await signed.ingest([heartbeat(policy_remote_sha256=policies.digest(DEFAULT_POLICY))])
    page = (await browser.get(f"/agents/{signed.agent_id}")).text
    assert "in use" in page


async def test_only_one_default_and_names_are_unique(signed: Site) -> None:
    browser = await signed.admin()
    first = await _create(browser, name="one", is_default=True)
    second = await _create(browser, name="two", is_default=True)
    async with signed.manager.database.session() as session:
        defaults = [policy.name for policy in await policies.list_policies(session) if policy.is_default]
    assert defaults == ["two"]
    duplicate = await browser.post("/policies", {"name": "one", "content": WEB_POLICY})
    assert duplicate.status_code == 400 and "already exists" in duplicate.text
    renamed = await browser.send("PATCH", f"/policies/{second}", {"name": "one", "content": WEB_POLICY})
    assert renamed.status_code == 400
    assert (await browser.send("DELETE", f"/policies/{first}")).status_code == 200
    assert (await browser.get(f"/policies/{first}")).status_code == 404


async def test_editing_is_audited_and_admin_only(signed: Site) -> None:
    browser = await signed.admin()
    policy_id = await _create(browser, name="web", tags="web")
    updated = await browser.send(
        "PATCH", f"/policies/{policy_id}", {"name": "web", "content": PROD_POLICY, "tags": "web, prod", "priority": "3"}
    )
    assert updated.status_code == 200 and data(updated)["sha256"] == policies.digest(PROD_POLICY)
    audit = (await browser.get("/audit?action=policy.update")).text
    assert "policy.update" in audit
    bad = await browser.send("PATCH", f"/policies/{policy_id}", {"name": "web", "content": "version: 3\n"})
    assert bad.status_code == 400

    for role in ("analyst", "viewer"):
        other = await getattr(signed, role)()
        assert (await other.get("/policies")).status_code in {302, 303, 403}
        assert (await other.post("/policies", {"name": "x", "content": WEB_POLICY})).status_code == 403


def test_policy_key_cli_generates_and_prints_keys(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "policy.key"
    assert cli.main(["policy-key", "generate", str(path)]) == 0
    public = capsys.readouterr().out
    assert public.startswith("-----BEGIN PUBLIC KEY-----")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cli.main(["policy-key", "public", str(path)]) == 0
    assert capsys.readouterr().out == public
    # Never overwrite a key in use.
    assert cli.main(["policy-key", "generate", str(path)]) == 2


def test_a_readable_or_linked_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "policy.key"
    policies.generate_key(str(path))
    path.chmod(0o640)
    with pytest.raises(policies.SigningKeyError, match="group or others"):
        policies.load_signer(str(path))
    path.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(path)
    with pytest.raises(policies.SigningKeyError):
        policies.load_signer(str(link))
    with pytest.raises(ConfigError, match="TGM_POLICY_SIGNING_KEY_FILE"):
        create_app(Config.for_testing(database_url=f"sqlite+aiosqlite:///{tmp_path / 'm.db'}", policy_signing_key_file=str(link)))
    with pytest.raises(ConfigError, match="absolute"):
        Config.for_testing(policy_signing_key_file="relative.key")


def test_a_signature_covers_the_exact_bytes(tmp_path: Path) -> None:
    signer = policies.generate_key(str(tmp_path / "k"))
    key = load_pem_public_key(signer.public_pem().encode())
    assert isinstance(key, Ed25519PublicKey)
    signature = base64.b64decode(signer.sign(WEB_POLICY))
    key.verify(signature, WEB_POLICY.encode())
    with pytest.raises(Exception):  # noqa: B017 - cryptography's InvalidSignature
        key.verify(signature, WEB_POLICY.replace("web", "wob").encode())
    assert len(signature) == 64
    assert (tmp_path / "k").exists()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[" * 2000 + "]" * 2000, "nested too deeply|not valid YAML"),
        ("version: 1.0\n", "version: 1"),
        ("version: true\n", "version: 1"),
    ],
)
def test_odd_documents_are_refused_cleanly(content: str, message: str) -> None:
    with pytest.raises(policies.PolicyError, match=message):
        policies.validate_content(content)


async def test_large_policies_can_be_saved(signed: Site) -> None:
    blocked = ", ".join(f"host-{index:06d}.example" for index in range(8000))
    content = f"version: 1\ndns:\n  block: [{blocked}]\n"
    assert len(content) > 150_000
    browser = await signed.admin()
    await _create(browser, name="big", content=content, is_default=True)
    assert (await _fetch(signed)).text == content


async def test_agents_on_the_empty_policy_show_whether_they_took_it(signed: Site) -> None:
    browser = await signed.admin()
    await _fetch(signed)
    await signed.ingest([heartbeat(policy_remote_sha256=policies.EMPTY_POLICY_SHA256)])
    page = (await browser.get(f"/agents/{signed.agent_id}")).text
    assert "served an empty policy" in page and "in use" in page


async def test_a_second_default_is_refused_by_the_database(signed: Site) -> None:
    from sqlalchemy.exc import IntegrityError

    browser = await signed.admin()
    await _create(browser, name="one", is_default=True)
    with pytest.raises(IntegrityError):
        async with signed.manager.database.session() as session:
            session.add(
                policies.Policy(
                    name="two",
                    content=WEB_POLICY,
                    sha256=policies.digest(WEB_POLICY),
                    tags=[],
                    priority=0,
                    is_default=True,
                    created_by="x",
                    updated_by="x",
                )
            )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("version: 1\ndns: 2001-13-45\n", "cannot read"),
        ("version: 1\ndns: \ud800\n", "not valid text"),
        ("version: 1\nbase: &b {block: [x]}\ndns:\n  <<: *b\n", "merge keys"),
        ("version: 1\nx: &a 1\nlist: [" + ", ".join(["*a"] * 300) + "]\n", "aliases"),
    ],
)
def test_awkward_yaml_is_refused_cleanly(content: str, message: str) -> None:
    with pytest.raises(policies.PolicyError, match=message):
        policies.validate_content(content)


async def test_a_stale_save_cannot_leave_no_default(signed: Site) -> None:
    browser = await signed.admin()
    first = await _create(browser, name="first", is_default=True)
    await _create(browser, name="second", is_default=True)
    # A save of "first" from a page loaded while it was still the default.
    saved = await browser.send("PATCH", f"/policies/{first}", {"name": "first", "content": WEB_POLICY, "is_default": True})
    assert saved.status_code == 200
    async with signed.manager.database.session() as session:
        defaults = [policy.name for policy in await policies.list_policies(session) if policy.is_default]
    assert defaults == ["first"]


@pytest.mark.parametrize(
    "content",
    [
        "version: 1\nbase: &b {block: [x]}\ndns:\n  !!merge anything: *b\n",
        "version: 1\nbase: &b {block: [x]}\ndns:\n  !<tag:yaml.org,2002:merge> 'k': *b\n",
        "version: 1\nbase: &b {block: [x]}\ndns:\n  ? !!merge [m]\n  : *b\n",
        "version: 1\nbase: &b {block: [x]}\ndns:\n  ! <<: *b\n",
    ],
)
def test_explicit_merge_tags_are_refused(content: str) -> None:
    with pytest.raises(policies.PolicyError, match="merge"):
        policies.validate_content(content)


def test_a_fifo_signing_key_is_refused_without_hanging(tmp_path: Path) -> None:
    fifo = tmp_path / "policy.key"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(policies.SigningKeyError, match="regular file"):
        policies.load_signer(str(fifo))


@pytest.mark.parametrize(
    "content",
    [
        'version: 1\ndns:\n  block: [x.example]\nresponses: []\ndetection_exceptions: [{id: e1, rules: [r], reason: "<<"}]\n',
        "version: 1\ndetection_exceptions: [{id: e1, rules: [r], reason: '<<'}]\n",
        "version: 1\ndetection_exceptions:\n  - id: e1\n    rules: [r]\n    reason: |\n      <<\n",
    ],
)
def test_quoted_and_block_strings_may_hold_merge_text(content: str) -> None:
    assert policies.validate_content(content)


def test_a_non_specific_tag_merge_is_still_refused() -> None:
    with pytest.raises(policies.PolicyError, match="merge"):
        policies.validate_content('version: 1\nbase: &b {block: [x]}\ndns:\n  ! "<<": *b\n')
