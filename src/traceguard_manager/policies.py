"""Central policy: TraceGuard policy documents the manager signs and serves.

Each agent fetches one remote policy, merged on the agent with any local
overlay. The manager picks it: the highest-priority policy that shares a tag
with the agent, or else the default policy. Every document is signed with
an Ed25519 key, as TraceGuard verifies with ``TRACEGUARD_POLICY_SIGNING_KEY``.

The manager checks a document's shape before saving it; the agent's own
validation is the last word, and it reports a policy it rejects.
"""

import asyncio
import base64
import hashlib
import os
import stat
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from . import fleet
from .errors import DomainError
from .models import Agent, Policy

# TraceGuard refuses larger policy documents.
MAX_POLICY_BYTES = 4 << 20
MAX_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500
PRIORITY_RANGE = range(-1000, 1001)
# Top-level keys a TraceGuard policy may hold, as of TraceGuard 1.9.
TOP_LEVEL_KEYS = frozenset(
    {
        "version",
        "builtin_profiles",
        "disabled_rule_ids",
        "dns",
        "egress",
        "exec",
        "file",
        "bind",
        "unix",
        "sockopt",
        "detections",
        "detection_exceptions",
        "detection_sequences",
        "file_integrity",
        "threat_intel",
        "responses",
    }
)
RESERVED_RESPONSE_ID = "manager-command"
# Served when no policy applies to an agent: it runs on its local policy alone.
EMPTY_POLICY = "version: 1\n"
# A policy saved from the dashboard arrives as a JSON string, where escaping
# can double its size.
MAX_POLICY_REQUEST_BYTES = 2 * MAX_POLICY_BYTES + (64 << 10)


class PolicyError(DomainError):
    """A user-facing validation failure. The message is safe to show."""


class SigningKeyError(Exception):
    """The configured signing key cannot be used."""


def digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


EMPTY_POLICY_SHA256 = digest(EMPTY_POLICY)


def validate_content(content: str) -> str:
    """Check a policy document's shape and return it with normalised newlines."""
    content = content.replace("\r\n", "\n")
    try:
        content.encode()
    except UnicodeEncodeError:
        raise PolicyError("The policy holds characters that are not valid text.") from None
    if not content.strip():
        raise PolicyError("The policy is empty.")
    if len(content.encode()) > MAX_POLICY_BYTES:
        raise PolicyError(f"Policies are limited to {MAX_POLICY_BYTES // (1 << 20)} MiB.")
    _check_yaml_events(content)
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise PolicyError(f"The policy is not valid YAML{where}.") from exc
    except RecursionError:
        raise PolicyError("The policy is nested too deeply.") from None
    except ValueError:
        # PyYAML raises plain ValueError for some scalars, such as an impossible date.
        raise PolicyError("The policy holds a value YAML cannot read, such as an impossible date.") from None
    if len(documents) != 1:
        raise PolicyError("A policy must be exactly one YAML document.")
    document = documents[0]
    if not isinstance(document, dict):
        raise PolicyError("A policy must be a YAML mapping, such as `version: 1`.")
    unknown = sorted(str(key) for key in document if key not in TOP_LEVEL_KEYS)
    if unknown:
        raise PolicyError(f"Unknown top-level keys: {', '.join(unknown[:5])}.")
    # TraceGuard rejects a document without it, so it must be written out.
    version = document.get("version")
    if type(version) is not int or version != 1:
        raise PolicyError("Only policy `version: 1` is supported.")
    responses = document.get("responses") or []
    if isinstance(responses, list) and any(
        isinstance(item, dict) and item.get("id") == RESERVED_RESPONSE_ID for item in responses
    ):
        raise PolicyError(f"The response id `{RESERVED_RESPONSE_ID}` is reserved for console commands.")
    return content


MAX_YAML_ALIASES = 256


def _check_yaml_events(content: str) -> None:
    """Refuse YAML whose construction could expand far beyond its size.

    Merge keys copy the mappings they name, so a few aliases can build a
    huge document; plain aliases are shared and stay cheap, but are bounded.
    """
    aliases = 0
    try:
        for event in yaml.parse(content, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                aliases += 1
                if aliases > MAX_YAML_ALIASES:
                    raise PolicyError(f"Policies may use at most {MAX_YAML_ALIASES} YAML aliases.")
            elif _merges(event):
                raise PolicyError("YAML merge keys (<<) are not supported in policies; write the entries out.")
    except yaml.YAMLError:
        # Reported, with its line, by the full parse.
        return


_MERGE_TAGS = frozenset({"tag:yaml.org,2002:merge", "!!merge"})


def _merges(event: yaml.Event) -> bool:
    """Whether a node could become a merge key.

    An explicit merge tag merges on any node, scalar or collection, so it is
    refused wherever it appears. A ``<<`` scalar merges exactly when PyYAML
    resolves it implicitly as a plain scalar (untagged plain, or tagged
    ``!``); a quoted or block ``"<<"`` is an ordinary string and is allowed.
    """
    tag = getattr(event, "tag", None)
    if tag in _MERGE_TAGS:
        return True
    return isinstance(event, yaml.ScalarEvent) and event.value == "<<" and bool(event.implicit[0])


def _clean_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise PolicyError("Give the policy a name.")
    if len(name) > MAX_NAME_LENGTH:
        raise PolicyError(f"Names are limited to {MAX_NAME_LENGTH} characters.")
    return name


def _clean_description(description: str) -> str:
    description = description.strip()
    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise PolicyError(f"Descriptions are limited to {MAX_DESCRIPTION_LENGTH} characters.")
    return description


def _clean_priority(priority: int) -> int:
    if priority not in PRIORITY_RANGE:
        raise PolicyError(f"Priority must be between {PRIORITY_RANGE.start} and {PRIORITY_RANGE.stop - 1}.")
    return priority


async def list_policies(session: AsyncSession) -> list[Policy]:
    """Every policy, without its document, which only the chosen one needs."""
    return list(
        await session.scalars(
            select(Policy).options(defer(Policy.content)).order_by(Policy.is_default.desc(), Policy.priority.desc(), Policy.name)
        )
    )


async def content_of(session: AsyncSession, policy: Policy | None) -> tuple[str, str]:
    """The document served for this choice and its digest, read together.

    Both come from one row read, so an edit committed between two reads can
    never pair a document with another revision's digest.
    """
    if policy is None:
        return EMPTY_POLICY, EMPTY_POLICY_SHA256
    row = (await session.execute(select(Policy.content, Policy.sha256).where(Policy.id == policy.id))).first()
    if row is None:
        return EMPTY_POLICY, EMPTY_POLICY_SHA256
    return row[0], row[1]


async def validate_off_loop(content: str) -> str:
    """Validate in a worker thread: parsing a large document takes long enough to stall other requests."""
    return await asyncio.to_thread(validate_content, content)


async def get_policy(session: AsyncSession, policy_id: uuid.UUID) -> Policy | None:
    return await session.get(Policy, policy_id)


async def _name_taken(session: AsyncSession, name: str, *, excluding: uuid.UUID | None = None) -> bool:
    query = select(Policy.id).where(Policy.name == name)
    if excluding is not None:
        query = query.where(Policy.id != excluding)
    return await session.scalar(query) is not None


async def _clear_default(session: AsyncSession, *, keep: uuid.UUID | None) -> None:
    """Unset the current default first, so the unique index allows the new one."""
    query = update(Policy).where(Policy.is_default.is_(True))
    if keep is not None:
        query = query.where(Policy.id != keep)
    await session.execute(query.values(is_default=False).execution_options(synchronize_session="fetch"))


async def create_policy(
    session: AsyncSession,
    *,
    name: str,
    description: str,
    content: str,
    tags: list[str],
    priority: int,
    is_default: bool,
    actor: str,
    now: datetime,
) -> Policy:
    name = _clean_name(name)
    if await _name_taken(session, name):
        raise PolicyError("A policy with that name already exists.")
    content = await validate_off_loop(content)
    if is_default:
        await _clear_default(session, keep=None)
    policy = Policy(
        name=name,
        description=_clean_description(description),
        content=content,
        sha256=digest(content),
        tags=tags,
        priority=_clean_priority(priority),
        is_default=is_default,
        created_by=actor,
        created_at=now,
        updated_by=actor,
        updated_at=now,
    )
    session.add(policy)
    await _flush(session)
    return policy


async def _flush(session: AsyncSession) -> None:
    try:
        await session.flush()
    except IntegrityError:
        # Another admin saved a policy with the same name, or a new default, at the same moment.
        raise PolicyError("Another change to the policies was saved at the same time. Reload and try again.") from None


async def update_policy(
    session: AsyncSession,
    policy: Policy,
    *,
    name: str,
    description: str,
    content: str,
    tags: list[str],
    priority: int,
    is_default: bool,
    actor: str,
    now: datetime,
) -> bool:
    """Save changes. Returns whether the document itself changed."""
    name = _clean_name(name)
    if await _name_taken(session, name, excluding=policy.id):
        raise PolicyError("A policy with that name already exists.")
    content = await validate_off_loop(content)
    changed = content != policy.content
    if is_default:
        await _clear_default(session, keep=policy.id)
        # Written out even when this request already saw it as the default:
        # another save may have cleared it meanwhile.
        try:
            await session.execute(update(Policy).where(Policy.id == policy.id).values(is_default=True))
        except IntegrityError:
            raise PolicyError("Another change to the policies was saved at the same time. Reload and try again.") from None
    policy.name = name
    policy.description = _clean_description(description)
    policy.content = content
    policy.sha256 = digest(content)
    policy.tags = tags
    policy.priority = _clean_priority(priority)
    policy.is_default = is_default
    policy.updated_by = actor
    policy.updated_at = now
    await _flush(session)
    return changed


async def delete_policy(session: AsyncSession, policy: Policy) -> None:
    await session.delete(policy)


def choose(policies: Sequence[Policy], tags: Sequence[str]) -> Policy | None:
    """The policy an agent with these tags gets, or None when no policy applies."""
    wanted = set(tags)
    tagged = [policy for policy in policies if wanted.intersection(policy.tags)]
    if tagged:
        # Highest priority first; the name breaks ties so the answer is stable.
        return min(tagged, key=lambda policy: (-policy.priority, policy.name))
    return next((policy for policy in policies if policy.is_default), None)


async def policy_for_agent(session: AsyncSession, agent: Agent) -> Policy | None:
    return choose(await list_policies(session), agent.tags)


@dataclass(frozen=True, slots=True)
class Assignment:
    """What an agent is assigned and whether it has taken it."""

    policy: Policy | None
    # in_sync | pending | not_fetching; policy is None for the empty fallback
    state: str


def assignment(agent: Agent, policies: Sequence[Policy]) -> Assignment:
    policy = choose(policies, agent.tags)
    expected = policy.sha256 if policy is not None else EMPTY_POLICY_SHA256
    if agent.policy_remote_sha256 == expected:
        return Assignment(policy=policy, state="in_sync")
    if agent.policy_fetched_at is None:
        return Assignment(policy=policy, state="not_fetching")
    return Assignment(policy=policy, state="pending")


async def agents_using(session: AsyncSession, policy: Policy) -> list[Agent]:
    policies = await list_policies(session)
    using = []
    for agent in await fleet.list_agents(session):
        chosen = choose(policies, agent.tags)
        if chosen is not None and chosen.id == policy.id:
            using.append(agent)
    return using


class Signer:
    """Signs policy documents with the manager's Ed25519 key."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    def sign(self, content: str) -> str:
        """A base64 detached signature over the document's exact bytes."""
        return base64.b64encode(self._key.sign(content.encode())).decode()

    def public_pem(self) -> str:
        return (
            self._key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )


def load_signer(path: str) -> Signer:
    """Read the signing key, refusing one that other users could read."""
    try:
        # O_NOFOLLOW refuses a symlink; the checks below run on the file opened.
        # O_NONBLOCK so a FIFO at the path is reported, not waited on.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise SigningKeyError(f"cannot read the policy signing key: {exc.strerror}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SigningKeyError("the policy signing key must be a regular file")
        if info.st_mode & 0o077:
            raise SigningKeyError("the policy signing key must not be readable by group or others (chmod 600)")
        if info.st_uid != os.geteuid():
            raise SigningKeyError("the policy signing key must be owned by the user the manager runs as")
        data = handle.read(64 << 10)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("the policy signing key is not an unencrypted PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyError("the policy signing key must be an Ed25519 key")
    return Signer(key)


def generate_key(path: str) -> Signer:
    """Write a new private key to path, readable by its owner only."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    return Signer(key)
