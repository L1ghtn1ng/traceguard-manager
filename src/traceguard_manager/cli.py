"""Command line: serve, migrate, and bootstrap accounts and agents."""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence
from datetime import timedelta

from sqlalchemy.exc import SQLAlchemyError

from . import __version__, accounts, audit, demo, fleet, policies
from .config import Config, ConfigError
from .db import MIGRATIONS_DIR, Database, SchemaError
from .errors import DomainError
from .models import Role, utcnow


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traceguard-manager", description="TraceGuard fleet manager")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Run the HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--workers", type=int, default=1)
    serve.add_argument(
        "--trust-proxy",
        metavar="ADDRESSES",
        help="Comma-separated proxy addresses whose X-Forwarded-* headers are trusted. Off by default.",
    )

    commands.add_parser("migrate", help="Create or upgrade the database schema")

    user = commands.add_parser("create-user", help="Create a dashboard user")
    user.add_argument("username")
    user.add_argument("--role", choices=[role.value for role in Role], default=Role.ADMIN.value)
    user.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from standard input instead of prompting",
    )

    unlock = commands.add_parser("unlock-user", help="Clear a dashboard user's sign-in lockout")
    unlock.add_argument("username")

    agent = commands.add_parser("create-agent", help="Enrol an agent and print its token once")
    agent.add_argument("name")

    sample = commands.add_parser(
        "demo-data",
        help="Fill the dashboard with sample agents and alerts (for trying it out, not for production)",
    )
    sample.add_argument("--remove", action="store_true", help="Delete the sample agents and their alerts")
    sample.add_argument("--force", action="store_true", help="Add sample data even though real agents are enrolled")

    key = commands.add_parser("policy-key", help="Create or show the key that signs central policies")
    key_actions = key.add_subparsers(dest="key_action", required=True)
    generate = key_actions.add_parser("generate", help="Write a new private key (mode 0600) and print its public key")
    generate.add_argument("path", help="Where to write the private key; set TGM_POLICY_SIGNING_KEY_FILE to it")
    public = key_actions.add_parser("public", help="Print the public key agents verify policies with")
    public.add_argument("path", help="The private key file")
    return parser


def _policy_key(args: argparse.Namespace) -> int:
    """Key management needs no database or configuration, only the key file."""
    try:
        if args.key_action == "generate":
            signer = policies.generate_key(args.path)
            print(f"Wrote {args.path}. Set TGM_POLICY_SIGNING_KEY_FILE={args.path} and restart.", file=sys.stderr)
        else:
            signer = policies.load_signer(args.path)
    except FileExistsError:
        print(f"error: {args.path} already exists; refusing to overwrite a signing key", file=sys.stderr)
        return 2
    except (OSError, policies.SigningKeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    # Agents verify with this; save it as TRACEGUARD_POLICY_SIGNING_KEY on each.
    print(signer.public_pem(), end="")
    return 0


def _read_password(*, from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != password:
        raise DomainError("Passwords do not match.")
    return password


def _migrate(config: Config) -> None:
    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_config = AlembicConfig()
    alembic_config.set_main_option("script_location", str(MIGRATIONS_DIR))
    alembic_config.attributes["database_url"] = config.database_url
    command.upgrade(alembic_config, "head")


async def _create_user(config: Config, *, username: str, password: str, role: str) -> None:
    database = Database(config)
    try:
        async with database.session() as session:
            user = await accounts.create_user(session, username=username, password=password, role=role)
            await audit.record(session, actor="cli", action="user.create", target=user.username, detail={"role": role})
    finally:
        await database.dispose()
    print(f"Created {role} user {user.username!r}.")


async def _create_agent(config: Config, *, name: str) -> None:
    database = Database(config)
    try:
        async with database.session() as session:
            agent, token = await fleet.enroll_agent(session, name=name)
            await audit.record(session, actor="cli", action="agent.enroll", target=agent.name)
    finally:
        await database.dispose()
    print(f"Enrolled agent {agent.name!r}. This token is shown once:\n")
    print(f"  TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer {token}")


async def _unlock_user(config: Config, *, username: str) -> None:
    database = Database(config)
    try:
        async with database.session() as session:
            user = await accounts.unlock_by_name(session, username=username)
            if user is None:
                raise DomainError(f"No user named {username!r}.")
            await audit.record(session, actor="cli", action="user.unlock", target=user.username)
    finally:
        await database.dispose()
    print(f"Unlocked {user.username!r}; it can sign in again.")


async def _check_schema(config: Config) -> None:
    database = Database(config)
    try:
        await database.check_schema()
    except (SQLAlchemyError, OSError) as error:
        # The driver's own message can carry connection details, so only its type is shown.
        raise SchemaError(f"Could not connect to the database ({type(error).__name__}). Check TGM_DATABASE_URL.") from error
    finally:
        await database.dispose()


async def _demo_data(config: Config, *, remove: bool, force: bool) -> None:
    database = Database(config)
    try:
        async with database.session() as session:
            if remove:
                removed = await demo.remove(session)
                await audit.record(session, actor="cli", action="demo.remove", detail={"agents": removed})
                report = f"Removed {removed} sample agent(s) and their alerts."
            else:
                summary = await demo.seed(
                    session,
                    now=utcnow(),
                    dialect=database.dialect,
                    offline_after=timedelta(seconds=config.agent_offline_seconds),
                    force=force,
                )
                await audit.record(
                    session, actor="cli", action="demo.seed", detail={"agents": summary.agents, "alerts": summary.alerts}
                )
                report = (
                    f"Added {summary.agents} sample agents ({demo.DEMO_PREFIX}...) and {summary.alerts} alerts.\n"
                    "Remove them again with: traceguard-manager demo-data --remove"
                )
    finally:
        await database.dispose()
    print(report)


def _serve(config: Config, args: argparse.Namespace) -> None:
    import uvicorn

    # Fail here with one clear line instead of serving 500s from an unmigrated database.
    asyncio.run(_check_schema(config))
    uvicorn.run(
        "traceguard_manager.asgi:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        # Forwarded headers are only honoured from proxies the operator names explicitly.
        proxy_headers=bool(args.trust_proxy),
        forwarded_allow_ips=args.trust_proxy or None,
        server_header=False,
        date_header=True,
        log_level=config.log_level.lower(),
        access_log=False,
        timeout_keep_alive=15,
        limit_concurrency=1000,
        h11_max_incomplete_event_size=16 * 1024,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "policy-key":
        return _policy_key(args)
    try:
        config = Config.from_env()
        match args.command:
            case "serve":
                _serve(config, args)
            case "migrate":
                _migrate(config)
                print("Database schema is up to date.")
            case "create-user":
                password = _read_password(from_stdin=args.password_stdin)
                asyncio.run(_create_user(config, username=args.username, password=password, role=args.role))
            case "create-agent":
                asyncio.run(_create_agent(config, name=args.name))
            case "unlock-user":
                asyncio.run(_unlock_user(config, username=args.username))
            case "demo-data":
                asyncio.run(_demo_data(config, remove=args.remove, force=args.force))
    except (ConfigError, DomainError, SchemaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
