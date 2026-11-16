"""Command line: serve, migrate, and bootstrap accounts and agents."""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, accounts, audit, fleet
from .config import Config, ConfigError
from .db import Database
from .errors import DomainError
from .models import Role

PACKAGE_DIR = Path(__file__).resolve().parent


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

    agent = commands.add_parser("create-agent", help="Enrol an agent and print its token once")
    agent.add_argument("name")
    return parser


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
    alembic_config.set_main_option("script_location", str(PACKAGE_DIR / "migrations"))
    alembic_config.attributes["database_url"] = config.database_url
    command.upgrade(alembic_config, "head")


async def _create_user(config: Config, *, username: str, password: str, role: str) -> None:
    database = Database(config)
    try:
        async with database.session() as session:
            user = await accounts.create_user(session, username=username, password=password, role=role)
            await audit.record(
                session, actor="cli", action="user.create", target=user.username, detail={"role": role}
            )
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


def _serve(config: Config, args: argparse.Namespace) -> None:
    import uvicorn

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
    except (ConfigError, DomainError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
