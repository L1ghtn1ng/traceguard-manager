"""Async database engine and session handling."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import Connection, event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import Config
from .models import Base

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


class SchemaError(RuntimeError):
    """The database schema does not match this version. The message says what to run."""


class Database:
    """Owns the engine for one process.

    Queries go through SQLAlchemy Core/ORM constructs only, so every value is
    sent as a bound parameter.
    """

    def __init__(self, config: Config) -> None:
        options: dict[str, Any] = {"pool_pre_ping": True, "pool_recycle": 1800}
        # SQLite allows one writer at a time, so a large pool only adds lock contention.
        options |= {"pool_size": 5, "max_overflow": 5} if config.is_sqlite else {"pool_size": 10, "max_overflow": 20}
        self.engine: AsyncEngine = create_async_engine(config.database_url, **options)
        self.dialect: str = self.engine.dialect.name
        if config.is_sqlite:
            event.listen(self.engine.sync_engine, "connect", _configure_sqlite)
        self._sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession]:
        """Yield a session that commits on success and rolls back on any error."""
        async with self._sessions() as session, session.begin():
            yield session

    async def create_all(self) -> None:
        """Create the current schema directly and mark it as migrated.

        Tests use this; deployments run migrations.
        """
        async with self.engine.begin() as connection:
            await connection.run_sync(_create_current_schema)

    async def check_schema(self) -> None:
        """Raise SchemaError unless the database is at the revision this version ships.

        Without this, a server started before ``migrate`` answers every request
        with a 500 and the reason is only visible in the logs.
        """
        scripts = ScriptDirectory(str(MIGRATIONS_DIR))
        expected = scripts.get_current_head()
        async with self.engine.connect() as connection:
            found = await connection.run_sync(_current_revision)
        if found == expected:
            return
        if found is None:
            raise SchemaError("The database has no schema yet. Run `traceguard-manager migrate`, then start the server again.")
        try:
            scripts.get_revision(found)
        except CommandError:
            raise SchemaError(
                f"The database schema (revision {found}) is newer than this version of TraceGuard Manager "
                f"(revision {expected}). Upgrade the manager rather than downgrading the database."
            ) from None
        raise SchemaError(
            f"The database schema is at revision {found} but this version needs {expected}. "
            "Run `traceguard-manager migrate`, then start the server again."
        )

    async def dispose(self) -> None:
        await self.engine.dispose()


def _create_current_schema(connection: Connection) -> None:
    Base.metadata.create_all(connection)
    MigrationContext.configure(connection).stamp(ScriptDirectory(str(MIGRATIONS_DIR)), "head")


def _current_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


def _configure_sqlite(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()
