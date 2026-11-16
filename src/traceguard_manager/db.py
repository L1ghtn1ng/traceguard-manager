"""Async database engine and session handling."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import Config
from .models import Base


class Database:
    """Owns the engine for one process.

    Queries go through SQLAlchemy Core/ORM constructs only, so every value is
    sent as a bound parameter.
    """

    def __init__(self, config: Config) -> None:
        options: dict[str, Any] = {"pool_pre_ping": True, "pool_recycle": 1800}
        # SQLite allows one writer at a time, so a large pool only adds lock contention.
        options |= (
            {"pool_size": 5, "max_overflow": 5} if config.is_sqlite else {"pool_size": 10, "max_overflow": 20}
        )
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
        """Create the schema directly. Tests use this; deployments run migrations."""
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()


def _configure_sqlite(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()
