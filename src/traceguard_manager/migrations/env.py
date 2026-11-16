"""Alembic environment using the application's async engine settings."""

import asyncio
import os
from typing import Literal

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from traceguard_manager.models import Base, UtcDateTime

target_metadata = Base.metadata


def _render_item(type_: str, obj: object, _autogen_context: object) -> str | Literal[False]:
    """Write the portable column type into migrations instead of the application's decorator."""
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def _database_url() -> str:
    url = context.config.attributes.get("database_url") or os.environ.get("TGM_DATABASE_URL", "")
    if not url:
        raise RuntimeError("Set TGM_DATABASE_URL before running migrations.")
    return url


def _configure(connection: Connection | None = None, url: str | None = None) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        literal_binds=connection is None,
        compare_type=True,
        render_item=_render_item,
        # SQLite cannot ALTER most things in place; batch mode rebuilds the table instead.
        render_as_batch=True,
    )


def run_migrations_offline() -> None:
    _configure(url=_database_url())
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_database_url(), poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
