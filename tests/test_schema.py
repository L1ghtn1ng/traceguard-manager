"""The server refuses to start against a database that has not been migrated."""

from pathlib import Path

import pytest
from flasgo import TestClient
from sqlalchemy import text

from traceguard_manager import cli
from traceguard_manager.asgi import create_app
from traceguard_manager.config import Config
from traceguard_manager.db import Database, SchemaError


async def test_empty_database_is_reported_with_the_fix(config: Config) -> None:
    database = Database(config)
    try:
        with pytest.raises(SchemaError, match="traceguard-manager migrate"):
            await database.check_schema()
    finally:
        await database.dispose()


async def test_directly_created_schema_counts_as_current(config: Config) -> None:
    database = Database(config)
    try:
        await database.create_all()
        await database.check_schema()
    finally:
        await database.dispose()


async def test_outdated_and_unknown_revisions_are_told_apart(config: Config) -> None:
    database = Database(config)
    try:
        await database.create_all()
        async with database.session() as session:
            await session.execute(text("UPDATE alembic_version SET version_num = 'from-the-future'"))
        with pytest.raises(SchemaError, match="newer than this version"):
            await database.check_schema()
    finally:
        await database.dispose()


async def test_application_startup_fails_without_a_schema(config: Config) -> None:
    manager = create_app(config)
    try:
        # The framework reports a failed startup generically; the reason is in the log.
        with pytest.raises(RuntimeError, match="startup failed"):
            async with TestClient(manager.web):
                pass
    finally:
        await manager.database.dispose()


def test_migrate_then_serve_check_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TGM_SECRET_KEY", "k" * 48)
    monkeypatch.setenv("TGM_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")
    served: list[bool] = []
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: served.append(True))

    assert cli.main(["serve"]) == 2
    assert "traceguard-manager migrate" in capsys.readouterr().err
    assert served == []

    assert cli.main(["migrate"]) == 0
    assert cli.main(["serve"]) == 0
    assert served == [True]
