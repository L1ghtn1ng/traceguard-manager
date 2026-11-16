"""ASGI entry point.

Run with ``uvicorn traceguard_manager.asgi:app`` or ``traceguard-manager serve``.
"""

import logging
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from flasgo import Flasgo, FlasgoJSONFormatter, configure_logging

from .api import create_api_app
from .config import Config
from .db import Database
from .signals import ChangeSignal
from .web import create_web_app

type Scope = MutableMapping[str, Any]
type Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
type Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

API_PREFIX = "/api/v1"


@dataclass(frozen=True, slots=True)
class Manager:
    """Routes agent traffic to the ingest API and everything else to the dashboard.

    The two applications have different trust models (bearer tokens versus
    browser sessions), so each keeps its own security settings. The dashboard
    owns the process lifespan, including the database engine.
    """

    config: Config
    database: Database
    signal: ChangeSignal
    web: Flasgo
    api: Flasgo

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and (path == API_PREFIX or path.startswith(f"{API_PREFIX}/")):
            await self.api(scope, receive, send)  # ty: ignore[invalid-argument-type]
        else:
            await self.web(scope, receive, send)  # ty: ignore[invalid-argument-type]


def _configure_logging(config: Config) -> None:
    """Send framework and application logs to stderr in one format."""
    configure_logging(level=config.log_level, format=config.log_format)
    logger = logging.getLogger("traceguard_manager")
    logger.setLevel(config.log_level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            FlasgoJSONFormatter()
            if config.log_format == "json"
            else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False


def create_app(config: Config | None = None) -> Manager:
    config = config or Config.from_env()
    _configure_logging(config)
    database = Database(config)
    signal = ChangeSignal()
    return Manager(
        config=config,
        database=database,
        signal=signal,
        web=create_web_app(config, database, signal),
        api=create_api_app(config, database, signal),
    )


def __getattr__(name: str) -> Manager:
    """Build the application on first access so importing this module has no side effects."""
    if name == "app":
        manager = create_app()
        globals()["app"] = manager
        return manager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
