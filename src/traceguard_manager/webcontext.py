"""What the dashboard's route modules share: the signed-in user and the handles they need."""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from flasgo import Flasgo, Request, Response, abort

from .commands import Bell
from .config import Config
from .db import Database
from .notify import Transport
from .policies import Signer
from .signals import ChangeSignal

# Sent by requests the page makes by itself, so they do not count as the person being active.
BACKGROUND_HEADER = "x-tgm-background"


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: uuid.UUID
    username: str
    role: str
    scopes: frozenset[str]
    # True while the password was chosen by someone else and must be replaced.
    must_change: bool = False


class LogAction(Protocol):
    def __call__(
        self,
        request: Request,
        action: str,
        *,
        actor: str | None = None,
        target: str | None = None,
        outcome: str = "success",
        detail: dict[str, Any] | None = None,
    ) -> Awaitable[None]: ...


class Render(Protocol):
    def __call__(self, request: Request, template: str, *, status_code: int = 200, **context: Any) -> Response: ...


@dataclass(frozen=True, slots=True)
class Web:
    """Everything a route module needs from the application it is registered on."""

    app: Flasgo
    config: Config
    database: Database
    signal: ChangeSignal
    transport: Transport
    offline_after: timedelta
    requires: Callable[..., Any]
    current: Callable[[Request], CurrentUser]
    render: Render
    log_action: LogAction
    # None until TGM_POLICY_SIGNING_KEY_FILE is set.
    signer: Signer | None
    bell: Bell


def parse_uuid(value: str) -> uuid.UUID:
    """Identifiers arrive in URLs; anything that is not one is simply not found."""
    try:
        return uuid.UUID(value)
    except ValueError:
        abort(404)


def query_params(request: Request) -> dict[str, str]:
    """The first value of each query parameter."""
    return {name: values[0] for name, values in request.query_params.items() if values}


def page_number(params: dict[str, str], maximum: int) -> int:
    raw = params.get("page", "1")
    return min(max(int(raw), 1), maximum) if raw.isdigit() else 1


def page_count(total: int, size: int) -> int:
    return max((total + size - 1) // size, 1)
