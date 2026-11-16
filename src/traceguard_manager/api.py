"""Agent-facing ingest API.

This is a separate Flasgo application from the dashboard on purpose. Agents
authenticate with a bearer token and never with cookies, so browser CSRF
protection does not apply here; the dashboard keeps CSRF fully enabled.
"""

import logging

from flasgo import Flasgo, HasScope, IsAuthenticated, Request, Response, User, abort, bearer_token_backend

from . import fleet
from .config import Config
from .db import Database
from .ingest import parse_batch
from .models import utcnow
from .signals import ChangeSignal
from .webconfig import SECURITY_HEADERS

logger = logging.getLogger("traceguard_manager.api")

# TraceGuard never sends a batch above 1 MiB; anything larger is not an agent.
MAX_BATCH_BYTES = 1_048_576 + 1_024
INGEST_SCOPE = "events:write"


def create_api_app(config: Config, database: Database, signal: ChangeSignal) -> Flasgo:
    app = Flasgo(
        settings={
            "DEBUG": False,
            "SECRET_KEY": config.secret_key,
            "ALLOWED_HOSTS": set(config.allowed_hosts),
            "CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": config.secure_cookies,
            "CSRF_COOKIE_SECURE": config.secure_cookies,
            "MAX_REQUEST_BODY_BYTES": MAX_BATCH_BYTES,
            "LOG_FORMAT": config.log_format,
            "LOG_LEVEL": config.log_level,
            "SECURITY_HEADERS": dict(SECURITY_HEADERS),
            "API_TITLE": "TraceGuard Manager ingest API",
        }
    )

    async def validate_token(token: str) -> User | None:
        async with database.session() as session:
            agent = await fleet.agent_for_token(session, token)
        if agent is None:
            return None
        return User(
            id=str(agent.id),
            is_authenticated=True,
            scopes=frozenset({INGEST_SCOPE}),
            data={"agent_id": agent.id, "name": agent.name},
        )

    app.register_auth_backend("agent", bearer_token_backend(validate_token))

    def agent_key(request: Request) -> str | None:
        return request.user.id if request.user else request.client_ip

    @app.post("/api/v1/events", name="ingest")
    @app.authorize(IsAuthenticated(), HasScope(INGEST_SCOPE), backend="agent")
    @app.ratelimit(config.ingest_requests_per_minute, per=60, key_func=agent_key)
    async def ingest(request: Request) -> Response:
        """Accept one TraceGuard export batch (a JSON array of event records)."""
        if request.content_type.partition(";")[0].strip().lower() != "application/json":
            abort(415, "Content-Type must be application/json.")
        payload = await request.json()
        if not isinstance(payload, list):
            abort(400, "Request body must be a JSON array of event records.")
        if len(payload) > config.ingest_max_records:
            abort(413, f"A batch may hold at most {config.ingest_max_records} records.")

        user = request.user
        assert user is not None  # guaranteed by the authorize decorator
        now = utcnow()
        batch = parse_batch(payload, now=now)
        async with database.session() as session:
            result = await fleet.store_batch(
                session, agent_id=user.data["agent_id"], batch=batch, now=now, dialect=database.dialect
            )
        if result.stored:
            signal.notify()
        if batch.invalid:
            logger.warning(
                "ingest dropped malformed records agent=%s invalid=%d request_id=%s",
                user.id,
                batch.invalid,
                request.request_id,
            )
        return Response.json(
            {
                "received": batch.received,
                "stored": result.stored,
                "duplicates": result.duplicates,
                "ignored": batch.ignored,
                "invalid": batch.invalid,
            }
        )

    return app
