"""Agent-facing ingest API.

This is a separate Flasgo application from the dashboard on purpose. Agents
authenticate with a bearer token and never with cookies, so browser CSRF
protection does not apply here; the dashboard keeps CSRF fully enabled.
"""

import asyncio
import json
import logging
import uuid
from datetime import timedelta

from flasgo import Flasgo, HasScope, IsAuthenticated, Request, Response, User, abort, bearer_token_backend
from sqlalchemy import select

from . import commands, fleet, policies
from .config import Config
from .db import Database
from .ingest import parse_batch
from .models import Agent, AgentCommand, utcnow
from .signals import ChangeSignal
from .webconfig import SECURITY_HEADERS

logger = logging.getLogger("traceguard_manager.api")

# TraceGuard never sends a batch above 1 MiB; anything larger is not an agent.
MAX_BATCH_BYTES = 1_048_576 + 1_024
INGEST_SCOPE = "events:write"
POLICY_SCOPE = "policy:read"
COMMAND_SCOPE = "commands:poll"
# How often a waiting poll re-checks the database, for commands queued by
# another worker process.
POLL_RECHECK_SECONDS = 5.0
MAX_RESULT_BYTES = 4_096
# How long an agent over its hourly alert cap is asked to wait before resending.
ALERT_CAP_RETRY_SECONDS = 300


def _delivery(header: str | None) -> str | None:
    """How the agent sent the batch, from TraceGuard's TraceGuard-Delivery header."""
    value = (header or "").strip().lower()
    return value if value in {fleet.DELIVERY_LIVE, fleet.DELIVERY_REPLAY} else None


def _run_header(header: str | None) -> str | None:
    """The sending process's run ID, from TraceGuard's TraceGuard-Run header."""
    value = (header or "").strip().lower()
    return value if len(value) == 32 and all(char in "0123456789abcdef" for char in value) else None


def create_api_app(
    config: Config,
    database: Database,
    signal: ChangeSignal,
    *,
    signer: policies.Signer | None = None,
    bell: commands.Bell | None = None,
) -> Flasgo:
    app = Flasgo(
        settings={
            "DEBUG": False,
            "SECRET_KEY": config.secret_key,
            "ALLOWED_HOSTS": set(config.allowed_hosts),
            "CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": config.secure_cookies,
            "CSRF_COOKIE_SECURE": config.secure_cookies,
            "MAX_REQUEST_BODY_BYTES": MAX_BATCH_BYTES,
            # Off: it throttles a client IP after bad tokens before checking any
            # token, so junk from one address would lock out every agent that
            # shares it (a NAT, or a proxy). A 256-bit token cannot be guessed,
            # and each agent keeps its own rate limit.
            "SECURITY_FAILURE_RATE_LIMIT": 0,
            "LOG_FORMAT": config.log_format,
            "LOG_LEVEL": config.log_level,
            "SECURITY_HEADERS": dict(SECURITY_HEADERS),
            "API_TITLE": "TraceGuard Manager ingest API",
        }
    )

    offline_after = timedelta(seconds=config.agent_offline_seconds)

    async def validate_token(token: str) -> User | None:
        async with database.session() as session:
            agent = await fleet.agent_for_token(session, token)
        if agent is None:
            return None
        return User(
            id=str(agent.id),
            is_authenticated=True,
            scopes=frozenset({INGEST_SCOPE, POLICY_SCOPE, COMMAND_SCOPE}),
            data={
                "agent_id": agent.id,
                "name": agent.name,
                "last_seen_at": agent.last_seen_at,
                "token_hash": agent.token_hash,
            },
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
        over_cap = False
        async with database.session() as session:
            cap = config.ingest_max_alerts_per_hour
            if cap and batch.alerts:
                stored = await fleet.alerts_in_last_hour(session, agent_id=user.data["agent_id"], now=now)
                if stored + len(batch.alerts) > cap:
                    # One agent cannot fill the database or flood operators. Its
                    # health and stop records still count; the alerts are refused
                    # with a 429, so TraceGuard spools them and sends them later.
                    over_cap = True
                    batch.alerts = []
            result = await fleet.store_batch(
                session,
                agent_id=user.data["agent_id"],
                batch=batch,
                now=now,
                dialect=database.dialect,
                delivery=_delivery(request.headers.get("traceguard-delivery")),
                sender_run=_run_header(request.headers.get("traceguard-run")),
            )
            last_seen = user.data["last_seen_at"]
            if last_seen is not None and now - last_seen > offline_after:
                await fleet.resolve_offline_alerts(session, agent_id=user.data["agent_id"], now=now)
        if result.stored or batch.stopping is not None:
            signal.notify()
        if over_cap:
            logger.warning("ingest over the hourly alert cap agent=%s cap=%d request_id=%s", user.id, cap, request.request_id)
            return Response.json(
                {"error": f"This agent has stored {cap} alerts in the past hour; send the rest later."},
                status_code=429,
                headers={"retry-after": str(ALERT_CAP_RETRY_SECONDS)},
            )
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

    bell = bell or commands.Bell()

    def no_central_policy() -> Response:
        return Response.json({"error": "Central policy is not enabled on this manager."}, status_code=404)

    @app.get("/api/v1/policy", name="policy")
    @app.authorize(IsAuthenticated(), HasScope(POLICY_SCOPE), backend="agent")
    @app.ratelimit(60, per=60, key_func=agent_key)
    async def policy(request: Request) -> Response:
        """The agent's signed TraceGuard policy, for TRACEGUARD_POLICY_URL."""
        if signer is None:
            return no_central_policy()
        assert request.user is not None
        async with database.session() as session:
            agent = await session.get(Agent, uuid.UUID(request.user.id))
            if agent is None:
                abort(404)
            chosen = await policies.policy_for_agent(session, agent)
            sha256 = chosen.sha256 if chosen is not None else policies.EMPTY_POLICY_SHA256
            agent.policy_served_sha256 = sha256
            agent.policy_fetched_at = utcnow()
            etag = f'"{sha256}"'
            headers = {"etag": etag, "cache-control": "no-store"}
            if etag in {tag.strip() for tag in request.headers.get("if-none-match", "").split(",")}:
                # Unchanged: answered from metadata, without reading the document.
                return Response(body=b"", status_code=304, headers=headers)
            content, sha256 = await policies.content_of(session, chosen)
            agent.policy_served_sha256 = sha256
        # The ETag comes from the same read as the document it describes.
        headers["etag"] = f'"{sha256}"'
        return Response(body=content.encode(), headers=headers, content_type="application/yaml")

    @app.get("/api/v1/policy.sig", name="policy-signature")
    @app.authorize(IsAuthenticated(), HasScope(POLICY_SCOPE), backend="agent")
    @app.ratelimit(60, per=60, key_func=agent_key)
    async def policy_signature(request: Request) -> Response:
        """The detached Ed25519 signature TraceGuard fetches beside the policy."""
        if signer is None:
            return no_central_policy()
        assert request.user is not None
        async with database.session() as session:
            agent = await session.get(Agent, uuid.UUID(request.user.id))
            if agent is None:
                abort(404)
            content, _ = await policies.content_of(session, await policies.policy_for_agent(session, agent))
        return Response(body=signer.sign(content).encode(), headers={"cache-control": "no-store"})

    @app.get("/api/v1/commands", name="commands-poll")
    @app.authorize(IsAuthenticated(), HasScope(COMMAND_SCOPE), backend="agent")
    @app.ratelimit(120, per=60, key_func=agent_key)
    async def poll_commands(request: Request) -> Response:
        """Long-poll: answer as soon as a command is waiting, or after ``wait`` seconds."""
        assert request.user is not None
        if request.method == "HEAD":
            # Flasgo answers HEAD with the GET handler; it must never claim
            # commands it would then not return.
            return Response(body=b"", status_code=204)
        agent_id = uuid.UUID(request.user.id)
        token_hash = request.user.data["token_hash"]
        raw_wait = (request.query_params.get("wait") or ["0"])[0]
        valid = raw_wait.isascii() and raw_wait.isdigit() and len(raw_wait) <= 4
        wait = min(int(raw_wait), commands.MAX_POLL_WAIT) if valid else 0
        # Reserved before any database work and held for the whole request,
        # so a burst of polls cannot all slip under the cap.
        if not bell.acquire(agent_id):
            # One agent needs one poll open; more is a misbehaving client.
            return Response.json({"error": "Too many polls are already waiting."}, status_code=429)
        gone = asyncio.Event()

        async def watch_disconnect() -> None:
            while True:
                message = await request.receive()
                if message.get("type") == "http.disconnect":
                    gone.set()
                    return

        watcher: asyncio.Task[None] | None = None
        try:
            # Inside the try, so a failed read still releases the slot.
            await request.body()
            # A client that goes away must not claim commands it cannot receive.
            if wait:
                watcher = asyncio.create_task(watch_disconnect())
            loop_time = asyncio.get_running_loop().time
            deadline = loop_time() + wait
            while True:
                if gone.is_set():
                    return Response(body=b"", status_code=204)
                async with database.session() as session:
                    # The token was checked when the poll began; a rotation or
                    # disable while it waits must stop it taking commands.
                    valid = (Agent.id == agent_id, Agent.enabled.is_(True), Agent.token_hash == token_hash)
                    if await session.scalar(select(Agent.id).where(*valid)) is None:
                        abort(401)
                    due: list[AgentCommand] = []
                    if await commands.has_due(session, agent_id=agent_id, now=utcnow()):
                        # Only now is the agent row locked, for the rest of the
                        # claim: a rotation or disable either lands first and
                        # stops it, or waits. An idle recheck takes no lock.
                        if await session.scalar(select(Agent.id).where(*valid).with_for_update()) is None:
                            abort(401)
                        # The lock may have been waited on; a client gone
                        # meanwhile must not claim anything.
                        if gone.is_set():
                            return Response(body=b"", status_code=204)
                        due = await commands.take(session, agent_id=agent_id, now=utcnow(), token_hash=token_hash)
                    payload = [commands.wire(command) for command in due]
                if payload:
                    signal.notify()
                    return Response.json({"commands": payload})
                remaining = deadline - loop_time()
                if remaining <= 0:
                    return Response(body=b"", status_code=204)
                await bell.wait(agent_id, min(remaining, POLL_RECHECK_SECONDS), stop=gone)
        finally:
            if watcher is not None:
                watcher.cancel()
            bell.release(agent_id)

    @app.post("/api/v1/commands/<command_id>/result", name="commands-result")
    @app.authorize(IsAuthenticated(), HasScope(COMMAND_SCOPE), backend="agent")
    @app.ratelimit(240, per=60, key_func=agent_key)
    async def command_result(request: Request, command_id: str) -> Response:
        """The agent's result for one command."""
        assert request.user is not None
        try:
            parsed_id = uuid.UUID(command_id)
        except ValueError:
            abort(404)
        body = await request.body()
        if len(body) > MAX_RESULT_BYTES:
            abort(413, "Result is too large.")
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            abort(400, "Result must be JSON.")
        if not isinstance(payload, dict) or not isinstance(payload.get("status"), str):
            abort(400, "Result must have a status.")
        detail = payload.get("detail")
        async with database.session() as session:
            try:
                command = await commands.record_result(
                    session,
                    agent_id=uuid.UUID(request.user.id),
                    command_id=parsed_id,
                    status=payload["status"],
                    detail=detail if isinstance(detail, str) else None,
                    now=utcnow(),
                )
            except commands.CommandError as exc:
                abort(400, str(exc))
        if command is None:
            abort(404)
        signal.notify()
        return Response(body=b"", status_code=204)

    return app
