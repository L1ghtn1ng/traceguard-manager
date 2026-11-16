"""Dashboard application: sessions, rendering, error handling and background work.

The pages themselves live in ``routes/``; each module registers its routes on
the application built here.
"""

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from flasgo import (
    EventSourceResponse,
    Flasgo,
    HasScope,
    Header,
    HTTPException,
    IsAuthenticated,
    Request,
    RequestValidationError,
    Response,
    ServerSentEvent,
    abort,
    is_safe_redirect_target,
)
from flasgo import User as Principal
from sqlalchemy import text

from . import __version__, accounts, alerts, audit, fleet, mutes, notify
from .config import Config
from .db import Database, SchemaError
from .errors import DomainError
from .models import utcnow
from .routes import account as account_routes
from .routes import admin as admin_routes
from .routes import alerts as alert_routes
from .routes import fleet as fleet_routes
from .signals import ChangeSignal
from .webconfig import SECURITY_HEADERS
from .webcontext import BACKGROUND_HEADER, CurrentUser, Web

logger = logging.getLogger("traceguard_manager.web")

PACKAGE_DIR = Path(__file__).resolve().parent
MAX_LIVE_STREAMS = 200
STREAM_POLL_SECONDS = 5.0
# Streams are re-authenticated when they reconnect, so keep each one short-lived.
STREAM_MAX_SECONDS = 600
MAINTENANCE_INTERVAL_SECONDS = 3600
# How often the fleet is checked for agents that have gone quiet.
WATCH_INTERVAL_SECONDS = 60
# Requests a page makes by itself. They must not keep an unattended session alive.
BACKGROUND_PATHS = frozenset({"/stream", "/auth/session"})
PASSWORD_CHANGE_REQUIRED = "Choose a new password before doing anything else."  # noqa: S105 - a message, not a password

STATUS_TEXT = {
    400: "Bad request",
    401: "Sign in required",
    403: "You do not have access to this page",
    404: "Page not found",
    405: "Method not allowed",
    413: "Request too large",
    422: "Invalid request",
    429: "Too many requests",
    500: "Something went wrong",
    503: "Service unavailable",
}


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


def _ago(value: datetime | None, now: datetime) -> str:
    if value is None:
        return "never"
    seconds = max(int((now - value).total_seconds()), 0)
    for size, unit in ((86_400, "d"), (3_600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return "just now" if seconds < 10 else f"{seconds}s ago"


def _duration(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    days, rest = divmod(seconds, 86_400)
    hours, rest = divmod(rest, 3_600)
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h {rest // 60}m" if hours else f"{rest // 60}m"


def _datetime(value: datetime | None) -> str:
    return "-" if value is None else value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def create_web_app(
    config: Config, database: Database, signal: ChangeSignal, *, transport: notify.Transport | None = None
) -> Flasgo:
    app = Flasgo(
        settings={
            "DEBUG": config.debug,
            "SECRET_KEY": config.secret_key,
            "ALLOWED_HOSTS": set(config.allowed_hosts),
            "CSRF_ENABLED": True,
            "CSRF_CHECK_ORIGIN": True,
            "CSRF_REQUIRE_ORIGIN": True,
            "CSRF_TRUSTED_ORIGINS": set(config.csrf_trusted_origins),
            "CSRF_COOKIE_SECURE": config.secure_cookies,
            "SESSION_COOKIE_SECURE": config.secure_cookies,
            "SESSION_COOKIE_HTTP_ONLY": True,
            "SESSION_COOKIE_SAME_SITE": "Lax",
            "SESSION_COOKIE_MAX_AGE": config.session_absolute_seconds,
            "MAX_REQUEST_BODY_BYTES": 64 * 1024,
            "LOG_FORMAT": config.log_format,
            "LOG_LEVEL": config.log_level,
            "SECURITY_HEADERS": dict(SECURITY_HEADERS),
            "ENABLE_DOCS": False,
        }
    )
    app.configure_templates(
        PACKAGE_DIR / "templates",
        filters={
            "datetime": _datetime,
            "ago": lambda value: _ago(value, utcnow()),
            "duration": _duration,
            "pretty_json": _pretty_json,
            "level": alerts.level_for_severity,
        },
        globals={"app_version": __version__},
    )
    app.configure_static(PACKAGE_DIR / "static", url_path="/static", cache_max_age=3600)
    offline_after = timedelta(seconds=config.agent_offline_seconds)
    sender = transport or notify.NetworkTransport(config)
    live_streams = 0

    # ---- authentication -------------------------------------------------

    async def session_backend(request: Request) -> Principal | None:
        token = request.session.get("sid") if request.session is not None else None
        if not isinstance(token, str) or not token:
            return None
        background = request.path in BACKGROUND_PATHS or BACKGROUND_HEADER in request.headers
        async with database.session() as session:
            user = await accounts.resolve_session(session, config, token, touch=not background)
        if user is None:
            return None
        return Principal(
            id=str(user.id),
            is_authenticated=True,
            # Until a password chosen by someone else is replaced, the session can do nothing
            # but change it: no scope means every other route answers 403.
            scopes=frozenset() if user.must_change_password else accounts.ROLE_SCOPES.get(user.role, frozenset()),
            data={
                "user_id": user.id,
                "username": user.username,
                "role": user.role,
                "must_change": user.must_change_password,
            },
        )

    app.register_auth_backend("session", session_backend)

    def requires(*scopes: str) -> Any:
        return app.authorize(IsAuthenticated(), *(HasScope(scope) for scope in scopes), backend="session")

    def current(request: Request) -> CurrentUser:
        principal = request.user
        if principal is None or not principal.is_authenticated:
            abort(401)
        return CurrentUser(
            id=principal.data["user_id"],
            username=principal.data["username"],
            role=principal.data["role"],
            scopes=principal.scopes,
            must_change=bool(principal.data.get("must_change")),
        )

    def must_change_password(request: Request) -> bool:
        principal = request.user
        return bool(principal is not None and principal.is_authenticated and principal.data.get("must_change"))

    # ---- rendering ------------------------------------------------------

    def render(request: Request, template: str, *, status_code: int = 200, **context: Any) -> Response:
        now = utcnow()
        principal = request.user
        user = current(request) if principal is not None and principal.is_authenticated else None
        base: dict[str, Any] = {
            "current": user,
            "path": request.path,
            "now": now,
            "ago": lambda value: _ago(value, now),
        }
        return Response.template(template, templates=app.templates, context=base | context, status_code=status_code)

    def error_response(request: Request, status_code: int, detail: str | None = None) -> Response:
        message = detail or STATUS_TEXT.get(status_code, "Request failed")
        if _wants_html(request) and request.method in {"GET", "HEAD"}:
            return render(
                request,
                "error.html",
                status_code=status_code,
                status=status_code,
                message=STATUS_TEXT.get(status_code, "Request failed"),
                request_id=request.request_id,
            )
        return Response.json({"error": message, "request_id": request.request_id}, status_code=status_code)

    async def log_action(
        request: Request,
        action: str,
        *,
        actor: str | None = None,
        target: str | None = None,
        outcome: str = "success",
        detail: dict[str, Any] | None = None,
    ) -> None:
        if actor is None:
            actor = current(request).username
        async with database.session() as session:
            await audit.record(
                session,
                actor=actor,
                action=action,
                target=target,
                outcome=outcome,
                client_ip=request.client_ip,
                request_id=request.request_id,
                detail=detail,
            )

    @app.after_request
    def present_denials(request: Request, response: Response) -> Response:
        """Give browsers a sign-in redirect or an error page instead of bare text."""
        if response.status_code not in {401, 403, 404, 405} or request.path.startswith("/static/"):
            return response
        html_page = _wants_html(request) and request.method in {"GET", "HEAD"}
        if response.status_code == 403 and must_change_password(request):
            if html_page:
                return Response.redirect("/account", status_code=303)
            return Response.json({"error": PASSWORD_CHANGE_REQUIRED, "request_id": request.request_id}, status_code=403)
        if not html_page:
            if response.content_type.startswith("application/json"):
                return response
            return error_response(request, response.status_code)
        if response.status_code == 401:
            target = request.path + (f"?{request.query_string}" if request.query_string else "")
            query = urlencode({"next": target}) if target != "/" and is_safe_redirect_target(target) else ""
            return Response.redirect(f"/login?{query}" if query else "/login", status_code=303)
        return error_response(request, response.status_code)

    @app.errorhandler(Exception)
    def handle_error(request: Request, error: Exception) -> Response:
        """Fail closed: specific messages only for errors written for the user."""
        match error:
            case DomainError():
                return Response.json({"error": str(error)}, status_code=400)
            case RequestValidationError():
                return Response.json(
                    {"error": "Some fields are missing or invalid.", "request_id": request.request_id},
                    status_code=422,
                )
            case HTTPException():
                response = error_response(request, error.status_code)
                response.headers.update({key.lower(): value for key, value in error.headers.items()})
                return response
            case _:
                logger.exception("unhandled error request_id=%s path=%s", request.request_id, request.path)
                return error_response(request, 500)

    # ---- lifecycle ------------------------------------------------------

    async def run_maintenance() -> None:
        """Enforce retention so storage stays bounded."""
        while True:
            try:
                now = utcnow()
                async with database.session() as session:
                    removed = await alerts.purge_older_than(session, cutoff=now - timedelta(days=config.alert_retention_days))
                    await accounts.purge_expired_sessions(session, config, now=now)
                    await mutes.purge_expired(session, now=now)
                if removed:
                    logger.info("retention removed %d alerts", removed)
            except Exception:
                # Keep the loop alive; a failed pass is retried on the next interval.
                logger.exception("maintenance pass failed")
            await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)

    async def watch_fleet() -> None:
        """Raise an alert when an agent stops reporting, so silence is noticed."""
        while True:
            try:
                async with database.session() as session:
                    raised = await fleet.raise_offline_alerts(
                        session, now=utcnow(), offline_after=offline_after, dialect=database.dialect
                    )
                if raised:
                    signal.notify()
            except Exception:
                logger.exception("fleet watch pass failed")
            await asyncio.sleep(WATCH_INTERVAL_SECONDS)

    @app.lifespan
    async def lifespan(_: Flasgo) -> AsyncGenerator[None]:
        try:
            await database.check_schema()
        except SchemaError as error:
            logger.error("refusing to start: %s", error)
            raise
        tasks = [
            asyncio.create_task(run_maintenance(), name="traceguard-manager-maintenance"),
            asyncio.create_task(watch_fleet(), name="traceguard-manager-fleet-watch"),
            asyncio.create_task(notify.run(database, config, signal, transport=sender), name="traceguard-manager-notify"),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await database.dispose()

    # ---- routes ---------------------------------------------------------

    @app.get("/healthz", public=True, name="healthz")
    async def healthz() -> Response:
        try:
            async with database.session() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            logger.exception("health check failed")
            return Response.json({"status": "unavailable"}, status_code=503)
        return Response.json({"status": "ok"})

    web = Web(
        app=app,
        config=config,
        database=database,
        signal=signal,
        transport=sender,
        offline_after=offline_after,
        requires=requires,
        current=current,
        render=render,
        log_action=log_action,
    )
    account_routes.register(web, session_backend=session_backend)
    alert_routes.register(web)
    fleet_routes.register(web)
    admin_routes.register(web)

    @app.get("/stream", name="stream")
    @requires("alerts:read")
    async def stream(
        last_event_id: Annotated[str | None, Header(alias="last-event-id")] = None,
    ) -> EventSourceResponse:
        """Server-sent events announcing new alerts."""
        nonlocal live_streams
        if live_streams >= MAX_LIVE_STREAMS:
            abort(503, "Too many live connections.")
        cursor: uuid.UUID | None = None
        if last_event_id:
            with contextlib.suppress(ValueError):
                cursor = uuid.UUID(last_event_id)
        if cursor is None:
            # Fix the starting point before the response begins, so an alert stored
            # while the stream is still opening is delivered rather than skipped.
            async with database.session() as session:
                cursor = await alerts.latest_alert_id(session) or uuid.UUID(int=0)

        async def events() -> AsyncIterator[ServerSentEvent]:
            nonlocal live_streams, cursor
            live_streams += 1
            try:
                while True:
                    async with database.session() as session:
                        fresh = await alerts.alerts_after(session, cursor)
                    for alert in fresh:
                        cursor = alert.id
                        yield ServerSentEvent(
                            {
                                "id": str(alert.id),
                                "title": alert.title,
                                "level": alerts.level_for_severity(alert.severity),
                                "severity": alert.severity,
                                "hostname": alert.hostname,
                                "kind": alert.kind,
                            },
                            event="alert",
                            id=str(alert.id),
                        )
                    # Wake early when this process stores an alert; otherwise poll, which
                    # also covers alerts stored by other worker processes.
                    with contextlib.suppress(TimeoutError):
                        async with asyncio.timeout(STREAM_POLL_SECONDS):
                            await signal.wait()
            finally:
                live_streams -= 1

        return EventSourceResponse(events(), heartbeat=15, max_duration=STREAM_MAX_SECONDS)

    return app
