"""Dashboard application: server-rendered pages plus small JSON actions."""

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from flasgo import (
    Body,
    EventSourceResponse,
    Flasgo,
    HasScope,
    Header,
    HTTPException,
    IsAuthenticated,
    Query,
    Request,
    RequestValidationError,
    Response,
    ServerSentEvent,
    abort,
    is_safe_redirect_target,
)
from flasgo import User as Principal
from sqlalchemy import text

from . import __version__, accounts, alerts, audit, charts, fleet, security
from .config import Config
from .db import Database, SchemaError
from .errors import DomainError
from .ingest import SEVERITIES
from .models import AlertKind, AlertStatus, Role, utcnow
from .signals import ChangeSignal
from .webconfig import SECURITY_HEADERS

logger = logging.getLogger("traceguard_manager.web")

PACKAGE_DIR = Path(__file__).resolve().parent
AUDIT_PAGE_SIZE = 50
MAX_LIVE_STREAMS = 200
STREAM_POLL_SECONDS = 5.0
# Streams are re-authenticated when they reconnect, so keep each one short-lived.
STREAM_MAX_SECONDS = 600
MAINTENANCE_INTERVAL_SECONDS = 3600
GENERIC_LOGIN_ERROR = "Invalid username or password."
# Shown in the alert header already, so left out of the field table.
DETAIL_HIDDEN_FIELDS = frozenset(
    {
        "timestamp",
        "level",
        "message",
        "hostname",
        "event",
        "severity",
        "source_event",
        "detection_message",
        "detection_rule_id",
        "tags",
        "mitre_tactics",
        "mitre_techniques",
    }
)

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


@dataclass(slots=True)
class LoginBody:
    username: str
    password: str
    next: str = "/"

    def __post_init__(self) -> None:
        if not 1 <= len(self.username) <= 64 or not 1 <= len(self.password) <= security.PASSWORD_MAX_LENGTH:
            raise ValueError("Username or password has an invalid length.")
        if len(self.next) > 512:
            raise ValueError("Redirect target is too long.")


@dataclass(slots=True)
class AlertStatusBody:
    ids: list[str]
    status: str
    note: str | None = None


@dataclass(slots=True)
class AgentCreateBody:
    name: str


@dataclass(slots=True)
class AgentEnabledBody:
    enabled: bool


@dataclass(slots=True)
class UserCreateBody:
    username: str
    password: str
    role: str


@dataclass(slots=True)
class UserUpdateBody:
    role: str | None = None
    is_active: bool | None = None


@dataclass(slots=True)
class PasswordResetBody:
    password: str


@dataclass(slots=True)
class PasswordChangeBody:
    current_password: str
    new_password: str


@dataclass(frozen=True, slots=True)
class Pivot:
    """An exact-match alert filter the list is narrowed by."""

    name: str
    label: str
    text: str
    value: str
    remove_url: str


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: uuid.UUID
    username: str
    role: str
    scopes: frozenset[str]


def _parse_uuid(value: str) -> uuid.UUID:
    """Parse a path identifier, answering 404 for anything that is not a UUID."""
    try:
        return uuid.UUID(value)
    except ValueError:
        abort(404)


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


def _hour_label(bucket: int | None) -> str | None:
    if bucket is None:
        return None
    return datetime.fromtimestamp(bucket * 3600, tz=UTC).strftime("%Y-%m-%d %H:00 UTC")


def _pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def create_web_app(config: Config, database: Database, signal: ChangeSignal) -> Flasgo:
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
            "duration": _duration,
            "pretty_json": _pretty_json,
            "level": alerts.level_for_severity,
        },
        globals={"app_version": __version__},
    )
    app.configure_static(PACKAGE_DIR / "static", url_path="/static", cache_max_age=3600)
    offline_after = timedelta(seconds=config.agent_offline_seconds)
    live_streams = 0

    # ---- authentication -------------------------------------------------

    async def session_backend(request: Request) -> Principal | None:
        token = request.session.get("sid") if request.session is not None else None
        if not isinstance(token, str) or not token:
            return None
        async with database.session() as session:
            user = await accounts.resolve_session(session, config, token)
        if user is None:
            return None
        return Principal(
            id=str(user.id),
            is_authenticated=True,
            scopes=accounts.ROLE_SCOPES.get(user.role, frozenset()),
            data={"user_id": user.id, "username": user.username, "role": user.role},
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
        )

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
        if not (_wants_html(request) and request.method in {"GET", "HEAD"}):
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
                if removed:
                    logger.info("retention removed %d alerts", removed)
            except Exception:
                # Keep the loop alive; a failed pass is retried on the next interval.
                logger.exception("maintenance pass failed")
            await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)

    @app.lifespan
    async def lifespan(_: Flasgo) -> AsyncGenerator[None]:
        try:
            await database.check_schema()
        except SchemaError as error:
            logger.error("refusing to start: %s", error)
            raise
        task = asyncio.create_task(run_maintenance(), name="traceguard-manager-maintenance")
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await database.dispose()

    # ---- public routes --------------------------------------------------

    @app.get("/healthz", public=True, name="healthz")
    async def healthz() -> Response:
        try:
            async with database.session() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            logger.exception("health check failed")
            return Response.json({"status": "unavailable"}, status_code=503)
        return Response.json({"status": "ok"})

    @app.get("/login", public=True, name="login")
    async def login_page(request: Request, next: Annotated[str, Query()] = "/") -> Response:
        if await session_backend(request) is not None:
            return Response.redirect("/", status_code=303)
        target = next if len(next) <= 512 and is_safe_redirect_target(next) else "/"
        return render(request, "login.html", next=target)

    @app.post("/auth/login", public=True, name="auth-login")
    @app.ratelimit(10, per=60, scope="login")
    async def login(request: Request, body: Annotated[LoginBody, Body()]) -> Response:
        username = accounts.normalise_username(body.username)
        token: str | None = None
        async with database.session() as session:
            result = await accounts.authenticate(session, config, username=username, password=body.password)
            if result.user is not None:
                token = await accounts.start_session(session, config, user=result.user, client_ip=request.client_ip)
        await log_action(
            request,
            "auth.login",
            actor=username if security.USERNAME_RE.fullmatch(username) else "invalid-username",
            outcome="success" if token else "failure",
            detail={"reason": result.reason},
        )
        if token is None or request.session is None:
            return Response.json({"error": GENERIC_LOGIN_ERROR}, status_code=401)
        # A brand-new session identifier is issued at sign-in, so a pre-login cookie is worthless.
        request.session.clear()
        request.session["sid"] = token
        target = body.next if is_safe_redirect_target(body.next) else "/"
        return Response.json({"redirect": target})

    # ---- session routes -------------------------------------------------

    @app.get("/auth/session", name="auth-session")
    @requires()
    async def session_state(request: Request) -> Response:
        """Lets an open page tell an ended session apart from a dropped connection."""
        return Response.json({"username": current(request).username})

    @app.post("/auth/logout", name="auth-logout")
    @requires()
    async def logout(request: Request) -> Response:
        user = current(request)
        if request.session is not None:
            token = request.session.get("sid")
            if isinstance(token, str):
                async with database.session() as session:
                    await accounts.end_session(session, token)
            request.session.clear()
        await log_action(request, "auth.logout", actor=user.username)
        return Response.json({"redirect": "/login"})

    @app.get("/", name="dashboard")
    @requires("alerts:read")
    async def dashboard(request: Request) -> Response:
        now = utcnow()
        async with database.session() as session:
            stats = await alerts.dashboard_stats(session, now=now)
            recent, _ = await alerts.list_alerts(session, alerts.AlertFilter(status=AlertStatus.OPEN.value))
            _, summary = fleet.describe_fleet(await fleet.list_agents(session), now=now, offline_after=offline_after)
        rule_peak = max((count for _, count in stats.top_rules), default=0)
        host_peak = max((count for _, count in stats.top_hosts), default=0)
        return render(
            request,
            "dashboard.html",
            stats=stats,
            recent=recent[:8],
            can_enrol="agents:write" in current(request).scopes,
            fleet=summary,
            levels=alerts.LEVELS,
            chart=charts.build_timeline(stats),
            chart_width=charts.CHART_WIDTH,
            chart_height=charts.CHART_HEIGHT,
            top_rules=[(name, count, charts.share(count, rule_peak)) for name, count in stats.top_rules],
            top_hosts=[(name, count, charts.share(count, host_peak)) for name, count in stats.top_hosts],
        )

    @app.get("/alerts", name="alerts")
    @requires("alerts:read")
    async def alert_list(
        request: Request,
        status: Annotated[str | None, Query()] = None,
        level: Annotated[str | None, Query()] = None,
        kind: Annotated[str | None, Query()] = None,
        agent: Annotated[str | None, Query()] = None,
        q: Annotated[str | None, Query()] = None,
        rule: Annotated[str | None, Query()] = None,
        host: Annotated[str | None, Query()] = None,
        hour: Annotated[int | None, Query()] = None,
        page: Annotated[int, Query()] = 1,
    ) -> Response:
        filters = alerts.AlertFilter.from_params(
            status=status, level=level, kind=kind, agent=agent, query=q, page=page, rule=rule, host=host, hour=hour
        )
        async with database.session() as session:
            rows, total = await alerts.list_alerts(session, filters)
            agents = await fleet.list_agents(session)
        params = {
            "status": filters.status,
            "level": filters.level,
            "kind": filters.kind,
            "agent": str(filters.agent_id) if filters.agent_id else None,
            "q": filters.query,
            "rule": filters.rule,
            "host": filters.host,
            "hour": str(filters.hour) if filters.hour is not None else None,
        }
        base_query = urlencode({key: value for key, value in params.items() if value})
        # Exact-match filters have no form control, so each is shown as a chip that removes it.
        pivot_text = {"rule": filters.rule, "host": filters.host, "hour": _hour_label(filters.hour)}

        def without(name: str) -> str:
            rest = urlencode({key: value for key, value in params.items() if value and key != name})
            return f"/alerts?{rest}" if rest else "/alerts"

        pivots = [
            Pivot(name=name, label=name.capitalize(), text=shown, value=params[name] or "", remove_url=without(name))
            for name, shown in pivot_text.items()
            if shown
        ]
        pages = max((total + alerts.PAGE_SIZE - 1) // alerts.PAGE_SIZE, 1)
        return render(
            request,
            "alerts.html",
            alerts=rows,
            total=total,
            filters=filters,
            pivots=pivots,
            agents=agents,
            agent_names={item.id: item.name for item in agents},
            page=filters.page,
            pages=pages,
            base_query=base_query,
            statuses=[item.value for item in AlertStatus],
            kinds=[item.value for item in AlertKind],
            levels=alerts.LEVELS,
        )

    @app.get("/alerts/<alert_id>", name="alert-detail")
    @requires("alerts:read")
    async def alert_detail(request: Request, alert_id: str) -> Response:
        async with database.session() as session:
            alert = await alerts.get_alert(session, _parse_uuid(alert_id))
            agent = await fleet.get_agent(session, alert.agent_id) if alert else None
        if alert is None:
            abort(404)
        details = sorted(
            (key, value)
            for key, value in alert.fields.items()
            if key not in DETAIL_HIDDEN_FIELDS and not isinstance(value, (dict, list))
        )
        return render(
            request,
            "alert_detail.html",
            alert=alert,
            agent=agent,
            details=details,
            statuses=[item.value for item in AlertStatus],
            severities=SEVERITIES,
        )

    @app.post("/alerts/status", name="alert-status")
    @requires("alerts:write")
    async def alert_status(request: Request, body: Annotated[AlertStatusBody, Body()]) -> Response:
        user = current(request)
        try:
            ids = [uuid.UUID(value) for value in body.ids[: alerts.MAX_BULK + 1]]
        except ValueError:
            raise alerts.AlertError("One of the selected alerts is not valid.") from None
        async with database.session() as session:
            changed = await alerts.set_status(
                session, alert_ids=ids, status=body.status, actor=user.username, note=body.note, now=utcnow()
            )
        await log_action(
            request,
            "alert.status",
            target=str(ids[0]) if len(ids) == 1 else f"{len(ids)} alerts",
            detail={"status": body.status, "changed": changed},
        )
        signal.notify()
        return Response.json({"changed": changed})

    @app.get("/agents", name="agents")
    @requires("agents:read")
    async def agent_list(request: Request, enrol: Annotated[str | None, Query()] = None) -> Response:
        now = utcnow()
        async with database.session() as session:
            views, summary = fleet.describe_fleet(await fleet.list_agents(session), now=now, offline_after=offline_after)
        return render(request, "agents.html", agents=views, fleet=summary, open_enrol=enrol is not None)

    @app.get("/agents/<agent_id>", name="agent-detail")
    @requires("agents:read")
    async def agent_detail(request: Request, agent_id: str) -> Response:
        now = utcnow()
        async with database.session() as session:
            everyone = await fleet.list_agents(session)
            recent = await alerts.recent_for_agent(session, _parse_uuid(agent_id))
        views, summary = fleet.describe_fleet(everyone, now=now, offline_after=offline_after)
        view = next((item for item in views if str(item.agent.id) == agent_id.lower()), None)
        if view is None:
            abort(404)
        return render(request, "agent_detail.html", view=view, agent=view.agent, fleet=summary, recent=recent)

    @app.post("/agents", name="agent-create")
    @requires("agents:write")
    async def agent_create(request: Request, body: Annotated[AgentCreateBody, Body()]) -> Response:
        async with database.session() as session:
            agent, token = await fleet.enroll_agent(session, name=body.name)
        await log_action(request, "agent.enroll", target=agent.name)
        # The token is returned exactly once and is never stored or logged in clear text.
        return Response.json({"id": str(agent.id), "name": agent.name, "token": token}, status_code=201)

    @app.post("/agents/<agent_id>/rotate", name="agent-rotate")
    @requires("agents:write")
    async def agent_rotate(request: Request, agent_id: str) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, _parse_uuid(agent_id))
            if agent is None:
                abort(404)
            token = fleet.rotate_token(agent, now=utcnow())
        await log_action(request, "agent.rotate_token", target=agent.name)
        return Response.json({"id": str(agent.id), "name": agent.name, "token": token})

    @app.post("/agents/<agent_id>/enabled", name="agent-enabled")
    @requires("agents:write")
    async def agent_enabled(request: Request, agent_id: str, body: Annotated[AgentEnabledBody, Body()]) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, _parse_uuid(agent_id))
            if agent is None:
                abort(404)
            agent.enabled = body.enabled
        await log_action(request, "agent.enable" if body.enabled else "agent.disable", target=agent.name)
        return Response.json({"enabled": body.enabled})

    @app.delete("/agents/<agent_id>", name="agent-delete")
    @requires("agents:write")
    async def agent_delete(request: Request, agent_id: str) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, _parse_uuid(agent_id))
            if agent is None:
                abort(404)
            await session.delete(agent)
        await log_action(request, "agent.delete", target=agent.name)
        return Response.json({"redirect": "/agents"})

    @app.get("/users", name="users")
    @requires("users:manage")
    async def user_list(request: Request) -> Response:
        async with database.session() as session:
            users = await accounts.list_users(session)
        return render(request, "users.html", users=users, roles=[item.value for item in Role])

    @app.post("/users", name="user-create")
    @requires("users:manage")
    async def user_create(request: Request, body: Annotated[UserCreateBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.create_user(session, username=body.username, password=body.password, role=body.role)
        await log_action(request, "user.create", target=user.username, detail={"role": user.role})
        return Response.json({"id": str(user.id), "username": user.username}, status_code=201)

    @app.patch("/users/<user_id>", name="user-update")
    @requires("users:manage")
    async def user_update(request: Request, user_id: str, body: Annotated[UserUpdateBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, _parse_uuid(user_id))
            if user is None:
                abort(404)
            await accounts.update_user(session, user=user, role=body.role, is_active=body.is_active)
        await log_action(
            request,
            "user.update",
            target=user.username,
            detail={"role": body.role, "is_active": body.is_active},
        )
        return Response.json({"role": user.role, "is_active": user.is_active})

    @app.post("/users/<user_id>/password", name="user-password")
    @requires("users:manage")
    async def user_password(request: Request, user_id: str, body: Annotated[PasswordResetBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, _parse_uuid(user_id))
            if user is None:
                abort(404)
            await accounts.change_password(session, user=user, new_password=body.password)
            await accounts.end_all_sessions(session, user.id)
        await log_action(request, "user.reset_password", target=user.username)
        return Response.json({"ok": True})

    @app.get("/account", name="account")
    @requires()
    async def account_page(request: Request) -> Response:
        return render(request, "account.html", min_length=security.PASSWORD_MIN_LENGTH)

    @app.post("/account/password", name="account-password")
    @requires()
    @app.ratelimit(10, per=300, scope="password-change")
    async def account_password(request: Request, body: Annotated[PasswordChangeBody, Body()]) -> Response:
        me = current(request)
        token = request.session.get("sid") if request.session is not None else None
        async with database.session() as session:
            user = await accounts.get_user(session, me.id)
            if user is None:
                abort(401)
            verified = await security.verify_password(user.password_hash, body.current_password)
            if verified:
                await accounts.change_password(session, user=user, new_password=body.new_password)
                # Other browsers are signed out; this one keeps working.
                await accounts.end_all_sessions(session, user.id, keep_token=token if isinstance(token, str) else None)
        await log_action(request, "account.change_password", outcome="success" if verified else "failure")
        if not verified:
            return Response.json({"error": "Current password is incorrect."}, status_code=400)
        return Response.json({"ok": True})

    @app.get("/audit", name="audit")
    @requires("audit:read")
    async def audit_page(request: Request, page: Annotated[int, Query()] = 1) -> Response:
        page = min(max(page, 1), alerts.MAX_PAGE)
        async with database.session() as session:
            events, total = await audit.recent(session, limit=AUDIT_PAGE_SIZE, offset=(page - 1) * AUDIT_PAGE_SIZE)
        pages = max((total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE, 1)
        return render(request, "audit.html", events=events, total=total, page=page, pages=pages)

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
