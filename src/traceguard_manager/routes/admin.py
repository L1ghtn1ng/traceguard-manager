"""Administration: users, the audit log, and notification channels."""

from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

from flasgo import Body, Request, Response, abort

from .. import accounts, alerts, audit, notify
from ..models import ChannelKind, Role, utcnow
from ..webcontext import Web, page_count, page_number, parse_uuid, query_params

AUDIT_PAGE_SIZE = 50


@dataclass(slots=True)
class UserCreateBody:
    username: str
    password: str
    role: str


@dataclass(slots=True)
class UserUpdateBody:
    role: str | None = None
    is_active: bool | None = None
    # True clears a lockout early.
    unlock: bool | None = None


@dataclass(slots=True)
class PasswordResetBody:
    password: str


@dataclass(slots=True)
class ChannelCreateBody:
    name: str
    kind: str
    target: str
    min_level: str = "high"


@dataclass(slots=True)
class ChannelUpdateBody:
    enabled: bool | None = None
    min_level: str | None = None


def register(web: Web) -> None:
    app, config, database = web.app, web.config, web.database
    requires, current, render, log_action = web.requires, web.current, web.render, web.log_action

    # ---- users ----------------------------------------------------------

    @app.get("/users", name="users")
    @requires("users:manage")
    async def user_list(request: Request) -> Response:
        now = utcnow()
        async with database.session() as session:
            users = await accounts.list_users(session)
        return render(
            request,
            "users.html",
            users=users,
            roles=[item.value for item in Role],
            locked={user.id for user in users if accounts.is_locked(user, now=now)},
        )

    @app.post("/users", name="user-create")
    @requires("users:manage")
    async def user_create(request: Request, body: Annotated[UserCreateBody, Body()]) -> Response:
        async with database.session() as session:
            # The administrator knows this password, so it has to be replaced at first sign-in.
            user = await accounts.create_user(
                session, username=body.username, password=body.password, role=body.role, must_change=True
            )
        await log_action(request, "user.create", target=user.username, detail={"role": user.role})
        return Response.json({"id": str(user.id), "username": user.username}, status_code=201)

    @app.patch("/users/<user_id>", name="user-update")
    @requires("users:manage")
    async def user_update(request: Request, user_id: str, body: Annotated[UserUpdateBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, parse_uuid(user_id))
            if user is None:
                abort(404)
            await accounts.update_user(session, user=user, role=body.role, is_active=body.is_active)
            if body.unlock:
                accounts.unlock(user)
        await log_action(
            request,
            "user.unlock" if body.unlock else "user.update",
            target=user.username,
            detail={"role": body.role, "is_active": body.is_active},
        )
        return Response.json({"role": user.role, "is_active": user.is_active})

    @app.post("/users/<user_id>/password", name="user-password")
    @requires("users:manage")
    async def user_password(request: Request, user_id: str, body: Annotated[PasswordResetBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, parse_uuid(user_id))
            if user is None:
                abort(404)
            await accounts.change_password(session, user=user, new_password=body.password, by_admin=True)
            await accounts.end_all_sessions(session, user.id)
        await log_action(request, "user.reset_password", target=user.username)
        return Response.json({"ok": True})

    @app.post("/users/<user_id>/two-step/reset", name="user-two-step-reset")
    @requires("users:manage")
    async def user_two_step_reset(request: Request, user_id: str) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, parse_uuid(user_id))
            if user is None:
                abort(404)
            accounts.disable_totp(user)
            # Whoever holds the old device should not keep a session either.
            await accounts.end_all_sessions(session, user.id)
        await log_action(request, "user.reset_two_step", target=user.username)
        return Response.json({"ok": True})

    @app.delete("/users/<user_id>", name="user-delete")
    @requires("users:manage")
    async def user_delete(request: Request, user_id: str) -> Response:
        me = current(request)
        async with database.session() as session:
            user = await accounts.get_user(session, parse_uuid(user_id))
            if user is None:
                abort(404)
            await accounts.delete_user(session, user=user, acting_user_id=me.id)
        await log_action(request, "user.delete", target=user.username, detail={"role": user.role})
        return Response.json({"ok": True})

    # ---- audit log ------------------------------------------------------

    @app.get("/audit", name="audit")
    @requires("audit:read")
    async def audit_page(request: Request) -> Response:
        params = query_params(request)
        page = page_number(params, alerts.MAX_PAGE)
        search = audit.AuditSearch.from_params(params)
        async with database.session() as session:
            events, total = await audit.search(
                session, search, now=utcnow(), limit=AUDIT_PAGE_SIZE, offset=(page - 1) * AUDIT_PAGE_SIZE
            )
            actions = await audit.known_actions(session)
        return render(
            request,
            "audit.html",
            events=events,
            total=total,
            search=search,
            actions=actions,
            ranges=alerts.RANGE_LABELS,
            page=page,
            pages=page_count(total, AUDIT_PAGE_SIZE),
            base_query=urlencode(search.to_query()),
        )

    # ---- notification channels ------------------------------------------

    @app.get("/notifications", name="notifications")
    @requires("notify:manage")
    async def channel_list(request: Request) -> Response:
        async with database.session() as session:
            channels = await notify.list_channels(session)
        return render(
            request,
            "notifications.html",
            channels=[(channel, notify.display_target(channel)) for channel in channels],
            kinds=[item.value for item in ChannelKind],
            levels=alerts.LEVELS,
            email_ready=bool(config.smtp_host),
            public_url=config.public_url,
        )

    @app.post("/notifications", name="channel-create")
    @requires("notify:manage")
    async def channel_create(request: Request, body: Annotated[ChannelCreateBody, Body()]) -> Response:
        async with database.session() as session:
            channel = await notify.create_channel(
                session,
                config,
                name=body.name,
                kind=body.kind,
                target=body.target,
                min_level=body.min_level,
                actor=current(request).username,
            )
        await log_action(
            request, "channel.create", target=channel.name, detail={"kind": channel.kind, "min_level": channel.min_level}
        )
        # The signing secret is shown once, like an agent token.
        return Response.json({"id": str(channel.id), "name": channel.name, "secret": channel.secret}, status_code=201)

    @app.patch("/notifications/<channel_id>", name="channel-update")
    @requires("notify:manage")
    async def channel_update(request: Request, channel_id: str, body: Annotated[ChannelUpdateBody, Body()]) -> Response:
        async with database.session() as session:
            channel = await notify.get_channel(session, parse_uuid(channel_id))
            if channel is None:
                abort(404)
            notify.update_channel(channel, enabled=body.enabled, min_level=body.min_level)
        await log_action(
            request, "channel.update", target=channel.name, detail={"enabled": body.enabled, "min_level": body.min_level}
        )
        return Response.json({"enabled": channel.enabled, "min_level": channel.min_level})

    @app.delete("/notifications/<channel_id>", name="channel-delete")
    @requires("notify:manage")
    async def channel_delete(request: Request, channel_id: str) -> Response:
        async with database.session() as session:
            channel = await notify.get_channel(session, parse_uuid(channel_id))
            if channel is None:
                abort(404)
            await session.delete(channel)
        await log_action(request, "channel.delete", target=channel.name)
        return Response.json({"ok": True})

    @app.post("/notifications/<channel_id>/test", name="channel-test")
    @requires("notify:manage")
    @app.ratelimit(10, per=60, scope="channel-test")
    async def channel_test(request: Request, channel_id: str) -> Response:
        async with database.session() as session:
            channel = await notify.get_channel(session, parse_uuid(channel_id))
        if channel is None:
            abort(404)
        error = await notify.send_test(database, config, channel, transport=web.transport)
        await log_action(request, "channel.test", target=channel.name, outcome="failure" if error else "success")
        if error:
            return Response.json({"error": f"The test did not go through. {error}"}, status_code=400)
        return Response.json({"ok": True})
