"""Signing in and out, and everything on the account page."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

import segno
from flasgo import Body, Query, Request, Response, abort, is_safe_redirect_target
from flasgo import User as Principal
from markupsafe import Markup

from .. import accounts, security, totp
from ..models import User, utcnow
from ..webcontext import Web, parse_uuid

GENERIC_LOGIN_ERROR = "Invalid username or password."


@dataclass(slots=True)
class LoginBody:
    username: str
    password: str
    next: str = "/"
    code: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= len(self.username) <= 64 or not 1 <= len(self.password) <= security.PASSWORD_MAX_LENGTH:
            raise ValueError("Username or password has an invalid length.")
        if len(self.next) > 512:
            raise ValueError("Redirect target is too long.")
        if self.code is not None and len(self.code) > 32:
            raise ValueError("Code is too long.")


@dataclass(slots=True)
class PasswordChangeBody:
    current_password: str
    new_password: str


@dataclass(slots=True)
class PasswordConfirmBody:
    current_password: str


@dataclass(slots=True)
class CodeBody:
    code: str


def register(web: Web, *, session_backend: Callable[[Request], Awaitable[Principal | None]]) -> None:
    app, config, database = web.app, web.config, web.database
    requires, current, render, log_action = web.requires, web.current, web.render, web.log_action

    def session_token(request: Request) -> str | None:
        token = request.session.get("sid") if request.session is not None else None
        return token if isinstance(token, str) else None

    async def confirm_password(request: Request, password: str, action: str) -> User | None:
        """Re-check the signed-in user's password before a sensitive change. Returns None if it is wrong."""
        me = current(request)
        locked = False
        async with database.session() as session:
            user = await accounts.get_user(session, me.id)
            if user is None:
                abort(401)
            verified = await security.verify_password(user.password_hash, password)
            if not verified:
                # Counted like a failed sign-in, so a stolen session cannot guess the password.
                locked = await accounts.record_failed_check(session, config, user=user, now=utcnow())
        if not verified:
            await log_action(request, action, outcome="failure", detail={"reason": "wrong password", "locked": locked})
            if locked:
                abort(401)
            return None
        return user

    # ---- signing in and out ---------------------------------------------

    @app.get("/login", public=True, name="login")
    async def login_page(request: Request, next: Annotated[str, Query()] = "/") -> Response:
        if await session_backend(request) is not None:
            return Response.redirect("/", status_code=303)
        target = next if len(next) <= 512 and is_safe_redirect_target(next) else "/"
        return render(request, "login.html", next=target)

    @app.post("/auth/login", public=True, name="auth-login")
    @app.ratelimit(config.login_requests_per_minute, per=60, scope="login")
    async def login(request: Request, body: Annotated[LoginBody, Body()]) -> Response:
        username = accounts.normalise_username(body.username)
        token: str | None = None
        must_change = False
        async with database.session() as session:
            result = await accounts.authenticate(session, config, username=username, password=body.password, code=body.code)
            if result.user is not None:
                must_change = result.user.must_change_password
                token = await accounts.start_session(
                    session,
                    config,
                    user=result.user,
                    client_ip=request.client_ip,
                    user_agent=request.headers.get("user-agent"),
                )
        outcome = "success" if token else ("challenge" if result.reason == "mfa_required" else "failure")
        await log_action(
            request,
            "auth.login",
            actor=username if security.USERNAME_RE.fullmatch(username) else "invalid-username",
            outcome=outcome,
            detail={"reason": result.reason},
        )
        if result.reason == "mfa_required":
            # The password was right, so asking for the second step gives nothing more away.
            return Response.json(
                {"error": "Enter the 6-digit code from your authenticator app.", "mfa_required": True}, status_code=401
            )
        if result.reason == "mfa_invalid":
            return Response.json({"error": "That code is not right. Try the next one.", "mfa_required": True}, status_code=401)
        if token is None or request.session is None:
            return Response.json({"error": GENERIC_LOGIN_ERROR}, status_code=401)
        # A brand-new session identifier is issued at sign-in, so a pre-login cookie is worthless.
        request.session.clear()
        request.session["sid"] = token
        target = body.next if is_safe_redirect_target(body.next) else "/"
        return Response.json({"redirect": "/account" if must_change else target})

    @app.post("/auth/logout", name="auth-logout")
    @requires()
    async def logout(request: Request) -> Response:
        user = current(request)
        if request.session is not None:
            token = session_token(request)
            if token is not None:
                async with database.session() as session:
                    await accounts.end_session(session, token)
            request.session.clear()
        await log_action(request, "auth.logout", actor=user.username)
        return Response.json({"redirect": "/login"})

    @app.get("/auth/session", name="auth-session")
    @requires()
    async def session_state(request: Request) -> Response:
        """Lets an open page tell an ended session apart from a dropped connection."""
        return Response.json({"username": current(request).username})

    # ---- the account page -----------------------------------------------

    @app.get("/account", name="account")
    @requires()
    async def account_page(request: Request) -> Response:
        me = current(request)
        token = session_token(request)
        current_hash = security.hash_token(token) if token else None
        async with database.session() as session:
            user = await accounts.get_user(session, me.id)
            if user is None:
                abort(401)
            sessions = await accounts.list_sessions(session, config, me.id, now=utcnow())
        return render(
            request,
            "account.html",
            min_length=security.PASSWORD_MIN_LENGTH,
            two_step_on=user.totp_enabled_at is not None,
            two_step_since=user.totp_enabled_at,
            recovery_codes_left=len(user.recovery_codes),
            sessions=sessions,
            current_session_hash=current_hash,
        )

    @app.post("/account/password", name="account-password")
    @requires()
    @app.ratelimit(10, per=300, scope="password-change")
    async def account_password(request: Request, body: Annotated[PasswordChangeBody, Body()]) -> Response:
        me = current(request)
        token = session_token(request)
        async with database.session() as session:
            user = await accounts.get_user(session, me.id)
            if user is None:
                abort(401)
            verified = await security.verify_password(user.password_hash, body.current_password)
            locked = False
            if not verified:
                # Counted like a failed sign-in, so a stolen session cannot guess the password.
                locked = await accounts.record_failed_check(session, config, user=user, now=utcnow())
            if verified:
                if body.new_password == body.current_password:
                    raise accounts.AccountError("Choose a password you have not just been using.")
                await accounts.change_password(session, user=user, new_password=body.new_password)
                # Other browsers are signed out; this one keeps working.
                await accounts.end_all_sessions(session, user.id, keep_token=token)
        await log_action(
            request, "account.change_password", outcome="success" if verified else "failure", detail={"locked": locked}
        )
        if locked:
            abort(401)
        if not verified:
            return Response.json({"error": "Current password is incorrect."}, status_code=400)
        return Response.json({"ok": True, "redirect": "/"})

    # ---- sessions -------------------------------------------------------

    @app.delete("/account/sessions/<session_id>", name="account-session-end")
    @requires()
    async def account_session_end(request: Request, session_id: str) -> Response:
        me = current(request)
        async with database.session() as session:
            ended = await accounts.end_session_by_id(session, user_id=me.id, session_id=parse_uuid(session_id))
        if not ended:
            abort(404)
        await log_action(request, "account.end_session")
        return Response.json({"ok": True})

    @app.post("/account/sessions/end-others", name="account-sessions-end-others")
    @requires()
    async def account_sessions_end_others(request: Request) -> Response:
        me = current(request)
        async with database.session() as session:
            await accounts.end_all_sessions(session, me.id, keep_token=session_token(request))
        await log_action(request, "account.end_other_sessions")
        return Response.json({"ok": True})

    # ---- two-step sign-in -----------------------------------------------

    @app.post("/account/two-step/start", name="account-two-step-start")
    @requires("alerts:read")
    @app.ratelimit(10, per=300, scope="password-change")
    async def two_step_start(request: Request, body: Annotated[PasswordConfirmBody, Body()]) -> Response:
        if await confirm_password(request, body.current_password, "account.two_step_start") is None:
            return Response.json({"error": "Current password is incorrect."}, status_code=400)
        async with database.session() as session:
            user = await accounts.get_user(session, current(request).id)
            if user is None:
                abort(401)
            accounts.begin_totp(user)
        return Response.json({"redirect": "/account/two-step"})

    @app.get("/account/two-step", name="account-two-step")
    @requires("alerts:read")
    async def two_step_page(request: Request) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, current(request).id)
        if user is None or user.totp_secret is None or user.totp_enabled_at is not None:
            return Response.redirect("/account", status_code=303)
        uri = totp.provisioning_uri(user.totp_secret, user.username)
        # Drawn here rather than by a third-party service, so the secret never leaves the manager.
        qr = segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#000000", light="#ffffff")
        return render(
            request,
            "two_step.html",
            qr=Markup(qr),  # noqa: S704 - generated by segno from our own data, not user markup
            secret=" ".join(user.totp_secret[index : index + 4] for index in range(0, len(user.totp_secret), 4)),
        )

    @app.post("/account/two-step/confirm", name="account-two-step-confirm")
    @requires("alerts:read")
    @app.ratelimit(10, per=300, scope="two-step")
    async def two_step_confirm(request: Request, body: Annotated[CodeBody, Body()]) -> Response:
        async with database.session() as session:
            user = await accounts.get_user(session, current(request).id)
            if user is None:
                abort(401)
            codes = accounts.confirm_totp(user, body.code, now=utcnow())
        await log_action(request, "account.two_step_on")
        # Shown once: only their hashes are kept.
        return Response.json({"recovery_codes": codes})

    @app.post("/account/two-step/disable", name="account-two-step-disable")
    @requires("alerts:read")
    @app.ratelimit(10, per=300, scope="password-change")
    async def two_step_disable(request: Request, body: Annotated[PasswordConfirmBody, Body()]) -> Response:
        if await confirm_password(request, body.current_password, "account.two_step_off") is None:
            return Response.json({"error": "Current password is incorrect."}, status_code=400)
        async with database.session() as session:
            user = await accounts.get_user(session, current(request).id)
            if user is None:
                abort(401)
            accounts.disable_totp(user)
        await log_action(request, "account.two_step_off")
        return Response.json({"ok": True})
