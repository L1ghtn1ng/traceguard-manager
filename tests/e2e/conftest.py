"""Starts a real server (migrations, CLI-created users, uvicorn) for browser tests."""

import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, VIEWER_PASSWORD

type RoleCookies = dict[str, list[Any]]

USERS = {
    "admin": ("admin", ADMIN_PASSWORD),
    "analyst": ("analyst", ANALYST_PASSWORD),
    "viewer": ("viewer", VIEWER_PASSWORD),
}


@dataclass(frozen=True, slots=True)
class Server:
    url: str

    def ingest(self, token: str, records: list[dict[str, object]]) -> dict[str, int]:
        """Post a batch the way a TraceGuard agent does."""
        request = urllib.request.Request(  # noqa: S310 - fixed http://127.0.0.1 test server
            f"{self.url}/api/v1/events",
            data=json.dumps(records).encode(),
            headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return json.loads(response.read())


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _cli(env: dict[str, str], *args: str, stdin: str | None = None) -> None:
    subprocess.run(
        [sys.executable, "-m", "traceguard_manager.cli", *args],
        env=env,
        input=stdin,
        text=True,
        check=True,
        capture_output=True,
        timeout=60,
    )


@pytest.fixture(scope="session")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Server]:
    workdir: Path = tmp_path_factory.mktemp("e2e")
    port = _free_port()
    env = os.environ | {
        "TGM_SECRET_KEY": secrets.token_urlsafe(48),
        "TGM_DATABASE_URL": f"sqlite+aiosqlite:///{workdir / 'e2e.db'}",
        "TGM_SECURE_COOKIES": "false",
        "TGM_LOG_FORMAT": "text",
        "TGM_LOG_LEVEL": "WARNING",
        # Every browser here shares one address, so the suite needs more sign-ins than one person would.
        "TGM_LOGIN_REQUESTS_PER_MINUTE": "100",
    }
    # Central policy on, so the policy pages and endpoint work as in production.
    key_path = workdir / "policy-signing.key"
    _cli(env, "policy-key", "generate", str(key_path))
    env["TGM_POLICY_SIGNING_KEY_FILE"] = str(key_path)
    _cli(env, "migrate")
    for role, (username, password) in USERS.items():
        _cli(env, "create-user", username, "--role", role, "--password-stdin", stdin=password + "\n")

    log = (workdir / "server.log").open("w")
    process = subprocess.Popen(
        [sys.executable, "-m", "traceguard_manager.cli", "serve", "--port", str(port)],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"server exited early:\n{(workdir / 'server.log').read_text()}")
            try:
                with urllib.request.urlopen(f"{url}/healthz", timeout=1) as response:  # noqa: S310
                    if response.status == 200:
                        break
            except urllib.error.URLError, OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"server did not start:\n{(workdir / 'server.log').read_text()}") from None
                time.sleep(0.1)
        yield Server(url=url)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, object]) -> dict[str, object]:
    """Let TGM_E2E_BROWSER point at an installed browser instead of Playwright's download."""
    executable = os.environ.get("TGM_E2E_BROWSER")
    return browser_type_launch_args | ({"executable_path": executable} if executable else {})


@pytest.fixture
def csp_violations(page: Page) -> list[str]:
    """Collects console errors, which is where browsers report CSP violations."""
    problems: list[str] = []
    page.on("console", lambda message: problems.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: problems.append(str(error)))
    return problems


def sign_in_through_form(page: Page, server: Server, role: str = "admin") -> None:
    username, password = USERS[role]
    page.goto(f"{server.url}/login")
    page.get_by_label("Username").fill(username)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_test_id("current-user")).to_have_text(username)


@pytest.fixture(scope="session")
def role_cookies(browser: Browser, server: Server) -> RoleCookies:
    """Sign in once per role and share the cookies.

    Sign-in is rate limited per client address, so signing in for every test
    would trip the limiter the suite is meant to leave switched on.
    """
    cookies: RoleCookies = {}
    for role in USERS:
        context = browser.new_context()
        sign_in_through_form(context.new_page(), server, role)
        cookies[role] = [
            {"name": cookie["name"], "value": cookie["value"], "url": server.url}
            for cookie in context.cookies()
            if "name" in cookie and "value" in cookie
        ]
        context.close()
    return cookies


@pytest.fixture
def sign_in(server: Server, role_cookies: RoleCookies) -> Callable[..., None]:
    def apply(page: Page, role: str = "admin") -> None:
        page.context.add_cookies(role_cookies[role])
        page.goto(f"{server.url}/")
        expect(page.get_by_test_id("current-user")).to_have_text(USERS[role][0])

    return apply
