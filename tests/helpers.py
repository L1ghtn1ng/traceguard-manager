"""Shared test helpers: a browser-like client and sample TraceGuard records."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from flasgo import TestClient, TestResponse

ORIGIN = "http://localhost"
ADMIN_PASSWORD = "correct-battery-staple-42"
ANALYST_PASSWORD = "triage-team-passphrase-26"
VIEWER_PASSWORD = "read-only-passphrase-26"


@dataclass(slots=True)
class Browser:
    """Drives the dashboard the way a browser does: cookies, Origin and CSRF header."""

    client: TestClient

    async def get(self, path: str, *, accept: str = "text/html", cookie: str | None = None) -> TestResponse:
        headers = {"accept": accept}
        if cookie is not None:
            headers["cookie"] = cookie  # replay a captured cookie, as an attacker would
        return await self.client.arequest("GET", path, headers=headers)

    def session_cookie(self) -> str:
        return self.client.cookies["flasgo-session"]

    async def send(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        csrf: bool = True,
        origin: str | None = ORIGIN,
    ) -> TestResponse:
        headers = {"accept": "application/json"}
        if origin is not None:
            headers["origin"] = origin
        if csrf:
            headers["x-csrf-token"] = self.client.cookies.get("flasgo-csrf", "")
        return await self.client.arequest(method, path, headers=headers, json=body)

    async def post(self, path: str, body: object | None = None) -> TestResponse:
        return await self.send("POST", path, body)

    async def login(self, username: str, password: str) -> TestResponse:
        await self.get("/login")  # issues the CSRF cookie, as loading the page does
        return await self.post("/auth/login", {"username": username, "password": password})


def data(response: TestResponse) -> dict[str, Any]:
    """The response body as a JSON object."""
    value = response.json()
    assert isinstance(value, dict)
    return value


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def heartbeat(hostname: str = "web-01", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timestamp": now_iso(),
        "level": "info",
        "message": "heartbeat",
        "hostname": hostname,
        "event": "heartbeat",
        "policy_sha256": "a" * 64,
        "policy_mode": "enforce",
        "uptime_seconds": 7200,
        "healthy": True,
        "unavailable_hooks": [],
        "ringbuf_dropped_events": 0,
        "ringbuf_unread_bytes": 0,
        "ringbuf_degraded": False,
        "detection_rules": 14,
    }
    return record | overrides


def detection(alert_id: str = "ALERT1", hostname: str = "web-01", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timestamp": now_iso(),
        "level": "info",
        "message": "detection alert",
        "hostname": hostname,
        "event": "detection_alert",
        "source_event": "exec",
        "alert_id": alert_id,
        "detection_rule_id": "tg-reverse-shell",
        "severity": "critical",
        "detection_message": "Interactive shell spawned by a network service",
        "tags": ["shell", "execution"],
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
        "threshold_count": 1,
        "exe": "/usr/bin/bash",
        "pid": 4242,
    }
    return record | overrides


def blocked(hostname: str = "web-01", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timestamp": now_iso(),
        "level": "info",
        "message": "egress_blocked",
        "hostname": hostname,
        "event": "egress_blocked",
        "domain": "evil.example",
        "comm": "curl",
    }
    return record | overrides


def telemetry(hostname: str = "web-01") -> dict[str, Any]:
    return {"timestamp": now_iso(), "level": "info", "message": "exec", "hostname": hostname, "event": "exec"}
