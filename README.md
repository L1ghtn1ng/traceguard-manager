# TraceGuard Manager

A fleet manager and alert console for [TraceGuard](https://github.com/L1ghtn1ng/traceguard) agents.

TraceGuard agents already export their events over HTTPS in batches. Point that export at this
manager and you get:

- **Alert triage**: detection alerts, blocked and would-block enforcement events, response actions
  and agent errors. Search, filter by time, severity, owner and MITRE label, sort, group by rule or
  host, and export to CSV or JSON. Each alert has an owner, a history of notes and status changes,
  and links to related alerts. Bulk actions can cover every alert a filter matches.
- **Mute rules**: silence a noisy rule, a host, or a rule on one host, for a set time. Muted alerts
  are still recorded, but stay out of the open list, the live toasts and notifications.
- **Notifications**: signed webhooks, Slack-style chat webhooks and email for new alerts, plus
  optional desktop notifications from an open tab.
- **Fleet health**: per-agent status from heartbeats (online, degraded, offline, pending), uptime,
  unavailable hooks, ring-buffer health, and policy drift against the fleet baseline. Agents can be
  searched, tagged and renamed, and an agent that stops reporting raises an alert of its own.
- **Live updates**: new alerts appear in the dashboard without reloading, and times are shown in
  your own time zone.
- **Accounts and audit**: local users with three roles, optional two-step sign-in, and a
  searchable audit log of every sensitive action.
- **Keyboard shortcuts**: press `?` anywhere in the dashboard for the list.

Raw telemetry (exec, dns, connection and so on) is accepted and counted but not stored.

Built on Python 3.14, [Flasgo](https://flasgo.dev), async SQLAlchemy, and server-rendered pages
with no front-end build step.

## Quick start

```bash
uv sync
cp .env.example .env    # then set TGM_SECRET_KEY
```

For local development over plain HTTP, also set `TGM_SECURE_COOKIES=false` and
`TGM_LOG_FORMAT=text` in `.env`.

```bash
set -a; source .env; set +a
uv run traceguard-manager migrate
uv run traceguard-manager create-user admin        # prompts for a password (12+ characters)
uv run traceguard-manager serve
```

Open <http://127.0.0.1:8000> and sign in. Until an agent is enrolled, the overview walks you
through connecting the first one.

`serve` refuses to start if the database has not been migrated, and says which command to run.

To look around before connecting a real agent, fill the dashboard with sample agents and alerts:

```bash
uv run traceguard-manager demo-data             # adds agents named demo-... and about 160 alerts
uv run traceguard-manager demo-data --remove    # deletes them again
```

Sample data is refused when real agents are already enrolled, unless you pass `--force`.

## Connecting an agent

1. In the dashboard open **Fleet → Enrol agent** (or run `uv run traceguard-manager create-agent web-01`).
   The token is shown once.
2. Add the two lines it gives you to the agent's environment file:

   ```bash
   TRACEGUARD_EVENT_EXPORT_URL=https://manager.example.com/api/v1/events
   TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer tgm_...
   ```

   TraceGuard only exports to `https://` URLs, so the manager needs TLS in front of it.
   Keep `TRACEGUARD_EVENT_SCHEMA` at its default (`traceguard`); OCSF is not accepted.
3. Restart the agent. Its first heartbeat marks it online.

Each agent has its own token. Rotating or disabling one agent never affects the others, and an
agent's identity always comes from its token, never from the hostname in the payload.

Delivery is idempotent: when an agent replays spooled batches after an outage, alerts that were
already stored are counted as duplicates rather than stored twice.

## Configuration

All settings are environment variables. See [.env.example](.env.example) for the full list.
Settings are checked at startup: a value that is out of range, or a `TGM_` name the manager does
not know (usually a typo), stops it with a message naming the setting.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TGM_SECRET_KEY` | required | Signs cookies. At least 32 characters, from a secret store. |
| `TGM_DATABASE_URL` | SQLite file | `sqlite+aiosqlite:///...` or `postgresql+asyncpg://...` |
| `TGM_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Host headers the manager accepts. |
| `TGM_CSRF_TRUSTED_ORIGINS` | empty | Public origin when a proxy terminates TLS. |
| `TGM_SECURE_COOKIES` | `true` | `Secure` cookies. Only disable for local HTTP. |
| `TGM_AGENT_OFFLINE_SECONDS` | `900` | Silence after which an agent is offline and an alert is raised. |
| `TGM_ALERT_RETENTION_DAYS` | `90` | Alerts older than this are deleted hourly. |
| `TGM_SESSION_IDLE_SECONDS` | `1800` | Sign-out after this long without the person doing anything. |
| `TGM_LOGIN_REQUESTS_PER_MINUTE` | `10` | Sign-in attempts allowed per client address. |
| `TGM_PUBLIC_URL` | empty | Public address of the dashboard, for links in notifications. |
| `TGM_SMTP_HOST`, `TGM_SMTP_FROM` | empty | Mail server and sender; needed for email channels. |
| `TGM_NOTIFY_ALLOW_PRIVATE_NETWORKS` | `false` | Allow webhooks to private addresses. |

The idle timeout counts only what a person does. The live stream and the page's own refreshes do
not keep a session alive, so an unattended tab signs out. For a wall-mounted dashboard, raise
`TGM_SESSION_IDLE_SECONDS` (up to the absolute limit, 12 hours by default).

### Database

SQLite is the zero-setup default and suits a small fleet on one worker. Use PostgreSQL for larger
fleets or more than one worker:

```bash
TGM_DATABASE_URL=postgresql+asyncpg://tgm:password@db.internal/tgm
uv run traceguard-manager migrate
uv run traceguard-manager serve --host 0.0.0.0 --workers 4
```

The same migrations and queries run on both.

### Production checklist

- Terminate TLS at a reverse proxy and keep the app port unreachable from outside.
- Set `TGM_ALLOWED_HOSTS` to the real hostname and `TGM_CSRF_TRUSTED_ORIGINS` to its `https://` origin.
- Forwarded headers are ignored unless you name the proxy: `serve --trust-proxy 10.0.0.2`.
- Load `TGM_SECRET_KEY` and the database password from a secret store.
- Sign-in and ingest rate limits are per process. Add an edge limit if you run several workers.
- With several workers, each alert is still announced and each offline agent still reported once.
  Live updates in the browser can lag by up to five seconds when another worker stored the alert.
- `GET /healthz` returns `200 {"status":"ok"}` when the database is reachable.

## Notifications

Add channels under **Notifications** (administrators only). New open alerts at or above a channel's
severity are sent within a few seconds; several arriving together go out as one message. Each alert
is announced once, even with several workers. Delivery is retried three times, and the last result
is shown next to the channel.

| Type | Sends | Notes |
| --- | --- | --- |
| Signed webhook | JSON: `{"version": 1, "sent_at": ..., "alerts": [...]}` | Verify the signature, below. |
| Chat webhook | A text message | The incoming-webhook URL of Slack, Mattermost or a Teams workflow. |
| Email | Plain text | Needs `TGM_SMTP_HOST` and `TGM_SMTP_FROM`; STARTTLS by default. |

Webhooks are only sent to `https://` URLs with a valid certificate, and never to loopback or
link-local addresses. Private addresses are refused too unless
`TGM_NOTIFY_ALLOW_PRIVATE_NETWORKS=true`. Redirects are not followed. A webhook URL is treated as a
credential: after saving, only its host name is shown.

A signed webhook carries `X-TraceGuard-Timestamp` and `X-TraceGuard-Signature`. The signature is
the HMAC-SHA256, keyed with the channel's secret (shown once when the channel is created), of the
timestamp, a full stop, and the raw request body:

```python
import hashlib, hmac, time


def is_genuine(secret: str, timestamp: str, signature: str, body: bytes) -> bool:
    if abs(time.time() - int(timestamp)) > 300:  # reject replays
        return False
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, f"sha256={expected}")
```

## Roles

| Role | Can |
| --- | --- |
| Viewer | Read alerts and fleet state |
| Analyst | Viewer, plus acknowledge, resolve, annotate and own alerts, and manage mute rules |
| Admin | Analyst, plus manage agents, users and notification channels, and read the audit log |

Changing a user's role or disabling them signs them out everywhere. The last active
administrator cannot be demoted, disabled or deleted.

A password set by an administrator, for a new account or a reset, must be replaced by its owner at
the next sign-in; until then the account can do nothing else. Anyone can turn on two-step sign-in
(an authenticator app, with one-time recovery codes) from their account page, where they can also
see and end their other sessions. An administrator can reset two-step sign-in for someone who has
lost their device, and can lift a lockout early.

## Architecture

```text
TraceGuard agent ──Bearer token──▶ /api/v1/events ──▶ ingest app  ─┐
                                                                   ├─▶ async SQLAlchemy ─▶ SQLite / PostgreSQL
Browser ──session cookie + CSRF──▶ everything else ──▶ dashboard  ─┘
```

`traceguard_manager.asgi:app` is a small ASGI router over two Flasgo applications. They are separate
because they have different trust models: agents present bearer tokens and never cookies, so CSRF
protection does not apply to them, while the dashboard keeps CSRF fully enabled.

| Module | Role |
| --- | --- |
| `api.py` | Ingest endpoint for agents |
| `web.py` | Dashboard application: sessions, rendering, errors, background tasks, live stream |
| `routes/` | Dashboard pages and actions: `account`, `alerts`, `fleet`, `admin` |
| `ingest.py` | Validates and classifies TraceGuard records |
| `fleet.py`, `alerts.py`, `mutes.py`, `accounts.py`, `audit.py` | Domain logic over the database |
| `notify.py` | Notification channels and delivery |
| `totp.py` | Time-based one-time passwords and recovery codes |
| `models.py`, `db.py`, `migrations/` | Schema, engine, Alembic migrations |
| `templates/`, `static/` | Server-rendered UI; no inline script or style |

## Security

Mapped to the OWASP Top 10 (2025):

| Risk | What the manager does |
| --- | --- |
| A01 Broken access control | Every route declares its permission; roles map to scopes checked by the framework. Agent identity is bound to the token. Identifiers are UUIDv7, not sequential. CSRF tokens plus `Origin` checks on every state change. Outbound webhooks are checked against server-side request forgery: https only, public addresses only by default, connected to the address that was checked, no redirects. |
| A02 Security misconfiguration | Secure defaults: strict host allowlist, `Secure`/`HttpOnly`/`SameSite` cookies, docs endpoints off, debug refuses to start alongside production cookie settings, proxy headers untrusted by default. Configuration is validated at startup, and a misspelt setting is an error rather than a silent fall-back to the default. |
| A03 Software supply chain failures | Dependencies are pinned in `uv.lock` with hashes and never resolve to a release younger than 7 days. CI audits them for known vulnerabilities and pins every GitHub Action to a commit. No CDN or third-party assets: every script and stylesheet is served from the app. |
| A04 Cryptographic failures | Argon2id for passwords. Session and agent tokens are 256-bit random values stored only as SHA-256 digests, as are recovery codes. Cookies are HMAC-signed. Webhooks are HMAC-signed with a timestamp. HSTS is sent on every response. Two-step secrets and webhook signing secrets have to be usable, so they are stored readable: protect the database accordingly. |
| A05 Injection | All SQL goes through SQLAlchemy bound parameters; search input is escaped for `LIKE`. Templates are sandboxed and auto-escaped. A strict CSP (`default-src 'none'`, no inline code) backs that up. Client code writes server data with `textContent` only. |
| A06 Insecure design | Separate applications for agents and browsers. Per-agent revocable tokens shown once. Idempotent ingest. Bounded request sizes, record counts, list lengths, page numbers and retention. |
| A07 Authentication failures | Length-based password policy, generic sign-in errors, constant-work verification for unknown users, per-account lockout (for wrong codes as well as wrong passwords), per-client rate limit, optional two-step sign-in with replay protection, passwords set by an administrator must be replaced at first use, server-side sessions with idle and absolute timeouts that are revoked on sign-out, password change and role change. Only what a person does counts against the idle timeout. |
| A08 Software or data integrity failures | No deserialisation of untrusted objects: JSON only, type-checked field by field. Unknown fields in dashboard requests are rejected. Schema changes go through reviewed migrations. |
| A09 Logging and alerting failures | Sign-ins (success and failure), token and user management, alert triage, exports, mute rules and notification channels are written to an append-only audit table and to structured logs with request IDs. Secrets never enter either. New alerts can be pushed to webhooks, chat and email, an agent that goes quiet raises an alert, and a failing notification channel is shown as failing. |
| A10 Mishandling of exceptional conditions | Errors fail closed with generic messages and a request ID; details stay in server logs. A malformed record never fails a whole batch, and database errors roll the transaction back. |

Defence in depth still depends on how you deploy: use TLS, keep the host patched, and restrict who
can reach the dashboard.

## Development

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest                     # unit and integration tests
uv run playwright install chromium
uv run pytest -m e2e              # browser tests against a real server
```

Browser tests are run separately because Playwright's sync API and pytest-asyncio cannot share an
event loop. To use a browser that is already installed instead of Playwright's download, set
`TGM_E2E_BROWSER=/path/to/chromium`.

The unit and integration tests use a throwaway SQLite file. To run them against PostgreSQL instead,
point them at an empty database you do not mind losing; its `public` schema is dropped before
every test:

```bash
TGM_TEST_DATABASE_URL=postgresql+asyncpg://tgm:password@localhost/tgm_test uv run pytest
```

### Dependencies and CI

- `uv.lock` pins every package. `exclude-newer = "7 days"` in `pyproject.toml` stops uv from
  resolving to a release published in the last week, so `uv lock --upgrade` and `uv add` only ever
  pick versions that have had time to be vetted.
- Dependabot ([.github/dependabot.yml](.github/dependabot.yml)) opens one grouped pull request a
  week covering Python packages and GitHub Actions, with the same 7-day cooldown. Security updates
  are not delayed.
- CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint, type check, tests on SQLite
  and on PostgreSQL, migration and framework checks, browser tests and a dependency audit on every
  push to `main` and every pull request, and weekly. Actions are pinned to commit hashes, jobs get
  read-only access, and `zizmor` audits the workflow files themselves.
- The uv version CI installs is set by `UV_VERSION` in the workflow, and the PostgreSQL image is
  pinned by digest there. Dependabot updates neither; bump them by hand.

Framework checks:

```bash
uv run flasgo check traceguard_manager.asgi:app.web --deploy
uv run flasgo check traceguard_manager.asgi:app.api          # --deploy reports FG004: CSRF is off by design here
uv run flasgo routes traceguard_manager.asgi:app.web --policy
```

After changing `models.py`, generate and review a migration. Alembic is configured under
`[tool.alembic]` in `pyproject.toml` and reads the database URL from `TGM_DATABASE_URL`:

```bash
uv run alembic revision --autogenerate -m "describe the change"
uv run alembic check        # fails if the models and migrations have drifted apart
```

Use `alembic` directly rather than `flasgo db`: Flasgo's wrapper only accepts an `alembic.ini` file.
