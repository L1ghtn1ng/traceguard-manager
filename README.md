# TraceGuard Manager

A fleet manager and alert console for [TraceGuard](https://github.com/L1ghtn1ng/traceguard) agents.

TraceGuard agents already export their events over HTTPS in batches. Point that export at this
manager and you get:

- **Alert triage**: detection alerts, blocked and would-block enforcement events, response actions
  and agent errors, with search, filters, bulk acknowledge/resolve, notes, and MITRE context.
  Rules, hosts and the hours of the overview chart link to the alerts behind them.
- **Fleet health**: per-agent status from heartbeats (online, degraded, offline, pending), uptime,
  unavailable hooks, ring-buffer health, and policy drift against the fleet baseline.
- **Live updates**: new alerts appear in the dashboard without reloading.
- **Accounts and audit**: local users with three roles, and an audit log of every sensitive action.

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
| `TGM_AGENT_OFFLINE_SECONDS` | `900` | Silence after which an agent is offline. |
| `TGM_ALERT_RETENTION_DAYS` | `90` | Alerts older than this are deleted hourly. |

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
- `GET /healthz` returns `200 {"status":"ok"}` when the database is reachable.

## Roles

| Role | Can |
| --- | --- |
| Viewer | Read alerts and fleet state |
| Analyst | Viewer, plus acknowledge, resolve and annotate alerts |
| Admin | Analyst, plus enrol and manage agents, manage users, read the audit log |

Changing a user's role or disabling them signs them out everywhere. The last active
administrator cannot be demoted or disabled.

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
| `web.py` | Dashboard pages, JSON actions, live event stream |
| `ingest.py` | Validates and classifies TraceGuard records |
| `fleet.py`, `alerts.py`, `accounts.py`, `audit.py` | Domain logic over the database |
| `models.py`, `db.py`, `migrations/` | Schema, engine, Alembic migrations |
| `templates/`, `static/` | Server-rendered UI; no inline script or style |

## Security

Mapped to the OWASP Top 10 (2025):

| Risk | What the manager does |
| --- | --- |
| A01 Broken access control | Every route declares its permission; roles map to scopes checked by the framework. Agent identity is bound to the token. Identifiers are UUIDv7, not sequential. CSRF tokens plus `Origin` checks on every state change. |
| A02 Security misconfiguration | Secure defaults: strict host allowlist, `Secure`/`HttpOnly`/`SameSite` cookies, docs endpoints off, debug refuses to start alongside production cookie settings, proxy headers untrusted by default. Configuration is validated at startup, and a misspelt setting is an error rather than a silent fall-back to the default. |
| A03 Software supply chain failures | Dependencies are pinned in `uv.lock` with hashes and never resolve to a release younger than 7 days. CI audits them for known vulnerabilities and pins every GitHub Action to a commit. No CDN or third-party assets: every script and stylesheet is served from the app. |
| A04 Cryptographic failures | Argon2id for passwords. Session and agent tokens are 256-bit random values stored only as SHA-256 digests. Cookies are HMAC-signed. HSTS is sent on every response. |
| A05 Injection | All SQL goes through SQLAlchemy bound parameters; search input is escaped for `LIKE`. Templates are sandboxed and auto-escaped. A strict CSP (`default-src 'none'`, no inline code) backs that up. Client code writes server data with `textContent` only. |
| A06 Insecure design | Separate applications for agents and browsers. Per-agent revocable tokens shown once. Idempotent ingest. Bounded request sizes, record counts, list lengths, page numbers and retention. |
| A07 Authentication failures | Length-based password policy, generic sign-in errors, constant-work verification for unknown users, per-account lockout, per-client rate limit, server-side sessions with idle and absolute timeouts that are revoked on sign-out, password change and role change. |
| A08 Software or data integrity failures | No deserialisation of untrusted objects: JSON only, type-checked field by field. Unknown fields in dashboard requests are rejected. Schema changes go through reviewed migrations. |
| A09 Logging and alerting failures | Sign-ins (success and failure), token and user management and alert triage are written to an append-only audit table and to structured logs with request IDs. Secrets never enter either. |
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

### Dependencies and CI

- `uv.lock` pins every package. `exclude-newer = "7 days"` in `pyproject.toml` stops uv from
  resolving to a release published in the last week, so `uv lock --upgrade` and `uv add` only ever
  pick versions that have had time to be vetted.
- Dependabot ([.github/dependabot.yml](.github/dependabot.yml)) opens one grouped pull request a
  week covering Python packages and GitHub Actions, with the same 7-day cooldown. Security updates
  are not delayed.
- CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint, type check, tests, migration
  and framework checks, browser tests and a dependency audit on every push to `main` and every pull
  request, and weekly. Actions are pinned to commit hashes, jobs get read-only access, and
  `zizmor` audits the workflow files themselves.
- The uv version CI installs is set by `UV_VERSION` in the workflow. Dependabot does not update it.

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
