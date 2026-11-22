# TraceGuard Manager

A fleet manager and alert console for [TraceGuard](https://github.com/L1ghtn1ng/traceguard) agents.

TraceGuard agents already export their events over HTTPS in batches. Point that export at this
manager and you get:

- **Alert triage**: detection alerts, blocked and would-block enforcement events, response actions
  and agent errors. Search, filter by time, severity, owner and MITRE label, sort, group by rule or
  host, and export to CSV or JSON. Each alert has an owner, a history of notes and status changes,
  and links to related alerts. Bulk actions can cover every alert a filter matches.
- **Mute rules**: silence a noisy rule, a host, or a rule on one host, for a set time. A host is the
  enrolled agent that reported it, so another agent claiming the same hostname is never muted with
  it. Muted alerts are still recorded, but stay out of the open list, the live toasts and
  notifications.
- **Notifications**: signed webhooks, Slack-style chat webhooks and email for new alerts, plus
  optional desktop notifications from an open tab.
- **Fleet health**: per-agent status from heartbeats (online, degraded, offline, pending), uptime,
  unavailable hooks, ring-buffer health, and policy drift against the fleet baseline. From
  TraceGuard 1.9, also the agent version, kernel and OS, response mode, active blocks and freezes,
  and whether the agent is dropping or having events rejected. Agents can be searched, tagged and
  renamed. An agent that stops reporting raises an alert, and one that says it is stopping raises
  one at once and is shown as stopped until it reports again.
- **Central policy**: write TraceGuard policies here, assign them by agent tag or as the default,
  and agents fetch them signed with the manager's Ed25519 key. Each agent page shows whether the
  agent has taken its policy.
- **Commands**: from an agent or an alert, block a peer address, freeze a cgroup, lift an active
  response, or have the agent refresh its policy now. Agents long-poll for commands and only take
  them when configured to.
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

TraceGuard's own [guide to connecting an agent](https://github.com/L1ghtn1ng/traceguard/blob/main/docs/manager.md)
covers the agent side in full: keeping the token in a systemd credential, private CAs and mTLS,
central policy, commands, and troubleshooting. The short version:

1. **Serve the manager over HTTPS.** TraceGuard exports only to `https://` URLs, so put a TLS
   reverse proxy in front of `serve` (see [Production checklist](#production-checklist)). Allow
   requests to `/api/v1/commands` to run longer than 40 seconds, because command polls are held
   open. From the agent host,
   `curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://manager.example.com/api/v1/events`
   should print `401`: the manager is reachable, and only the token is missing.
2. **Enrol the agent.** Open **Fleet → Enrol agent** and name it. The token is shown once, with
   the settings to copy. The URLs in that snippet use the address your browser opened the
   dashboard at, so change them if agents reach the manager at a different address. Or run
   `uv run traceguard-manager create-agent web-01`, which prints only the
   `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION` line.
3. **Configure the agent.** Add the settings to `/etc/traceguard/traceguard.env` on the agent:

   ```bash
   TRACEGUARD_EVENT_EXPORT_URL=https://manager.example.com/api/v1/events
   TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer tgm_...
   TRACEGUARD_EVENT_EXPORT_EVENTS=alerts
   TRACEGUARD_EVENT_SCHEMA=traceguard
   ```

   Keep `TRACEGUARD_EVENT_SCHEMA` at `traceguard`. OCSF is not accepted, and an agent sending it
   is flagged on its page. `TRACEGUARD_EVENT_EXPORT_EVENTS=alerts` (TraceGuard 1.9 and later) sends
   only what the manager uses, so routine telemetry never competes with alerts for the export
   queue. Older agents ignore it. If the proxy's certificate comes from a private CA, also set
   `TRACEGUARD_EVENT_EXPORT_CA_PATH` on the agent.
4. **Restart the agent** (`sudo systemctl restart traceguard`). The enrol dialog changes from
   *Waiting for the agent to connect* once the first heartbeat arrives, and the agent shows as
   online under **Fleet**. If it stays pending, check the agent's log
   (`journalctl -u traceguard`). A `401` there means the token is wrong or was rotated, or the
   agent is disabled.
5. **Optional: central policy and commands.** To have the agent fetch its signed policy, see
   [Central policy](#central-policy). To let the agent take commands from the manager, see
   [Commands](#commands).

Each agent has its own token. Rotating or disabling one agent never affects the others, and an
agent's identity always comes from its token, never from the hostname in the payload.
Rotating a token also forgets the agent's run counter. Agents that mark their batches recover from
a counter restored from a backup on their own; for one that does not, rotate its token.

Delivery is idempotent: when an agent replays spooled batches after an outage, alerts that were
already stored are counted as duplicates rather than stored twice. A replayed heartbeat or stop
record older than what the agent has already reported is ignored. TraceGuard 1.9 marks each batch
`live` or `replay` in a `TraceGuard-Delivery` header: a live heartbeat is taken as the running
agent's, whatever its run counter or clock says, and nothing replayed is taken as newer than it.

## Central policy

The manager can serve each agent a TraceGuard policy, signed so the agent can check it came from
here. It is off until a signing key is configured:

```bash
uv run traceguard-manager policy-key generate /etc/traceguard-manager/policy-signing.key
# prints the public key; set this and restart:
TGM_POLICY_SIGNING_KEY_FILE=/etc/traceguard-manager/policy-signing.key
```

The key file must be owned by the manager's user and mode `0600`; the manager refuses to start
with a key others can read or own. `policy-key public <path>` prints the public key again, and
**Administration → Policies** offers it as a download.

On each agent, save the public key and point the policy source at the manager with the agent's own
token:

```bash
TRACEGUARD_POLICY_URL=https://manager.example.com/api/v1/policy
TRACEGUARD_POLICY_AUTHORIZATION=Bearer tgm_...
TRACEGUARD_POLICY_SIGNING_KEY=/etc/traceguard/manager-policy.pub
```

Each agent gets one policy: the highest-priority policy that shares one of its tags, or else the
default. An agent with no match and no default is served an empty policy, so it runs on its local
policy file alone, which it always merges with what the manager sends. The manager checks a
document's shape before saving it (one YAML mapping, an explicit `version: 1`, known top-level
keys, at most 4 MiB, no YAML merge keys and at most 256 aliases); the agent validates it fully, keeps its previous policy if it rejects a new one, and
reports the error, which appears as an alert. Agents fetch on their refresh interval (5 minutes by
default) or at once with a **Refresh policy** command. Heartbeats report the digest of the policy
the agent took, and the agent page says whether that is the one assigned.

The signature is fetched separately from the policy, so a policy saved between the two requests
fails that one check; the agent keeps its current policy and succeeds on its next refresh.

## Commands

Administrators can send an agent a command from its page or from an alert:

| Command | From | What the agent does |
| --- | --- | --- |
| Block peer | agent page, or an alert with a peer address | Blocks the address for 15 minutes to 24 hours |
| Freeze cgroup | agent page, or an alert with a cgroup ID | Freezes the cgroup for 15 minutes to 24 hours |
| Lift response | agent page (active responses), or a response alert | Ends a block or freeze now |
| Refresh policy | agent page | Fetches and applies its policy now |

The agent must opt in with `TRACEGUARD_COMMAND_URL=https://manager.example.com/api/v1/commands`
(TraceGuard 1.9 and later). It long-polls that URL with its export token, runs each command at
most once, even across a restart, and reports the result, which the agent page shows. The agent
has the last word: `TRACEGUARD_COMMAND_ACTIONS` limits what it accepts, its response mode applies
(`dry-run`, the default, records what it would do without doing it, and the result says so), and it
refuses loopback addresses, the manager's own address, and protected or its own cgroups. **Refresh
policy** reports done only once the agent has loaded and applied its policy.

A command the agent has not fetched within 10 minutes expires. One it fetched but did not answer is
sent again after 90 seconds, until it expires, and is given up on an hour after that; a result that
arrives later still replaces "expired". A command can be cancelled until the agent fetches it.
Each agent may hold up to four polls open at once. Every command is written to the audit log in the
same transaction that queues it.

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
| `TGM_INGEST_MAX_ALERTS_PER_HOUR` | `10000` | New alerts one agent may store per hour. Past it, ingest answers `429` with `Retry-After`, so TraceGuard spools the alerts and resends them later; heartbeats still count. `0` turns the cap off. |
| `TGM_PUBLIC_URL` | empty | Public address of the dashboard, for links in notifications. |
| `TGM_SMTP_HOST`, `TGM_SMTP_FROM` | empty | Mail server and sender; needed for email channels. |
| `TGM_NOTIFY_ALLOW_PRIVATE_NETWORKS` | `false` | Allow webhooks to private addresses. |
| `TGM_POLICY_SIGNING_KEY_FILE` | empty | Ed25519 key that signs central policies; central policy is off without it. |

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
severity are sent within a few seconds; several arriving together go out as one message, and after a
message a channel waits at least 10 seconds before the next, so a burst becomes a few digests. Each alert
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
| Admin | Analyst, plus manage agents, users, notification channels and policies, send commands to agents, and read the audit log |

Changing a user's role or disabling them signs them out everywhere. The last active
administrator cannot be demoted, disabled or deleted.

A password set by an administrator, for a new account or a reset, must be replaced by its owner at
the next sign-in; until then the account can do nothing else. Anyone can turn on two-step sign-in
(an authenticator app, with one-time recovery codes) from their account page, where they can also
see and end their other sessions. An administrator can reset two-step sign-in for someone who has
lost their device, and can lift a lockout early.

Five wrong passwords or codes lock an account for 15 minutes. So that nobody can keep its owner out
by guessing on purpose, a locked account with two-step sign-in still opens for its password and a
current code given together (**Use a two-step code** on the sign-in page); a locked account never
says whether a password was right. A wrong current password given to confirm a change counts the
same way, and locking the account then ends that session. On the server,
`traceguard-manager unlock-user NAME` lifts a lockout, for when every administrator is locked out.

## Architecture

```text
TraceGuard agent ──Bearer token──▶ /api/v1/{events,policy,commands} ──▶ agent API ─┐
                                                                   ├─▶ async SQLAlchemy ─▶ SQLite / PostgreSQL
Browser ──session cookie + CSRF──▶ everything else ──────────────────▶ dashboard ─┘
```

`traceguard_manager.asgi:app` is a small ASGI router over two Flasgo applications. They are separate
because they have different trust models: agents present bearer tokens and never cookies, so CSRF
protection does not apply to them, while the dashboard keeps CSRF fully enabled.

| Module | Role |
| --- | --- |
| `api.py` | Agent endpoints: event ingest, signed policy, command long-poll and results |
| `web.py` | Dashboard application: sessions, rendering, errors, background tasks, live stream |
| `routes/` | Dashboard pages and actions: `account`, `alerts`, `fleet`, `admin`, `policies` |
| `ingest.py` | Validates and classifies TraceGuard records |
| `fleet.py`, `alerts.py`, `mutes.py`, `accounts.py`, `audit.py` | Domain logic over the database |
| `notify.py` | Notification channels and delivery |
| `policies.py`, `commands.py` | Central policy (validation, assignment, signing) and the agent command queue |
| `totp.py` | Time-based one-time passwords and recovery codes |
| `models.py`, `db.py`, `migrations/` | Schema, engine, Alembic migrations |
| `templates/`, `static/` | Server-rendered UI; no inline script or style |

## Security

Mapped to the OWASP Top 10 (2025):

| Risk | What the manager does |
| --- | --- |
| A01 Broken access control | Every route declares its permission; roles map to scopes checked by the framework. Agent identity is bound to the token: an agent is served only its own policy and commands, and can report results only for its own commands. Commands to agents are admin-only, audited, validated before queueing, and still subject to each agent's own allow-list and response mode. Identifiers are UUIDv7, not sequential. CSRF tokens plus `Origin` checks on every state change. Outbound webhooks are checked against server-side request forgery: https only, public addresses only by default, connected to the address that was checked, no redirects. |
| A02 Security misconfiguration | Secure defaults: strict host allowlist, `Secure`/`HttpOnly`/`SameSite` cookies, docs endpoints off, debug refuses to start alongside production cookie settings, proxy headers untrusted by default. Configuration is validated at startup, and a misspelt setting is an error rather than a silent fall-back to the default. |
| A03 Software supply chain failures | Dependencies are pinned in `uv.lock` with hashes and never resolve to a release younger than 7 days. CI audits them for known vulnerabilities and pins every GitHub Action to a commit. No CDN or third-party assets: every script and stylesheet is served from the app. |
| A04 Cryptographic failures | Argon2id for passwords. Session and agent tokens are 256-bit random values stored only as SHA-256 digests, as are recovery codes. Cookies are HMAC-signed. Webhooks are HMAC-signed with a timestamp. Central policies are signed with Ed25519; the private key is read from a file the manager refuses to use if others can read it, and never enters the database. HSTS is sent on every response. Two-step secrets and webhook signing secrets have to be usable, so they are stored readable: protect the database accordingly. |
| A05 Injection | All SQL goes through SQLAlchemy bound parameters; search input is escaped for `LIKE`. Templates are sandboxed and auto-escaped. A strict CSP (`default-src 'none'`, no inline code) backs that up. Client code writes server data with `textContent` only. |
| A06 Insecure design | Separate applications for agents and browsers. Per-agent revocable tokens shown once. Idempotent ingest. Bounded request sizes, record counts, list lengths, page numbers and retention, and a per-agent hourly cap on stored alerts. The lockout cannot be used to keep an owner with two-step sign-in out, and an operator can lift it from the server. Agent-reported hostnames are never trusted to identify a host for a mute. |
| A07 Authentication failures | Length-based password policy, generic sign-in errors, constant-work verification for unknown users, per-account lockout (for wrong codes and wrong passwords, including a wrong current password given to confirm a change), per-client rate limit, optional two-step sign-in with replay protection, passwords set by an administrator must be replaced at first use, server-side sessions with idle and absolute timeouts that are revoked on sign-out, password change and role change. Only what a person does counts against the idle timeout. |
| A08 Software or data integrity failures | No deserialisation of untrusted objects: JSON only, type-checked field by field. Unknown fields in dashboard requests are rejected. Schema changes go through reviewed migrations. |
| A09 Logging and alerting failures | Sign-ins (success and failure), refused requests (a missing permission, or a change a rule refused), token and user management, alert triage, exports, mute rules, notification channels, policies and agent commands are written to an append-only audit table and to structured logs with request IDs. Secrets never enter either. New alerts can be pushed to webhooks, chat and email, an agent that goes quiet or says it is stopping raises an alert, an agent losing events is flagged, and a failing notification channel is shown as failing. |
| A10 Mishandling of exceptional conditions | Errors fail closed with generic messages and a request ID; details stay in server logs. A malformed record never fails a whole batch, and database errors roll the transaction back. |

The agent API, mapped to the OWASP API Security Top 10 (2023):

| Risk | What the manager does |
| --- | --- |
| API1 Broken object level authorization | Every query is scoped to the agent the token belongs to: its own policy, its own commands, results only for its own commands (anything else is a 404, not a hint). |
| API2 Broken authentication | 256-bit tokens looked up by SHA-256 digest; disabled agents and rotated tokens stop working at once, including a long-poll already waiting. |
| API3 Broken object property level authorization | No mass assignment: each field an agent sends is type-checked and bounded and written explicitly. Agent-reported values such as hostnames are shown as reported but never decide what another agent's alerts do. |
| API4 Unrestricted resource consumption | Body size, records per batch, record size, list lengths and result size are capped; a per-agent rate limit, a per-agent hourly alert cap, and a few long-poll slots per agent. The pre-authentication failure throttle is off on the agent API, so junk from one address cannot lock out the agents behind it (a NAT or proxy). |
| API5 Broken function level authorization | Separate applications and authentication backends: agent tokens never reach dashboard routes, and sessions never reach the agent API. |
| API6 Unrestricted access to sensitive business flows | Notifications are coalesced into digests per channel, and the hourly alert cap bounds what one agent can push at operators. |
| API7 Server side request forgery | The manager fetches nothing on an agent's behalf; outbound webhooks are set by administrators and checked as described above. |
| API8 Security misconfiguration | No CORS, docs off, the dashboard's security headers plus `no-store`, generic error bodies. |
| API9 Improper inventory management | Four versioned endpoints under `/api/v1`, no debug or legacy routes, no published schema. |
| API10 Unsafe consumption of APIs | Agent data is validated on the way in and escaped on the way out (templates, CSV export with formula escaping, single-line notification text); nothing from an agent is executed or followed. |

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
