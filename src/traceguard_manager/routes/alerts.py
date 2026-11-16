"""The overview, the alert list and detail pages, triage actions, exports and mute rules."""

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import urlencode

from flasgo import Body, Request, Response, abort

from .. import accounts, alerts, charts, fleet, mutes
from ..models import AlertKind, AlertStatus, Role, User, utcnow
from ..webcontext import Web, page_count, parse_uuid, query_params

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
# Exact-match filters with no form control; each is shown as a chip that removes it.
PIVOTS: tuple[str, ...] = ("rule", "host", "hour", "tag", "tactic", "technique")
MUTE_SCOPES: tuple[str, ...] = ("rule", "rule_host", "host")


@dataclass(slots=True)
class AlertStatusBody:
    # Either the alerts ticked on the page, or the filters of the list to change everything it matches.
    ids: list[str] | None = None
    filter: dict[str, str] | None = None
    # Without a status this only adds the note.
    status: str | None = None
    note: str | None = None


@dataclass(slots=True)
class AlertAssignBody:
    ids: list[str]
    # A user id, "me", or empty for nobody.
    assignee: str = ""


@dataclass(slots=True)
class MuteBody:
    reason: str
    duration: str = "24h"
    # From an alert: which of its rule and host to mute.
    alert_id: str | None = None
    scope: str | None = None
    # Or spelled out directly.
    rule_id: str | None = None
    hostname: str | None = None


@dataclass(frozen=True, slots=True)
class Pivot:
    """An exact-match alert filter the list is narrowed by."""

    name: str
    label: str
    text: str
    value: str
    remove_url: str


def _hour_label(bucket: int | None) -> str | None:
    if bucket is None:
        return None
    return datetime.fromtimestamp(bucket * 3600, tz=UTC).strftime("%Y-%m-%d %H:00 UTC")


def _alerts_url(params: dict[str, str]) -> str:
    return f"/alerts?{urlencode(params)}" if params else "/alerts"


def _parse_ids(values: list[str], limit: int) -> list[uuid.UUID]:
    try:
        return [uuid.UUID(value) for value in values[: limit + 1]]
    except ValueError:
        raise alerts.AlertError("One of the selected alerts is not valid.") from None


def register(web: Web) -> None:
    app, database, signal = web.app, web.database, web.signal
    requires, current, render, log_action = web.requires, web.current, web.render, web.log_action
    dialect = database.dialect

    async def triage_users(session: Any) -> list[User]:
        """People an alert can be given to: active accounts that are allowed to triage."""
        return [
            user
            for user in await accounts.list_users(session)
            if user.is_active and user.role in {Role.ANALYST.value, Role.ADMIN.value}
        ]

    # ---- overview -------------------------------------------------------

    @app.get("/", name="dashboard")
    @requires("alerts:read")
    async def dashboard(request: Request) -> Response:
        now = utcnow()
        async with database.session() as session:
            stats = await alerts.dashboard_stats(session, now=now)
            recent, _ = await alerts.list_alerts(
                session, alerts.AlertFilter(status=AlertStatus.OPEN.value), now=now, dialect=dialect
            )
            _, summary = fleet.describe_fleet(await fleet.list_agents(session), now=now, offline_after=web.offline_after)
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

    # ---- list -----------------------------------------------------------

    @app.get("/alerts", name="alerts")
    @requires("alerts:read")
    async def alert_list(request: Request) -> Response:
        me = current(request)
        params = query_params(request)
        filters = alerts.AlertFilter.from_params(params)
        group = params.get("group") if params.get("group") in alerts.GROUPS else None
        now = utcnow()
        async with database.session() as session:
            agents = await fleet.list_agents(session)
            users = await accounts.list_users(session)
            if group:
                groups = await alerts.grouped(session, filters, by=group, now=now, dialect=dialect, viewer_id=me.id)
                rows, total = [], sum(item.total for item in groups)
            else:
                groups = []
                rows, total = await alerts.list_alerts(session, filters, now=now, dialect=dialect, viewer_id=me.id)

        query = filters.to_query()
        pivot_text = {name: query.get(name) for name in PIVOTS} | {"hour": _hour_label(filters.hour)}
        pivots = [
            Pivot(
                name=name,
                label=name.capitalize(),
                text=shown,
                value=query[name],
                remove_url=_alerts_url(
                    {key: value for key, value in query.items() if key != name} | ({"group": group} if group else {})
                ),
            )
            for name, shown in pivot_text.items()
            if shown
        ]

        def sort_url(column: str) -> str:
            # A second click on the same heading reverses it; a new heading starts descending.
            ascending = filters.sort == column and filters.descending
            changed = {key: value for key, value in query.items() if key not in {"sort", "dir"}}
            if column != "time":
                changed["sort"] = column
            if ascending:
                changed["dir"] = "asc"
            return _alerts_url(changed)

        group_key = "rule" if group == "rule" else "host"
        return render(
            request,
            "alerts.html",
            alerts=rows,
            groups=[
                (item, _alerts_url(query | {group_key: item.key}) if item.key else None, alerts.level_for_rank(item.top_rank))
                for item in groups
            ],
            group=group,
            group_urls={name: _alerts_url(query | {"group": name}) for name in alerts.GROUPS} | {"none": _alerts_url(query)},
            total=total,
            filters=filters,
            pivots=pivots,
            agents=agents,
            agent_names={item.id: item.name for item in agents},
            usernames={item.id: item.username for item in users},
            owners=[item for item in users if item.is_active and item.role != Role.VIEWER.value],
            page=filters.page,
            pages=page_count(total, alerts.PAGE_SIZE),
            base_query=urlencode(query),
            filter_json=json.dumps(query),
            sort_urls={column: sort_url(column) for column in alerts.SORTS},
            export_urls={kind: f"/alerts/export?{urlencode(query | {'format': kind})}" for kind in ("csv", "json")},
            statuses=[item.value for item in AlertStatus],
            kinds=[item.value for item in AlertKind],
            levels=alerts.LEVELS,
            ranges=alerts.RANGE_LABELS,
            bulk_limit=alerts.MAX_BULK_MATCHING,
        )

    @app.get("/alerts/export", name="alert-export")
    @requires("alerts:read")
    @app.ratelimit(20, per=60, scope="export")
    async def alert_export(request: Request) -> Response:
        me = current(request)
        params = query_params(request)
        filters = alerts.AlertFilter.from_params(params)
        as_json = params.get("format") == "json"
        now = utcnow()
        async with database.session() as session:
            rows = await alerts.export_rows(session, filters, now=now, dialect=dialect, viewer_id=me.id)
            agent_names = {item.id: item.name for item in await fleet.list_agents(session)}
            usernames = {item.id: item.username for item in await accounts.list_users(session)}
        records = [alerts.export_record(row, agent_names=agent_names, usernames=usernames) for row in rows]
        # Taking alert data out of the manager is worth a line in the audit log.
        await log_action(
            request,
            "alert.export",
            detail={"format": "json" if as_json else "csv", "rows": len(records), "filters": filters.to_query()},
        )
        stamp = now.strftime("%Y%m%d-%H%M%S")
        if as_json:
            response = Response.json(records)
            response.headers["content-disposition"] = f'attachment; filename="traceguard-alerts-{stamp}.json"'
            return response
        return Response(
            body=alerts.to_csv(records).encode(),
            headers={"content-disposition": f'attachment; filename="traceguard-alerts-{stamp}.csv"'},
            content_type="text/csv; charset=utf-8",
        )

    # ---- detail ---------------------------------------------------------

    @app.get("/alerts/<alert_id>", name="alert-detail")
    @requires("alerts:read")
    async def alert_detail(request: Request, alert_id: str) -> Response:
        now = utcnow()
        async with database.session() as session:
            alert = await alerts.get_alert(session, parse_uuid(alert_id))
            if alert is None:
                abort(404)
            agent = await fleet.get_agent(session, alert.agent_id)
            history = await alerts.history(session, alert.id)
            related = await alerts.related(session, alert)
            owners = await triage_users(session)
            owner = await accounts.get_user(session, alert.assignee_id) if alert.assignee_id else None
            muted_by = [
                rule
                for rule in await mutes.active(session, now=now)
                if mutes.matches([rule], rule_id=alert.rule_id, hostname=alert.hostname)
            ]
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
            history=history,
            related=related,
            owners=owners,
            owner=owner,
            muted_by=muted_by,
            mute_durations=mutes.DURATION_LABELS,
        )

    # ---- triage ---------------------------------------------------------

    @app.post("/alerts/status", name="alert-status")
    @requires("alerts:write")
    async def alert_status(request: Request, body: Annotated[AlertStatusBody, Body()]) -> Response:
        user = current(request)
        now = utcnow()
        if body.filter is not None:
            if body.status is None:
                raise alerts.AlertError("Choose a status.")
            filters = alerts.AlertFilter.from_params(body.filter)
            async with database.session() as session:
                changed = await alerts.set_status_matching(
                    session,
                    filters,
                    status=body.status,
                    actor=user.username,
                    note=body.note,
                    now=now,
                    dialect=dialect,
                    viewer_id=user.id,
                )
            target = "all matching"
            detail: dict[str, Any] = {"status": body.status, "changed": changed, "filters": filters.to_query()}
        else:
            ids = _parse_ids(body.ids or [], alerts.MAX_BULK)
            async with database.session() as session:
                if body.status is None:
                    alert = await alerts.get_alert(session, ids[0]) if len(ids) == 1 else None
                    if alert is None:
                        raise alerts.AlertError("Open one alert to add a note to it.")
                    await alerts.add_note(session, alert=alert, note=body.note or "", actor=user.username, now=now)
                    changed = 0
                else:
                    changed = await alerts.set_status(
                        session, alert_ids=ids, status=body.status, actor=user.username, note=body.note, now=now
                    )
            target = str(ids[0]) if len(ids) == 1 else f"{len(ids)} alerts"
            detail = {"status": body.status, "changed": changed}
        await log_action(request, "alert.status" if body.status else "alert.note", target=target, detail=detail)
        signal.notify()
        return Response.json({"changed": changed})

    @app.post("/alerts/assign", name="alert-assign")
    @requires("alerts:write")
    async def alert_assign(request: Request, body: Annotated[AlertAssignBody, Body()]) -> Response:
        user = current(request)
        ids = _parse_ids(body.ids, alerts.MAX_BULK)
        async with database.session() as session:
            assignee: User | None = None
            if body.assignee:
                assignee = await accounts.get_user(session, user.id if body.assignee == "me" else parse_uuid(body.assignee))
                if assignee is None or not assignee.is_active or assignee.role == Role.VIEWER.value:
                    raise alerts.AlertError("That person cannot be given alerts.")
            changed = await alerts.assign(session, alert_ids=ids, assignee=assignee, actor=user.username, now=utcnow())
        await log_action(
            request,
            "alert.assign",
            target=str(ids[0]) if len(ids) == 1 else f"{len(ids)} alerts",
            detail={"assignee": assignee.username if assignee else None, "changed": changed},
        )
        return Response.json({"changed": changed, "assignee": assignee.username if assignee else None})

    # ---- mute rules -----------------------------------------------------

    @app.get("/mutes", name="mutes")
    @requires("alerts:read")
    async def mute_list(request: Request) -> Response:
        async with database.session() as session:
            rules = await mutes.active(session, now=utcnow())
        return render(request, "mutes.html", rules=rules, durations=mutes.DURATION_LABELS)

    @app.post("/mutes", name="mute-create")
    @requires("alerts:write")
    async def mute_create(request: Request, body: Annotated[MuteBody, Body()]) -> Response:
        user = current(request)
        rule_id, hostname = body.rule_id, body.hostname
        async with database.session() as session:
            if body.alert_id is not None:
                alert = await alerts.get_alert(session, parse_uuid(body.alert_id))
                if alert is None or body.scope not in MUTE_SCOPES:
                    raise mutes.MuteError("Choose what to mute.")
                if body.scope != "host" and not alert.rule_id:
                    raise mutes.MuteError("This alert did not come from a rule, so only its host can be muted.")
                rule_id = alert.rule_id if body.scope in {"rule", "rule_host"} else None
                hostname = alert.hostname if body.scope in {"rule_host", "host"} else None
            rule, muted = await mutes.create(
                session,
                rule_id=rule_id,
                hostname=hostname,
                reason=body.reason,
                duration=body.duration,
                actor=user.username,
                now=utcnow(),
            )
        await log_action(
            request,
            "mute.create",
            target=rule.rule_id or rule.hostname,
            detail={"rule": rule.rule_id, "host": rule.hostname, "duration": body.duration, "muted_now": muted},
        )
        signal.notify()
        return Response.json({"id": str(rule.id), "muted": muted}, status_code=201)

    @app.delete("/mutes/<mute_id>", name="mute-delete")
    @requires("alerts:write")
    async def mute_delete(request: Request, mute_id: str) -> Response:
        async with database.session() as session:
            rule = await mutes.get(session, parse_uuid(mute_id))
            if rule is None:
                abort(404)
            await mutes.remove(session, rule)
        await log_action(
            request, "mute.delete", target=rule.rule_id or rule.hostname, detail={"rule": rule.rule_id, "host": rule.hostname}
        )
        return Response.json({"ok": True})
