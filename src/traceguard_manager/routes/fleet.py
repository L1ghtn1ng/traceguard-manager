"""The fleet page, agent detail, and agent management."""

from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

from flasgo import Body, Request, Response, abort

from .. import alerts, fleet
from ..models import utcnow
from ..webcontext import Web, page_count, page_number, parse_uuid, query_params


@dataclass(slots=True)
class AgentCreateBody:
    name: str


@dataclass(slots=True)
class AgentEnabledBody:
    enabled: bool


@dataclass(slots=True)
class AgentUpdateBody:
    name: str | None = None
    # Comma or space separated.
    tags: str | None = None


def register(web: Web) -> None:
    app, database = web.app, web.database
    requires, render, log_action = web.requires, web.render, web.log_action
    offline_after = web.offline_after

    @app.get("/agents", name="agents")
    @requires("agents:read")
    async def agent_list(request: Request) -> Response:
        params = query_params(request)
        query = fleet.FleetQuery.from_params(params | {"page": page_number(params, fleet.MAX_PAGE)})
        now = utcnow()
        async with database.session() as session:
            everyone = await fleet.list_agents(session)
        views, summary = fleet.describe_fleet(everyone, now=now, offline_after=offline_after)
        shown, matching = fleet.select_views(views, query)
        base = query.to_query()

        def sort_url(column: str) -> str:
            changed = {key: value for key, value in base.items() if key not in {"sort", "dir"}}
            if column != "name":
                changed["sort"] = column
            if query.sort == column and not query.descending:
                changed["dir"] = "desc"
            return f"/agents?{urlencode(changed)}" if changed else "/agents"

        return render(
            request,
            "agents.html",
            agents=shown,
            fleet=summary,
            matching=matching,
            query=query,
            filtered=bool(query.text or query.status or query.tag),
            tags=fleet.all_tags(everyone),
            statuses=fleet.STATUSES,
            sort_urls={column: sort_url(column) for column in fleet.SORTS},
            page=query.page,
            pages=page_count(matching, fleet.PAGE_SIZE),
            base_query=urlencode(base),
            open_enrol="enrol" in params,
        )

    @app.get("/agents/<agent_id>", name="agent-detail")
    @requires("agents:read")
    async def agent_detail(request: Request, agent_id: str) -> Response:
        now = utcnow()
        wanted = parse_uuid(agent_id)
        async with database.session() as session:
            everyone = await fleet.list_agents(session)
            recent = await alerts.recent_for_agent(session, wanted)
        views, summary = fleet.describe_fleet(everyone, now=now, offline_after=offline_after)
        view = next((item for item in views if item.agent.id == wanted), None)
        if view is None:
            abort(404)
        return render(request, "agent_detail.html", view=view, agent=view.agent, fleet=summary, recent=recent)

    @app.get("/agents/<agent_id>/state", name="agent-state")
    @requires("agents:read")
    async def agent_state(agent_id: str) -> Response:
        """What the token dialog polls to say when an agent has connected with its current token."""
        async with database.session() as session:
            agent = await fleet.get_agent(session, parse_uuid(agent_id))
        if agent is None:
            abort(404)
        connected = agent.last_seen_at is not None and agent.last_seen_at >= agent.token_rotated_at
        return Response.json(
            {"status": fleet.agent_status(agent, now=utcnow(), offline_after=offline_after), "connected": connected}
        )

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
            agent = await fleet.get_agent(session, parse_uuid(agent_id))
            if agent is None:
                abort(404)
            token = fleet.rotate_token(agent, now=utcnow())
        await log_action(request, "agent.rotate_token", target=agent.name)
        return Response.json({"id": str(agent.id), "name": agent.name, "token": token})

    @app.post("/agents/<agent_id>/enabled", name="agent-enabled")
    @requires("agents:write")
    async def agent_enabled(request: Request, agent_id: str, body: Annotated[AgentEnabledBody, Body()]) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, parse_uuid(agent_id))
            if agent is None:
                abort(404)
            agent.enabled = body.enabled
        await log_action(request, "agent.enable" if body.enabled else "agent.disable", target=agent.name)
        return Response.json({"enabled": body.enabled})

    @app.patch("/agents/<agent_id>", name="agent-update")
    @requires("agents:write")
    async def agent_update(request: Request, agent_id: str, body: Annotated[AgentUpdateBody, Body()]) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, parse_uuid(agent_id))
            if agent is None:
                abort(404)
            before = agent.name
            tags = fleet.parse_tags(body.tags) if body.tags is not None else None
            await fleet.update_agent(session, agent, name=body.name, tags=tags)
        await log_action(request, "agent.update", target=before, detail={"name": agent.name, "tags": agent.tags})
        return Response.json({"name": agent.name, "tags": agent.tags})

    @app.delete("/agents/<agent_id>", name="agent-delete")
    @requires("agents:write")
    async def agent_delete(request: Request, agent_id: str) -> Response:
        async with database.session() as session:
            agent = await fleet.get_agent(session, parse_uuid(agent_id))
            if agent is None:
                abort(404)
            await session.delete(agent)
        await log_action(request, "agent.delete", target=agent.name)
        return Response.json({"redirect": "/agents"})
