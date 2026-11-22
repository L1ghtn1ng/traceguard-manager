"""Central policy: write, assign, and inspect the signed policies agents fetch."""

from dataclasses import dataclass
from typing import Annotated

from flasgo import Body, Request, Response, abort

from .. import audit, fleet, policies
from ..models import utcnow
from ..webcontext import Web, parse_uuid

STARTER_POLICY = """version: 1
# Served to agents whose tags match, or to every agent when this is the default.
# The agent merges it with any local policy file. See TraceGuard's docs/policy.md.
dns:
  block: []
"""


@dataclass(slots=True)
class PolicyBody:
    name: str
    content: str
    description: str = ""
    # Comma or space separated agent tags.
    tags: str = ""
    priority: str = "0"
    is_default: bool = False


def _priority(text: str) -> int:
    try:
        return int(text.strip() or "0")
    except ValueError:
        raise policies.PolicyError("Priority must be a whole number.") from None


def register(web: Web) -> None:
    app, database = web.app, web.database
    requires, render = web.requires, web.render

    @app.get("/policies", name="policies")
    @requires("policy:manage")
    async def policy_list(request: Request) -> Response:
        async with database.session() as session:
            every_policy = await policies.list_policies(session)
            agents = await fleet.list_agents(session)
        assigned: dict[str, list[policies.Assignment]] = {}
        unassigned = 0
        for agent in agents:
            if not agent.enabled:
                continue
            assignment = policies.assignment(agent, every_policy)
            if assignment.policy is None:
                unassigned += 1
            else:
                assigned.setdefault(str(assignment.policy.id), []).append(assignment)
        return render(
            request,
            "policies.html",
            policies=every_policy,
            assigned=assigned,
            unassigned=unassigned,
            public_key=web.signer.public_pem() if web.signer else None,
            public_url=web.config.public_url,
        )

    @app.get("/policies/public-key", name="policy-public-key")
    @requires("policy:manage")
    async def policy_public_key() -> Response:
        """The key agents verify policies with, for TRACEGUARD_POLICY_SIGNING_KEY."""
        if web.signer is None:
            abort(404)
        return Response(
            body=web.signer.public_pem().encode(),
            headers={"content-disposition": 'attachment; filename="manager-policy.pub"'},
            content_type="application/x-pem-file",
        )

    @app.get("/policies/new", name="policy-new")
    @requires("policy:manage")
    async def policy_new(request: Request) -> Response:
        async with database.session() as session:
            tags = fleet.all_tags(await fleet.list_agents(session))
        return render(request, "policy_edit.html", policy=None, content=STARTER_POLICY, tags=tags, agents=[])

    @app.get("/policies/<policy_id>", name="policy-detail")
    @requires("policy:manage")
    async def policy_detail(request: Request, policy_id: str) -> Response:
        async with database.session() as session:
            policy = await policies.get_policy(session, parse_uuid(policy_id))
            if policy is None:
                abort(404)
            every_policy = await policies.list_policies(session)
            agents = await fleet.list_agents(session)
        using = []
        for agent in agents:
            assignment = policies.assignment(agent, every_policy)
            if assignment.policy is not None and assignment.policy.id == policy.id:
                using.append((agent, assignment.state))
        return render(
            request,
            "policy_edit.html",
            policy=policy,
            content=policy.content,
            tags=fleet.all_tags(agents),
            agents=using,
        )

    @app.post("/policies", name="policy-create")
    @requires("policy:manage")
    async def policy_create(request: Request, body: Annotated[PolicyBody, Body()]) -> Response:
        actor = web.current(request).username
        async with database.session() as session:
            policy = await policies.create_policy(
                session,
                name=body.name,
                description=body.description,
                content=body.content,
                tags=fleet.parse_tags(body.tags),
                priority=_priority(body.priority),
                is_default=body.is_default,
                actor=actor,
                now=utcnow(),
            )
            policy_id, name, sha256 = policy.id, policy.name, policy.sha256
            # In the same transaction, so agents never get a policy change with no record of it.
            await audit.record(
                session,
                actor=actor,
                action="policy.create",
                target=name,
                client_ip=request.client_ip,
                request_id=request.request_id,
                detail={"sha256": sha256, "default": body.is_default},
            )
        return Response.json({"id": str(policy_id), "redirect": f"/policies/{policy_id}"}, status_code=201)

    @app.patch("/policies/<policy_id>", name="policy-update")
    @requires("policy:manage")
    async def policy_update(request: Request, policy_id: str, body: Annotated[PolicyBody, Body()]) -> Response:
        actor = web.current(request).username
        async with database.session() as session:
            policy = await policies.get_policy(session, parse_uuid(policy_id))
            if policy is None:
                abort(404)
            before = policy.sha256
            changed = await policies.update_policy(
                session,
                policy,
                name=body.name,
                description=body.description,
                content=body.content,
                tags=fleet.parse_tags(body.tags),
                priority=_priority(body.priority),
                is_default=body.is_default,
                actor=actor,
                now=utcnow(),
            )
            name, sha256 = policy.name, policy.sha256
            await audit.record(
                session,
                actor=actor,
                action="policy.update",
                target=name,
                client_ip=request.client_ip,
                request_id=request.request_id,
                detail={"from": before, "to": sha256, "document_changed": changed, "tags": fleet.parse_tags(body.tags)},
            )
        return Response.json({"id": policy_id, "sha256": sha256, "redirect": f"/policies/{policy_id}"})

    @app.delete("/policies/<policy_id>", name="policy-delete")
    @requires("policy:manage")
    async def policy_delete(request: Request, policy_id: str) -> Response:
        async with database.session() as session:
            policy = await policies.get_policy(session, parse_uuid(policy_id))
            if policy is None:
                abort(404)
            name, sha256 = policy.name, policy.sha256
            await policies.delete_policy(session, policy)
            await audit.record(
                session,
                actor=web.current(request).username,
                action="policy.delete",
                target=name,
                client_ip=request.client_ip,
                request_id=request.request_id,
                detail={"sha256": sha256},
            )
        return Response.json({"redirect": "/policies"})
