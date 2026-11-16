from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from flasgo import TestClient, TestResponse

from traceguard_manager import accounts, fleet, security
from traceguard_manager.asgi import Manager, create_app
from traceguard_manager.config import Config

from .helpers import ADMIN_PASSWORD, ANALYST_PASSWORD, VIEWER_PASSWORD, Browser


@dataclass(slots=True)
class Site:
    """A manager with seeded accounts and one enrolled agent."""

    manager: Manager
    agent_id: str
    agent_token: str

    def browser(self) -> Browser:
        return Browser(TestClient(self.manager.web))

    def agent_client(self) -> TestClient:
        return TestClient(self.manager.api)

    async def ingest(self, records: Sequence[object], *, token: str | None = None) -> TestResponse:
        return await self.agent_client().arequest(
            "POST",
            "/api/v1/events",
            json=list(records),
            headers={"authorization": f"Bearer {token or self.agent_token}"},
        )

    async def signed_in(self, username: str, password: str) -> Browser:
        browser = self.browser()
        response = await browser.login(username, password)
        assert response.status_code == 200, response.text
        return browser

    async def admin(self) -> Browser:
        return await self.signed_in("admin", ADMIN_PASSWORD)

    async def analyst(self) -> Browser:
        return await self.signed_in("analyst", ANALYST_PASSWORD)

    async def viewer(self) -> Browser:
        return await self.signed_in("viewer", VIEWER_PASSWORD)


@pytest.fixture(autouse=True, scope="session")
def fast_password_hashing() -> Iterator[None]:
    """Use minimal Argon2 costs so the suite is not dominated by key stretching."""
    patch = pytest.MonkeyPatch()
    hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    patch.setattr(security, "_hasher", hasher)
    patch.setattr(security, "_DUMMY_HASH", hasher.hash("placeholder"))
    yield
    patch.undo()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.for_testing(database_url=f"sqlite+aiosqlite:///{tmp_path / 'manager.db'}")


@pytest.fixture
async def site(config: Config) -> AsyncIterator[Site]:
    manager = create_app(config)
    await manager.database.create_all()
    async with manager.database.session() as session:
        await accounts.create_user(session, username="admin", password=ADMIN_PASSWORD, role="admin")
        await accounts.create_user(session, username="analyst", password=ANALYST_PASSWORD, role="analyst")
        await accounts.create_user(session, username="viewer", password=VIEWER_PASSWORD, role="viewer")
        agent, token = await fleet.enroll_agent(session, name="web-01")
    try:
        yield Site(manager=manager, agent_id=str(agent.id), agent_token=token)
    finally:
        await manager.database.dispose()
