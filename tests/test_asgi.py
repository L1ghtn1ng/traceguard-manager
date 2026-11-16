from flasgo import TestClient

from .conftest import Site
from .helpers import data, detection


async def test_composite_routes_agents_and_browsers_to_the_right_app(site: Site) -> None:
    client = TestClient(site.manager)  # ty: ignore[invalid-argument-type]

    # Agent traffic: bearer auth, no CSRF token or Origin header needed.
    ingest = await client.arequest(
        "POST", "/api/v1/events", json=[detection()], headers={"authorization": f"Bearer {site.agent_token}"}
    )
    assert ingest.status_code == 200
    assert data(ingest)["stored"] == 1

    # Dashboard traffic: the same kind of request without CSRF is refused.
    login = await client.arequest("POST", "/auth/login", json={"username": "admin", "password": "x" * 16})
    assert login.status_code == 403

    page = await client.arequest("GET", "/login", headers={"accept": "text/html"})
    assert page.status_code == 200
    assert "TraceGuard Manager" in page.text


async def test_agent_tokens_do_not_open_the_dashboard(site: Site) -> None:
    client = TestClient(site.manager)  # ty: ignore[invalid-argument-type]
    response = await client.arequest("GET", "/alerts", headers={"authorization": f"Bearer {site.agent_token}"})
    assert response.status_code == 401


async def test_dashboard_sessions_do_not_open_the_ingest_api(site: Site) -> None:
    browser = await site.admin()
    client = TestClient(site.manager)  # ty: ignore[invalid-argument-type]
    response = await client.arequest(
        "POST",
        "/api/v1/events",
        json=[detection()],
        headers={"cookie": f"flasgo-session={browser.session_cookie()}"},
    )
    assert response.status_code == 401


async def test_static_assets_are_served_with_safe_types(site: Site) -> None:
    client = TestClient(site.manager)  # ty: ignore[invalid-argument-type]
    css = await client.arequest("GET", "/static/css/app.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert css.headers["x-content-type-options"] == "nosniff"
    js = await client.arequest("GET", "/static/js/app.js")
    assert js.status_code == 200
    assert "innerHTML" not in js.text
    assert (await client.arequest("GET", "/static/../config.py")).status_code in {400, 404}
    assert (await client.arequest("GET", "/static/%2e%2e/config.py")).status_code in {400, 404}
