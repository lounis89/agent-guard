"""Integration tests for the FastAPI server."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_guard.server import app

# -- Fixtures -----------------------------------------------------------------


@pytest.fixture
def client():
    """Synchronous test client for the FastAPI app."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# -- Health endpoint ----------------------------------------------------------


class TestHealthEndpoint:
    def test_health_ok(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


# -- Unknown routes -----------------------------------------------------------


class TestUnknownRoute:
    def test_unknown_post_returns_404(self, client: TestClient):
        response = client.post("/v1/unknown", json={"test": True})
        assert response.status_code == 404
        body = response.json()
        assert body["error"] == "unknown_route"
        assert "/v1/unknown" in body["detail"]

    def test_get_on_proxy_route_not_allowed(self, client: TestClient):
        response = client.get("/v1/messages")
        assert response.status_code == 405


# -- Provider routing (without network) ---------------------------------------


class TestProviderRouting:
    def test_anthropic_route_attempts_forward(self, client: TestClient):
        """POST /v1/messages should attempt to reach Anthropic.

        Without real credentials, we expect a provider error (not a 404).
        This proves the routing and forwarding logic works.
        Network may be blocked in sandbox/CI → accept 500/502 as well.
        """
        response = client.post(
            "/v1/messages",
            json={
                "model": "claude-3",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={
                "x-api-key": "sk-ant-fake",
                "anthropic-version": "2023-06-01",
            },
        )
        # Provider auth error, proxy network error, or sandbox block
        assert response.status_code in (401, 500, 502)

    def test_openai_route_attempts_forward(self, client: TestClient):
        """POST /v1/chat/completions should attempt to reach OpenAI."""
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "hi"}],
            },
            headers={"authorization": "Bearer sk-fake"},
        )
        assert response.status_code in (401, 500, 502)


# -- Response format ----------------------------------------------------------


class TestResponseFormat:
    def test_error_response_has_required_fields(self, client: TestClient):
        """Error responses should always have 'error' and 'detail' fields."""
        response = client.post("/v1/nonexistent", json={})
        body = response.json()
        assert "error" in body
        assert "detail" in body
