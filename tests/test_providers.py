"""Unit tests for provider detection and header extraction."""

from __future__ import annotations

from agent_guard.providers import (
    Provider,
    ProviderConfig,
    detect_provider,
    extract_forward_headers,
    get_provider_config,
)

# -- detect_provider ----------------------------------------------------------


class TestDetectProvider:
    def test_anthropic_route(self):
        assert detect_provider("/v1/messages") is Provider.ANTHROPIC

    def test_openai_route(self):
        assert detect_provider("/v1/chat/completions") is Provider.OPENAI

    def test_unknown_route(self):
        assert detect_provider("/v1/unknown") is None

    def test_empty_path(self):
        assert detect_provider("") is None


# -- get_provider_config ------------------------------------------------------


class TestGetProviderConfig:
    def test_anthropic_config(self):
        cfg = get_provider_config(Provider.ANTHROPIC)
        assert cfg.name == Provider.ANTHROPIC
        assert "anthropic.com" in cfg.base_url
        assert cfg.auth_header == "x-api-key"

    def test_openai_config(self):
        cfg = get_provider_config(Provider.OPENAI)
        assert cfg.name == Provider.OPENAI
        assert "openai.com" in cfg.base_url
        assert cfg.auth_header == "authorization"


# -- ProviderConfig.build_forward_url -----------------------------------------


class TestProviderConfigBuildUrl:
    def test_anthropic_url(self):
        cfg = get_provider_config(Provider.ANTHROPIC)
        url = cfg.build_forward_url("/v1/messages")
        assert url == "https://api.anthropic.com/v1/messages"

    def test_openai_url(self):
        cfg = get_provider_config(Provider.OPENAI)
        url = cfg.build_forward_url("/v1/chat/completions")
        assert url == "https://api.openai.com/v1/chat/completions"


# -- extract_forward_headers --------------------------------------------------


class TestExtractForwardHeaders:
    def test_anthropic_headers(self):
        raw = {
            "x-api-key": "sk-ant-test",
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "user-agent": "test/1.0",
        }
        headers = extract_forward_headers(raw, Provider.ANTHROPIC)
        assert headers["x-api-key"] == "sk-ant-test"
        assert headers["content-type"] == "application/json"
        assert headers["anthropic-version"] == "2023-06-01"
        # user-agent should NOT be forwarded
        assert "user-agent" not in headers

    def test_openai_headers(self):
        raw = {
            "authorization": "Bearer sk-test",
            "content-type": "application/json",
        }
        headers = extract_forward_headers(raw, Provider.OPENAI)
        assert headers["authorization"] == "Bearer sk-test"
        assert headers["content-type"] == "application/json"
        # anthropic-version should NOT be present for OpenAI
        assert "anthropic-version" not in headers

    def test_missing_auth_header(self):
        raw = {"content-type": "application/json"}
        headers = extract_forward_headers(raw, Provider.ANTHROPIC)
        assert "x-api-key" not in headers
        assert headers["content-type"] == "application/json"

    def test_empty_headers(self):
        headers = extract_forward_headers({}, Provider.OPENAI)
        assert headers == {}

    def test_anthropic_without_version(self):
        raw = {"x-api-key": "sk-ant-test"}
        headers = extract_forward_headers(raw, Provider.ANTHROPIC)
        assert "anthropic-version" not in headers
        assert headers["x-api-key"] == "sk-ant-test"


# -- ProviderConfig immutability ----------------------------------------------


class TestProviderConfigImmutable:
    def test_frozen(self):
        cfg = ProviderConfig(
            name=Provider.ANTHROPIC,
            base_url="https://example.com",
            auth_header="x-api-key",
        )
        with __import__("pytest").raises(AttributeError):
            cfg.base_url = "https://other.com"  # type: ignore[misc]
