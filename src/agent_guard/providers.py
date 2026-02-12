"""LLM provider detection and configuration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Provider(StrEnum):
    """Supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Immutable configuration for a single LLM provider."""

    name: Provider
    base_url: str
    auth_header: str

    def build_forward_url(self, path: str) -> str:
        """Build the full URL to forward to the real provider API."""
        return f"{self.base_url}{path}"


# -- Provider registry --------------------------------------------------------

PROVIDERS: dict[Provider, ProviderConfig] = {
    Provider.ANTHROPIC: ProviderConfig(
        name=Provider.ANTHROPIC,
        base_url="https://api.anthropic.com",
        auth_header="x-api-key",
    ),
    Provider.OPENAI: ProviderConfig(
        name=Provider.OPENAI,
        base_url="https://api.openai.com",
        auth_header="authorization",
    ),
}


# -- Route-to-provider mapping ------------------------------------------------

ROUTE_PROVIDER_MAP: dict[str, Provider] = {
    "/v1/messages": Provider.ANTHROPIC,
    "/v1/chat/completions": Provider.OPENAI,
}


def detect_provider(path: str) -> Provider | None:
    """Detect the LLM provider from the request path."""
    return ROUTE_PROVIDER_MAP.get(path)


def get_provider_config(provider: Provider) -> ProviderConfig:
    """Return the configuration for a given provider."""
    return PROVIDERS[provider]


def extract_forward_headers(
    raw_headers: dict[str, str],
    provider: Provider,
) -> dict[str, str]:
    """Extract and prepare headers to forward to the real provider.

    Forwards the authentication header and content-type.
    Adds provider-specific headers (e.g. anthropic-version).
    """
    config = PROVIDERS[provider]
    headers: dict[str, str] = {}

    # Forward auth header
    auth_value = raw_headers.get(config.auth_header)
    if auth_value:
        headers[config.auth_header] = auth_value

    # Forward content-type
    ct = raw_headers.get("content-type")
    if ct:
        headers["content-type"] = ct

    # Anthropic-specific: version header is required
    if provider == Provider.ANTHROPIC:
        av = raw_headers.get("anthropic-version")
        if av:
            headers["anthropic-version"] = av

    return headers
