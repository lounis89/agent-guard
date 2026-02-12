"""Input inspector — parse incoming request bodies and evaluate against policy."""

from __future__ import annotations

import json

from agent_guard.engine import Decision, evaluate, redact_secrets
from agent_guard.models import Action, PolicyConfig, RequestContext, SessionTier
from agent_guard.providers import Provider


def _extract_message_content(body: dict, provider: Provider) -> str | None:
    """Pull the user-facing message text from the request body.

    Anthropic:  body.messages[-1].content  (string or list of blocks)
    OpenAI:     body.messages[-1].content  (string)
    """
    messages = body.get("messages")
    if not messages or not isinstance(messages, list):
        return None

    last = messages[-1]
    content = last.get("content")
    if content is None:
        return None

    # Anthropic content can be a list of blocks
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts) if parts else None

    if isinstance(content, str):
        return content

    return None


def _extract_session_tier(headers: dict[str, str]) -> SessionTier:
    """Read the session tier from an optional ``x-session-tier`` header."""
    raw = headers.get("x-session-tier", "")
    try:
        return SessionTier(raw)
    except ValueError:
        return SessionTier.UNKNOWN


def _extract_channel(headers: dict[str, str]) -> str | None:
    """Read the originating channel from an optional ``x-channel`` header."""
    return headers.get("x-channel") or None


def build_request_context(
    body: dict,
    headers: dict[str, str],
    provider: Provider,
) -> RequestContext:
    """Build a :class:`RequestContext` from a parsed request."""
    return RequestContext(
        provider=provider.value,
        session_tier=_extract_session_tier(headers),
        channel=_extract_channel(headers),
        message_content=_extract_message_content(body, provider),
    )


def inspect_request(
    raw_body: bytes,
    headers: dict[str, str],
    provider: Provider,
    policy: PolicyConfig,
) -> tuple[Decision, bytes]:
    """Inspect an inbound request body against *policy*.

    Returns:
        A ``(decision, body)`` tuple.  If the decision is REDACT the body
        will have secrets replaced; otherwise it is returned unchanged.
    """
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # If we can't parse the body we can't inspect it — allow through
        return Decision.allow(), raw_body

    ctx = build_request_context(body, headers, provider)
    decision = evaluate(policy, ctx)

    if decision.action == Action.REDACT:
        # Walk the messages and redact secrets from content
        messages = body.get("messages", [])
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = redact_secrets(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        block["text"] = redact_secrets(block.get("text", ""))
        return decision, json.dumps(body).encode()

    return decision, raw_body
