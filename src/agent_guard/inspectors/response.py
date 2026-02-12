"""Output inspector — inspect SSE stream chunks for tool calls."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import structlog

from agent_guard.engine import evaluate, redact_secrets
from agent_guard.models import Action, GuardMode, PolicyConfig, RequestContext, SessionTier
from agent_guard.streaming import AsyncTextStream

log = structlog.get_logger("agent_guard.inspectors.response")


def _extract_tool_call_anthropic(event: dict) -> tuple[str | None, str | None]:
    """Extract tool name and args from an Anthropic SSE event.

    Anthropic streams tool use in two phases:
      1. content_block_start  → type=tool_use, name=...
      2. content_block_delta  → partial_json (arguments)
    """
    event_type = event.get("type", "")

    if event_type == "content_block_start":
        block = event.get("content_block", {})
        if block.get("type") == "tool_use":
            return block.get("name"), json.dumps(block.get("input", {}))

    if event_type == "content_block_delta":
        delta = event.get("delta", {})
        if delta.get("type") == "input_json_delta":
            return None, delta.get("partial_json", "")

    return None, None


def _extract_tool_call_openai(event: dict) -> tuple[str | None, str | None]:
    """Extract tool name and args from an OpenAI SSE event.

    OpenAI streams tool calls inside choices[].delta.tool_calls[].
    """
    choices = event.get("choices", [])
    if not choices:
        return None, None

    delta = choices[0].get("delta", {})
    tool_calls = delta.get("tool_calls", [])
    if not tool_calls:
        return None, None

    tc = tool_calls[0]
    fn = tc.get("function", {})
    name = fn.get("name")
    args = fn.get("arguments")
    return name, args


async def inspect_stream(
    response: AsyncTextStream,
    *,
    policy: PolicyConfig,
    provider: str,
    mode: GuardMode,
    session_tier: SessionTier = SessionTier.UNKNOWN,
    channel: str | None = None,
) -> AsyncIterator[str]:
    """Wrap an upstream SSE stream, inspecting each event for tool calls.

    Yields raw text chunks to the client.  When a tool call is detected
    and the policy says BLOCK (in enforce mode), the stream is terminated
    with an error event.  REDACT replaces secrets in the chunk.
    """
    buffer = ""
    current_tool_name: str | None = None
    accumulated_args = ""

    async for chunk in response.aiter_text():
        buffer += chunk

        # Process complete SSE events (delimited by double newlines)
        while "\n\n" in buffer:
            event_text, buffer = buffer.split("\n\n", 1)
            output_lines: list[str] = []

            for line in event_text.splitlines():
                if not line.startswith("data: "):
                    output_lines.append(line)
                    continue

                payload = line[6:]  # strip "data: "

                # Terminal event
                if payload.strip() == "[DONE]":
                    output_lines.append(line)
                    continue

                # Try to parse the JSON payload
                try:
                    event_data = json.loads(payload)
                except json.JSONDecodeError:
                    output_lines.append(line)
                    continue

                # Extract tool call info
                if provider == "anthropic":
                    name, args = _extract_tool_call_anthropic(event_data)
                else:
                    name, args = _extract_tool_call_openai(event_data)

                if name:
                    current_tool_name = name
                    accumulated_args = ""
                if args:
                    accumulated_args += args

                # Evaluate once we have a tool name
                if current_tool_name:
                    ctx = RequestContext(
                        provider=provider,
                        session_tier=session_tier,
                        channel=channel,
                        tool_name=current_tool_name,
                        tool_args=accumulated_args or None,
                    )
                    decision = evaluate(policy, ctx)

                    if decision.action == Action.BLOCK and mode == GuardMode.ENFORCE:
                        log.warning(
                            "tool_call_blocked",
                            tool=current_tool_name,
                            rule_id=decision.rule_id,
                            reason=decision.reason,
                        )
                        # Emit an error event and terminate
                        error_event = json.dumps(
                            {
                                "type": "error",
                                "error": {
                                    "type": "agent_guard_blocked",
                                    "message": (
                                        f"Blocked by rule '{decision.rule_id}': {decision.reason}"
                                    ),
                                },
                            }
                        )
                        yield f"data: {error_event}\n\n"
                        return

                    if decision.action == Action.REDACT:
                        log.info(
                            "tool_call_redacted",
                            tool=current_tool_name,
                            rule_id=decision.rule_id,
                        )
                        payload = redact_secrets(payload)
                        line = f"data: {payload}"

                output_lines.append(line)

            yield "\n".join(output_lines) + "\n\n"

        # If there's remaining buffer that doesn't form a complete event yet,
        # keep accumulating.

    # Flush any remaining buffer content
    if buffer.strip():
        yield buffer
