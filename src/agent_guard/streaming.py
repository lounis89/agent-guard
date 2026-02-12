"""SSE stream forwarding and parsing utilities."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable


@runtime_checkable
class AsyncTextStream(Protocol):
    """Protocol for any object that supports async text iteration."""

    def aiter_text(self) -> AsyncIterator[str]: ...


async def forward_stream(response: AsyncTextStream) -> AsyncIterator[str]:
    """Forward an SSE stream from the provider as-is (passthrough).

    Yields raw text chunks exactly as received from the upstream provider.
    This is the simplest mode — no inspection, just transparent forwarding.
    """
    async for chunk in response.aiter_text():
        yield chunk


async def iter_sse_events(response: AsyncTextStream) -> AsyncIterator[str]:
    """Parse an SSE stream and yield individual `data:` payloads.

    Each SSE event looks like:
        data: {"id": "msg_123", ...}\\n\\n

    This yields the JSON string after "data: " for each event,
    or the literal "[DONE]" for the terminal event.
    """
    buffer = ""
    async for chunk in response.aiter_text():
        buffer += chunk

        # SSE events are delimited by double newlines
        while "\n\n" in buffer:
            event, buffer = buffer.split("\n\n", 1)

            for line in event.splitlines():
                if line.startswith("data: "):
                    payload = line[6:]  # Strip "data: " prefix
                    yield payload
