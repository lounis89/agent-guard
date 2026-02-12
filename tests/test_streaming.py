"""Unit tests for SSE streaming utilities."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from agent_guard.streaming import forward_stream, iter_sse_events

# -- Helpers ------------------------------------------------------------------


class MockResponse:
    """Minimal mock for httpx.Response with async text iteration."""

    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks

    async def aiter_text(self) -> AsyncIterator[str]:
        for chunk in self._chunks:
            yield chunk


# -- forward_stream -----------------------------------------------------------


class TestForwardStream:
    @pytest.mark.asyncio
    async def test_passthrough(self):
        """Chunks are forwarded as-is."""
        response = MockResponse(["chunk1", "chunk2", "chunk3"])
        result = [chunk async for chunk in forward_stream(response)]
        assert result == ["chunk1", "chunk2", "chunk3"]

    @pytest.mark.asyncio
    async def test_empty_stream(self):
        """Empty stream yields nothing."""
        response = MockResponse([])
        result = [chunk async for chunk in forward_stream(response)]
        assert result == []

    @pytest.mark.asyncio
    async def test_single_chunk(self):
        """Single chunk is forwarded."""
        response = MockResponse(["only-one"])
        result = [chunk async for chunk in forward_stream(response)]
        assert result == ["only-one"]


# -- iter_sse_events ----------------------------------------------------------


class TestIterSseEvents:
    @pytest.mark.asyncio
    async def test_single_event(self):
        """Single SSE event is parsed correctly."""
        response = MockResponse(['data: {"id": "1"}\n\n'])
        events = [e async for e in iter_sse_events(response)]
        assert events == ['{"id": "1"}']

    @pytest.mark.asyncio
    async def test_multiple_events(self):
        """Multiple SSE events in one chunk."""
        response = MockResponse(['data: {"id": "1"}\n\ndata: {"id": "2"}\n\n'])
        events = [e async for e in iter_sse_events(response)]
        assert events == ['{"id": "1"}', '{"id": "2"}']

    @pytest.mark.asyncio
    async def test_split_across_chunks(self):
        """SSE event split across multiple chunks."""
        response = MockResponse(['data: {"id":', ' "1"}\n', "\n"])
        events = [e async for e in iter_sse_events(response)]
        assert events == ['{"id": "1"}']

    @pytest.mark.asyncio
    async def test_done_event(self):
        """[DONE] terminal event is yielded."""
        response = MockResponse(['data: {"id": "1"}\n\ndata: [DONE]\n\n'])
        events = [e async for e in iter_sse_events(response)]
        assert events == ['{"id": "1"}', "[DONE]"]

    @pytest.mark.asyncio
    async def test_ignores_non_data_lines(self):
        """Lines without 'data: ' prefix are ignored (e.g. event:, id:)."""
        response = MockResponse(["event: message\ndata: payload\n\n"])
        events = [e async for e in iter_sse_events(response)]
        assert events == ["payload"]

    @pytest.mark.asyncio
    async def test_empty_stream(self):
        """Empty stream yields no events."""
        response = MockResponse([])
        events = [e async for e in iter_sse_events(response)]
        assert events == []
