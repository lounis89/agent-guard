"""Core proxy logic — forward requests to LLM providers with policy inspection."""

from __future__ import annotations

import time

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse

from agent_guard.inspectors.request import inspect_request
from agent_guard.inspectors.response import inspect_stream
from agent_guard.models import Action, GuardConfig, GuardMode, PolicyConfig, SessionTier
from agent_guard.providers import (
    Provider,
    extract_forward_headers,
    get_provider_config,
)
from agent_guard.streaming import forward_stream


class LLMProxy:
    """Security proxy that inspects requests and responses against a policy.

    In **enforce** mode, dangerous requests are blocked (403) and secrets
    are redacted before forwarding.  In **dry-run** mode, decisions are
    logged but every request is forwarded unchanged.
    """

    def __init__(
        self,
        guard_config: GuardConfig,
        policy: PolicyConfig,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0))
        self._guard_config = guard_config
        self._policy = policy

    @property
    def policy(self) -> PolicyConfig:
        return self._policy

    @property
    def guard_config(self) -> GuardConfig:
        return self._guard_config

    async def close(self) -> None:
        """Shutdown the underlying HTTP client."""
        await self._client.aclose()

    async def forward(
        self, request: Request, provider: Provider
    ) -> StreamingResponse | JSONResponse:
        """Inspect a request, forward it if allowed, and inspect the response.

        Steps:
        1. Read the request body
        2. Inspect input against policy (block / redact / allow)
        3. Prepare headers for the provider
        4. Stream the request to the provider
        5. Inspect the response stream for tool calls
        6. Stream the (possibly modified) response back to the caller
        """
        import structlog

        from agent_guard.metrics import (
            BLOCKED_TOTAL,
            DECISIONS_TOTAL,
            REQUEST_LATENCY,
            REQUESTS_TOTAL,
        )

        log = structlog.get_logger("agent_guard.proxy")
        start_time = time.monotonic()
        body = await request.body()
        raw_headers = {k: v for k, v in request.headers.items()}

        # ── 1. Input inspection ─────────────────────────────────────────
        REQUESTS_TOTAL.labels(provider=provider.value, path=request.url.path).inc()

        decision, body = inspect_request(body, raw_headers, provider, self._policy)

        session_tier_raw = raw_headers.get("x-session-tier", "unknown")
        try:
            session_tier = SessionTier(session_tier_raw)
        except ValueError:
            session_tier = SessionTier.UNKNOWN

        DECISIONS_TOTAL.labels(action=decision.action, rule_id=decision.rule_id or "").inc()

        log.info(
            "request_inspected",
            provider=provider.value,
            action=decision.action,
            rule_id=decision.rule_id,
            mode=self._guard_config.mode,
            path=request.url.path,
        )

        if decision.action == Action.BLOCK and self._guard_config.mode == GuardMode.ENFORCE:
            BLOCKED_TOTAL.labels(rule_id=decision.rule_id or "").inc()
            log.warning(
                "request_blocked",
                rule_id=decision.rule_id,
                reason=decision.reason,
            )
            REQUEST_LATENCY.labels(provider=provider.value).observe(time.monotonic() - start_time)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "blocked_by_policy",
                    "rule_id": decision.rule_id,
                    "detail": decision.reason,
                },
            )

        # ── 2. Forward to provider ──────────────────────────────────────
        config = get_provider_config(provider)
        forward_url = config.build_forward_url(request.url.path)
        headers = extract_forward_headers(raw_headers, provider)

        try:
            provider_response = await self._client.send(
                self._client.build_request(
                    method="POST",
                    url=forward_url,
                    content=body,
                    headers=headers,
                ),
                stream=True,
            )
        except httpx.RequestError as exc:
            log.error("provider_unreachable", provider=provider.value, error=str(exc))
            return JSONResponse(
                status_code=502,
                content={
                    "error": "provider_unavailable",
                    "detail": f"Could not reach {provider.value}: {exc}",
                },
            )

        # Non-200 → read the error body and return it directly
        if provider_response.status_code != 200:
            error_body = await provider_response.aread()
            await provider_response.aclose()
            return JSONResponse(
                status_code=provider_response.status_code,
                content={
                    "error": "provider_error",
                    "detail": error_body.decode("utf-8", errors="replace"),
                },
            )

        # ── 3. Response inspection ──────────────────────────────────────
        content_type = provider_response.headers.get("content-type", "text/event-stream")

        # Only inspect SSE streams; non-streaming responses pass through
        if "text/event-stream" in content_type:
            stream = inspect_stream(
                provider_response,
                policy=self._policy,
                provider=provider.value,
                mode=self._guard_config.mode,
                session_tier=session_tier,
                channel=raw_headers.get("x-channel"),
            )
        else:
            stream = forward_stream(provider_response)

        REQUEST_LATENCY.labels(provider=provider.value).observe(time.monotonic() - start_time)

        return StreamingResponse(
            content=stream,
            status_code=200,
            media_type=content_type,
        )
