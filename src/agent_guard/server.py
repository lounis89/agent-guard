"""FastAPI application — routes and lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from agent_guard.config import load_guard_config, load_policy_config
from agent_guard.metrics import get_metrics_text
from agent_guard.providers import Provider, detect_provider
from agent_guard.proxy import LLMProxy

# -- Logging setup (structlog) ------------------------------------------------

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger("agent_guard.server")

# -- Lifespan -----------------------------------------------------------------

_guard_config = load_guard_config()
_policy = load_policy_config(_guard_config.policy_path)
proxy = LLMProxy(guard_config=_guard_config, policy=_policy)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Manage the proxy HTTP client lifecycle."""
    log.info(
        "server_started",
        mode=_guard_config.mode,
        policy_path=_guard_config.policy_path,
        rules_count=len(_policy.rules),
        host=_guard_config.host,
        port=_guard_config.port,
    )
    yield
    await proxy.close()
    log.info("server_stopped")


# -- App ----------------------------------------------------------------------

app = FastAPI(
    title="Agent Guard",
    description="LLM Security Proxy — inspect and control LLM API calls in real-time",
    version="0.1.0",
    lifespan=lifespan,
)


# -- Routes -------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        content=get_metrics_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post("/v1/messages")
async def proxy_anthropic(request: Request) -> JSONResponse:
    """Proxy for Anthropic Messages API."""
    return await proxy.forward(request, Provider.ANTHROPIC)


@app.post("/v1/chat/completions")
async def proxy_openai(request: Request) -> JSONResponse:
    """Proxy for OpenAI Chat Completions API."""
    return await proxy.forward(request, Provider.OPENAI)


@app.api_route("/{path:path}", methods=["POST"])
async def proxy_fallback(request: Request) -> JSONResponse:
    """Fallback route: detect provider from path automatically."""
    provider = detect_provider(request.url.path)
    if provider is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "unknown_route",
                "detail": f"No provider mapped for path: {request.url.path}",
            },
        )
    return await proxy.forward(request, provider)
