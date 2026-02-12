"""CLI entry point for Agent Guard."""

from __future__ import annotations

import uvicorn

from agent_guard.config import load_guard_config


def main() -> None:
    """Start the Agent Guard proxy server."""

    guard_config = load_guard_config()

    uvicorn.run(
        "agent_guard.server:app",
        host=guard_config.host,
        port=guard_config.port,
        reload=True,
    )


if __name__ == "__main__":
    main()
