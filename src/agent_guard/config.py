"""Configuration loading from environment variables and YAML files."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from agent_guard.models import GuardConfig, GuardMode, PolicyConfig


def load_guard_config() -> GuardConfig:
    """Load the global guard configuration from environment variables.

    Environment variables (all optional, defaults apply):
        AGENT_GUARD_MODE        — "dry-run" or "enforce"
        AGENT_GUARD_PORT        — port number (default 8443)
        AGENT_GUARD_HOST        — bind host (default 0.0.0.0)
        AGENT_GUARD_POLICY_PATH — path to policy YAML
        AGENT_GUARD_LOG_LEVEL   — logging level
    """
    return GuardConfig(
        mode=GuardMode(os.getenv("AGENT_GUARD_MODE", GuardMode.DRY_RUN)),
        port=int(os.getenv("AGENT_GUARD_PORT", "8443")),
        host=os.getenv("AGENT_GUARD_HOST", "0.0.0.0"),
        policy_path=os.getenv("AGENT_GUARD_POLICY_PATH", "policies/default.yaml"),
        log_level=os.getenv("AGENT_GUARD_LOG_LEVEL", "info"),
    )


def load_policy_config(policy_path: str | Path) -> PolicyConfig:
    """Load and validate a policy configuration from a YAML file.

    Args:
        policy_path: Path to the YAML policy file.

    Returns:
        A validated PolicyConfig instance.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If the YAML content is invalid.
    """
    path = Path(policy_path)

    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)

    if data is None:
        return PolicyConfig()

    if not isinstance(data, dict):
        msg = f"Policy file must contain a YAML mapping, got {type(data).__name__}"
        raise ValueError(msg)

    return PolicyConfig.model_validate(data)
