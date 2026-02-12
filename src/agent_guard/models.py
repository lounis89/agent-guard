"""Pydantic models for decisions, rules, and configuration."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field

# -- Enums --------------------------------------------------------------------


class Action(StrEnum):
    """Possible actions the proxy can take on a request or tool call."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


class GuardMode(StrEnum):
    """Operating mode of the proxy."""

    DRY_RUN = "dry-run"  # Log decisions but never block
    ENFORCE = "enforce"  # Actually block/redact when rules match


class Direction(StrEnum):
    """Which side of the LLM exchange a rule applies to."""

    INPUT = "input"  # Prompt sent to the LLM
    OUTPUT = "output"  # Response (including tool calls) from the LLM
    BOTH = "both"


class SessionTier(StrEnum):
    """Trust tiers for sessions (maps to OpenClaw session types)."""

    MAIN = "main"  # Operator — full trust
    DM_APPROVED = "dm"  # Approved direct message — medium trust
    GROUP = "group"  # Group chat — low trust
    UNKNOWN = "unknown"  # Unclassified


# -- Decision -----------------------------------------------------------------


class Decision(BaseModel):
    """Result of evaluating a request against the policy rules."""

    action: Action = Action.ALLOW
    rule_id: str | None = None
    reason: str | None = None

    @classmethod
    def allow(cls) -> Decision:
        return cls(action=Action.ALLOW)

    @classmethod
    def block(cls, *, rule_id: str, reason: str) -> Decision:
        return cls(action=Action.BLOCK, rule_id=rule_id, reason=reason)

    @classmethod
    def redact(cls, *, rule_id: str, reason: str) -> Decision:
        return cls(action=Action.REDACT, rule_id=rule_id, reason=reason)


# -- Rule ---------------------------------------------------------------------


class RuleCondition(BaseModel):
    """Conditions that must ALL match for a rule to trigger."""

    tool: str | None = None
    """Tool name to match (e.g. 'bash', 'sessions_send')."""

    args_regex: str | None = None
    """Regex pattern to match against tool call arguments."""

    message_regex: str | None = None
    """Regex pattern to match against message content."""

    source_tier: list[SessionTier] | None = None
    """Only match if the session tier is one of these."""

    target_contains: str | None = None
    """Only match if tool args contain this string (e.g. 'main')."""

    direction: Direction = Direction.BOTH
    """Which direction this condition applies to."""

    contains_secret: bool | None = None
    """If true, match when secrets are detected in the content."""


class Rule(BaseModel):
    """A single policy rule."""

    id: Annotated[str, Field(min_length=1)]
    """Unique identifier for this rule."""

    when: RuleCondition
    """Conditions that trigger this rule."""

    action: Action
    """Action to take when the rule matches."""

    reason: str
    """Human-readable explanation of why this rule exists."""

    enabled: bool = True
    """Whether this rule is active."""


# -- Policy config ------------------------------------------------------------


class PolicyConfig(BaseModel):
    """Top-level policy configuration loaded from YAML."""

    version: str = "1.0"
    default_action: Action = Action.ALLOW
    rules: list[Rule] = Field(default_factory=list)


# -- Guard config -------------------------------------------------------------


class GuardConfig(BaseModel):
    """Global configuration for the Agent Guard proxy."""

    mode: GuardMode = GuardMode.DRY_RUN
    """Operating mode: dry-run (log only) or enforce (actually block)."""

    port: int = Field(default=8443, ge=1, le=65535)
    """Port the proxy listens on."""

    host: str = "0.0.0.0"
    """Host the proxy binds to."""

    policy_path: str = "policies/default.yaml"
    """Path to the policy YAML file."""

    log_level: str = "info"
    """Logging level."""


# -- Request context ----------------------------------------------------------


class RequestContext(BaseModel):
    """Context assembled for each proxied request, used by the policy engine."""

    provider: str
    """LLM provider name (anthropic, openai)."""

    session_tier: SessionTier = SessionTier.UNKNOWN
    """Trust tier of the originating session."""

    channel: str | None = None
    """Originating channel (whatsapp, telegram, discord, etc.)."""

    tool_name: str | None = None
    """Name of the tool being called (for output inspection)."""

    tool_args: str | None = None
    """Raw arguments of the tool call (for output inspection)."""

    message_content: str | None = None
    """Content of the message being inspected (for input inspection)."""
