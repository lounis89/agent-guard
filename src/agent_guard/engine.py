"""Policy engine — evaluate requests against loaded rules."""

from __future__ import annotations

import re

from agent_guard.models import (
    Action,
    Decision,
    Direction,
    PolicyConfig,
    RequestContext,
    Rule,
)

# Well-known secret patterns used for the `contains_secret` condition.
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[0-9]+-[a-zA-Z0-9]+"),
]


def _text_contains_secret(text: str) -> bool:
    """Return True if *text* contains a recognisable secret token."""
    return any(p.search(text) for p in SECRET_PATTERNS)


def matches_condition(rule: Rule, ctx: RequestContext) -> bool:
    """Check whether a rule's conditions match the given request context.

    Every non-None condition must match for the rule to trigger (AND logic).
    """
    cond = rule.when

    # ── Direction gate ──────────────────────────────────────────────────
    if cond.direction == Direction.INPUT:
        # INPUT rules only fire when there is message content, not tool calls
        if ctx.tool_name is not None and ctx.message_content is None:
            return False
    if cond.direction == Direction.OUTPUT:
        # OUTPUT rules only fire for tool calls
        if ctx.message_content is not None and ctx.tool_name is None:
            return False

    # ── Tool name ───────────────────────────────────────────────────────
    if cond.tool is not None:
        if ctx.tool_name is None or ctx.tool_name != cond.tool:
            return False

    # ── Args regex ──────────────────────────────────────────────────────
    if cond.args_regex is not None:
        if ctx.tool_args is None:
            return False
        if not re.search(cond.args_regex, ctx.tool_args):
            return False

    # ── Message regex ───────────────────────────────────────────────────
    if cond.message_regex is not None:
        if ctx.message_content is None:
            return False
        if not re.search(cond.message_regex, ctx.message_content, re.DOTALL):
            return False

    # ── Source tier ─────────────────────────────────────────────────────
    if cond.source_tier is not None:
        if ctx.session_tier not in cond.source_tier:
            return False

    # ── Target contains ─────────────────────────────────────────────────
    if cond.target_contains is not None:
        if ctx.tool_args is None:
            return False
        if cond.target_contains not in ctx.tool_args:
            return False

    # ── Secret detection ────────────────────────────────────────────────
    if cond.contains_secret is True:
        text = ctx.message_content or ctx.tool_args or ""
        if not _text_contains_secret(text):
            return False

    return True


def evaluate(policy: PolicyConfig, ctx: RequestContext) -> Decision:
    """Evaluate a request context against a policy.

    Returns the *first* matching decision.  If no rule matches, the
    policy's ``default_action`` is returned (defaults to ALLOW).
    """
    for rule in policy.rules:
        if not rule.enabled:
            continue
        if matches_condition(rule, ctx):
            if rule.action == Action.BLOCK:
                return Decision.block(rule_id=rule.id, reason=rule.reason)
            if rule.action == Action.REDACT:
                return Decision.redact(rule_id=rule.id, reason=rule.reason)
            # ALLOW rule → stop evaluating, return allow
            return Decision.allow()

    # No rule matched — fall through to default
    if policy.default_action == Action.BLOCK:
        return Decision.block(rule_id="__default__", reason="Default policy action")
    return Decision.allow()


def redact_secrets(text: str, replacement: str = "[REDACTED]") -> str:
    """Replace all recognised secret tokens in *text* with *replacement*."""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
