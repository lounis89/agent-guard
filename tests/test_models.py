"""Unit tests for Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_guard.models import (
    Action,
    Decision,
    Direction,
    GuardConfig,
    GuardMode,
    PolicyConfig,
    RequestContext,
    Rule,
    RuleCondition,
    SessionTier,
)

# -- Enums --------------------------------------------------------------------


class TestAction:
    def test_values(self):
        assert Action.ALLOW == "allow"
        assert Action.BLOCK == "block"
        assert Action.REDACT == "redact"

    def test_from_string(self):
        assert Action("allow") is Action.ALLOW
        assert Action("block") is Action.BLOCK


class TestGuardMode:
    def test_values(self):
        assert GuardMode.DRY_RUN == "dry-run"
        assert GuardMode.ENFORCE == "enforce"


class TestSessionTier:
    def test_all_tiers_exist(self):
        assert SessionTier.MAIN == "main"
        assert SessionTier.DM_APPROVED == "dm"
        assert SessionTier.GROUP == "group"
        assert SessionTier.UNKNOWN == "unknown"


class TestDirection:
    def test_all_directions_exist(self):
        assert Direction.INPUT == "input"
        assert Direction.OUTPUT == "output"
        assert Direction.BOTH == "both"


# -- Decision -----------------------------------------------------------------


class TestDecision:
    def test_allow_factory(self):
        d = Decision.allow()
        assert d.action == Action.ALLOW
        assert d.rule_id is None
        assert d.reason is None

    def test_block_factory(self):
        d = Decision.block(rule_id="rule-1", reason="dangerous")
        assert d.action == Action.BLOCK
        assert d.rule_id == "rule-1"
        assert d.reason == "dangerous"

    def test_redact_factory(self):
        d = Decision.redact(rule_id="rule-2", reason="secret detected")
        assert d.action == Action.REDACT
        assert d.rule_id == "rule-2"
        assert d.reason == "secret detected"

    def test_default_is_allow(self):
        d = Decision()
        assert d.action == Action.ALLOW

    def test_block_requires_keyword_args(self):
        with pytest.raises(TypeError):
            Decision.block("rule-1", "reason")  # type: ignore[misc]


# -- RuleCondition ------------------------------------------------------------


class TestRuleCondition:
    def test_defaults(self):
        cond = RuleCondition()
        assert cond.tool is None
        assert cond.args_regex is None
        assert cond.message_regex is None
        assert cond.source_tier is None
        assert cond.target_contains is None
        assert cond.direction == Direction.BOTH
        assert cond.contains_secret is None

    def test_with_tool_and_regex(self):
        cond = RuleCondition(tool="bash", args_regex=r"rm\s+-rf")
        assert cond.tool == "bash"
        assert cond.args_regex == r"rm\s+-rf"

    def test_with_source_tier(self):
        cond = RuleCondition(source_tier=[SessionTier.GROUP, SessionTier.DM_APPROVED])
        assert len(cond.source_tier) == 2
        assert SessionTier.GROUP in cond.source_tier


# -- Rule ---------------------------------------------------------------------


class TestRule:
    def test_valid_rule(self):
        rule = Rule(
            id="block-rm",
            when=RuleCondition(tool="bash", args_regex=r"rm\s+-rf"),
            action=Action.BLOCK,
            reason="Dangerous shell command",
        )
        assert rule.id == "block-rm"
        assert rule.enabled is True

    def test_disabled_rule(self):
        rule = Rule(
            id="disabled-rule",
            when=RuleCondition(),
            action=Action.BLOCK,
            reason="test",
            enabled=False,
        )
        assert rule.enabled is False

    def test_empty_id_rejected(self):
        with pytest.raises(ValidationError):
            Rule(
                id="",
                when=RuleCondition(),
                action=Action.BLOCK,
                reason="test",
            )


# -- PolicyConfig -------------------------------------------------------------


class TestPolicyConfig:
    def test_defaults(self):
        policy = PolicyConfig()
        assert policy.version == "1.0"
        assert policy.default_action == Action.ALLOW
        assert policy.rules == []

    def test_with_rules(self):
        policy = PolicyConfig(
            rules=[
                Rule(
                    id="r1",
                    when=RuleCondition(tool="bash"),
                    action=Action.BLOCK,
                    reason="test",
                ),
            ]
        )
        assert len(policy.rules) == 1
        assert policy.rules[0].id == "r1"

    def test_from_dict(self):
        data = {
            "version": "2.0",
            "default_action": "block",
            "rules": [
                {
                    "id": "r1",
                    "when": {"tool": "bash"},
                    "action": "block",
                    "reason": "test",
                }
            ],
        }
        policy = PolicyConfig.model_validate(data)
        assert policy.version == "2.0"
        assert policy.default_action == Action.BLOCK
        assert len(policy.rules) == 1


# -- GuardConfig --------------------------------------------------------------


class TestGuardConfig:
    def test_defaults(self):
        cfg = GuardConfig()
        assert cfg.mode == GuardMode.DRY_RUN
        assert cfg.port == 8443
        assert cfg.host == "0.0.0.0"
        assert cfg.policy_path == "policies/default.yaml"
        assert cfg.log_level == "info"

    def test_custom_values(self):
        cfg = GuardConfig(mode=GuardMode.ENFORCE, port=9999, host="127.0.0.1")
        assert cfg.mode == GuardMode.ENFORCE
        assert cfg.port == 9999

    def test_invalid_port_rejected(self):
        with pytest.raises(ValidationError):
            GuardConfig(port=0)

        with pytest.raises(ValidationError):
            GuardConfig(port=99999)


# -- RequestContext -----------------------------------------------------------


class TestRequestContext:
    def test_minimal(self):
        ctx = RequestContext(provider="anthropic")
        assert ctx.provider == "anthropic"
        assert ctx.session_tier == SessionTier.UNKNOWN
        assert ctx.channel is None
        assert ctx.tool_name is None

    def test_full(self):
        ctx = RequestContext(
            provider="openai",
            session_tier=SessionTier.GROUP,
            channel="discord",
            tool_name="bash",
            tool_args='{"command": "ls"}',
            message_content="hello",
        )
        assert ctx.session_tier == SessionTier.GROUP
        assert ctx.channel == "discord"
        assert ctx.tool_name == "bash"
