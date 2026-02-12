"""Unit tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guard.config import load_guard_config, load_policy_config
from agent_guard.models import Action, GuardMode

# -- load_guard_config --------------------------------------------------------


class TestLoadGuardConfig:
    def test_defaults(self, monkeypatch):
        """All env vars unset → defaults apply."""
        monkeypatch.delenv("AGENT_GUARD_MODE", raising=False)
        monkeypatch.delenv("AGENT_GUARD_PORT", raising=False)
        monkeypatch.delenv("AGENT_GUARD_HOST", raising=False)
        monkeypatch.delenv("AGENT_GUARD_POLICY_PATH", raising=False)
        monkeypatch.delenv("AGENT_GUARD_LOG_LEVEL", raising=False)

        cfg = load_guard_config()
        assert cfg.mode == GuardMode.DRY_RUN
        assert cfg.port == 8443
        assert cfg.host == "0.0.0.0"
        assert cfg.policy_path == "policies/default.yaml"
        assert cfg.log_level == "info"

    def test_env_override(self, monkeypatch):
        """Environment variables override defaults."""
        monkeypatch.setenv("AGENT_GUARD_MODE", "enforce")
        monkeypatch.setenv("AGENT_GUARD_PORT", "9000")
        monkeypatch.setenv("AGENT_GUARD_HOST", "127.0.0.1")
        monkeypatch.setenv("AGENT_GUARD_POLICY_PATH", "/tmp/policy.yaml")
        monkeypatch.setenv("AGENT_GUARD_LOG_LEVEL", "debug")

        cfg = load_guard_config()
        assert cfg.mode == GuardMode.ENFORCE
        assert cfg.port == 9000
        assert cfg.host == "127.0.0.1"
        assert cfg.policy_path == "/tmp/policy.yaml"
        assert cfg.log_level == "debug"


# -- load_policy_config -------------------------------------------------------


class TestLoadPolicyConfig:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            load_policy_config("/nonexistent/path.yaml")

    def test_empty_yaml(self, tmp_path: Path):
        """Empty YAML file → default PolicyConfig."""
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("")

        policy = load_policy_config(policy_file)
        assert policy.version == "1.0"
        assert policy.default_action == Action.ALLOW
        assert policy.rules == []

    def test_valid_yaml(self, tmp_path: Path):
        """Valid YAML with rules → parsed correctly."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            """\
            version: "2.0"
            default_action: block
            rules:
              - id: block-rm
                when:
                  tool: bash
                  args_regex: "rm -rf"
                action: block
                reason: "Dangerous command"
              - id: allow-ls
                when:
                  tool: bash
                  args_regex: "^ls"
                action: allow
                reason: "Safe command"
            """
        )

        policy = load_policy_config(policy_file)
        assert policy.version == "2.0"
        assert policy.default_action == Action.BLOCK
        assert len(policy.rules) == 2
        assert policy.rules[0].id == "block-rm"
        assert policy.rules[0].when.tool == "bash"
        assert policy.rules[1].id == "allow-ls"

    def test_invalid_yaml_not_mapping(self, tmp_path: Path):
        """YAML that is a list instead of a mapping → ValueError."""
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("- item1\n- item2\n")

        with pytest.raises(ValueError, match="YAML mapping"):
            load_policy_config(policy_file)

    def test_yaml_with_all_condition_fields(self, tmp_path: Path):
        """All RuleCondition fields are parsed."""
        policy_file = tmp_path / "full.yaml"
        policy_file.write_text(
            """\
            rules:
              - id: full-rule
                when:
                  tool: sessions_send
                  args_regex: "main"
                  message_regex: "ignore.*instructions"
                  source_tier:
                    - group
                    - dm
                  target_contains: "main"
                  direction: output
                  contains_secret: true
                action: block
                reason: "Full condition test"
            """
        )

        policy = load_policy_config(policy_file)
        rule = policy.rules[0]
        assert rule.when.tool == "sessions_send"
        assert rule.when.args_regex == "main"
        assert rule.when.message_regex == "ignore.*instructions"
        assert rule.when.source_tier is not None
        assert len(rule.when.source_tier) == 2
        assert rule.when.target_contains == "main"
        assert rule.when.direction == "output"
        assert rule.when.contains_secret is True

    def test_disabled_rule(self, tmp_path: Path):
        """Rule with enabled=false is parsed correctly."""
        policy_file = tmp_path / "disabled.yaml"
        policy_file.write_text(
            """\
            rules:
              - id: disabled
                when:
                  tool: bash
                action: block
                reason: "test"
                enabled: false
            """
        )

        policy = load_policy_config(policy_file)
        assert policy.rules[0].enabled is False
