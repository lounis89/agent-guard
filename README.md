# Agent Guard

LLM Security Proxy — inspect and control LLM API calls in real-time.

## Quickstart

```bash
curl -fsSL https://pixi.sh/install.sh | sh
pixi install
pixi run start
```

## Integration

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8443"
export OPENAI_BASE_URL="http://127.0.0.1:8443"
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_GUARD_MODE` | `dry-run` | `dry-run` (log only) or `enforce` (block/redact) |
| `AGENT_GUARD_PORT` | `8443` | Proxy port |
| `AGENT_GUARD_POLICY_PATH` | `policies/default.yaml` | Path to YAML policy |

## Policy

Rules are defined in YAML. Each has conditions (`when`) and an action (`allow` / `block` / `redact`):

```yaml
rules:
  - id: block-prompt-injection
    when:
      message_regex: "(?i)ignore.*previous.*instructions"
      direction: input
    action: block
    reason: "Prompt injection detected"
```

Two policies are bundled: `policies/default.yaml` (allow-all) and `policies/openclaw-hardened.yaml` (12 rules against real CVEs).

## OpenClaw Integration

Point your OpenClaw agent's LLM traffic through Agent Guard, then enable the hardened policy:

```bash
# 1. Start Agent Guard with the OpenClaw-hardened policy
AGENT_GUARD_MODE=enforce \
AGENT_GUARD_POLICY_PATH=policies/openclaw-hardened.yaml \
pixi run start

# 2. Configure OpenClaw to route through the proxy
export ANTHROPIC_BASE_URL="http://127.0.0.1:8443"
export OPENAI_BASE_URL="http://127.0.0.1:8443"

# 3. Launch your OpenClaw agent as usual
openclaw run
```

The bundled `openclaw-hardened.yaml` policy covers CVE-2026-25253 (WebSocket hijack), CVE-2026-25157 (OS command injection), CVE-2026-24763 (Docker PATH injection), credential exfiltration, prompt injection, and 0-click RCE via Gmail hooks.

## Benchmark

```bash
pixi run bench       # verbose
pixi run bench-ci    # CI mode (fails under 100%)
```

34 scenarios, 100% detection, 0% false positives, ~30 microseconds/eval.

## Endpoints

| Path | Description |
|---|---|
| `GET /health` | Health check |
| `GET /metrics` | Prometheus metrics |
| `POST /v1/messages` | Anthropic proxy |
| `POST /v1/chat/completions` | OpenAI proxy |

## License

MIT
