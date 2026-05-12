# Agent Permission Normalizer

Rust normalizer for dynamic runtime permission grants in AI-agent systems.

The normalizer is the lightweight first stage of a three-stage guardrail pipeline:

1. **Normalizer** converts heterogeneous browser actions and tool calls into a stable permission request.
2. **Policy/threshold engine** can make fast allow/review/deny decisions from normalized fields.
3. **Executor/auditor** enforces the granted scope and records provenance.

The crate intentionally has no third-party dependencies. That keeps the stage small, auditable, and easy to embed in high-frequency agent runtime paths.

## Input

The CLI reads one JSON object from stdin or `--input <FILE>`. It accepts UIA-style browser actions and generic tool calls.

```json
{
  "request_id": "req-001",
  "agent_id": "agent-a",
  "source": "uia-runner",
  "task": "open settings",
  "observation": { "url": "https://app.example/settings" },
  "action": {
    "op": "CLICK",
    "target": { "css_selector": "#save", "text": "Save" }
  }
}
```

Tool-call input is also supported:

```json
{
  "tool": {
    "name": "shell.exec",
    "args": { "cmd": "rm -rf /tmp/demo" }
  }
}
```

## Output

The output is a canonical permission request with:

- `canonical_action`: normalized action class such as `navigate`, `ui_click`, `write`, or `execute`.
- `capability`: compact permission string suitable for a policy table.
- `resource`: normalized URL, domain, path, selector, or tool target.
- `sensitivity`: `public`, `internal`, `sensitive`, or `secret`.
- `risk_score` / `risk_level`: deterministic score and threshold bucket.
- `decision_hint`: `allow`, `review`, or `deny`.
- `redactions`: fields that should not be logged verbatim.
- `provenance`: raw source/op/tool metadata for audit logs.

## Risk thresholds

| Score | Level | Decision hint |
| --- | --- | --- |
| 0-24 | low | allow |
| 25-49 | medium | review |
| 50-79 | high | review |
| 80-100 | critical | deny |

The score is intentionally explicit so benchmark suites can compare policies against a measurable threshold.

## Usage

```bash
cargo run --manifest-path normalizer/Cargo.toml -- --input request.json
```

or:

```bash
cat request.json | cargo run --manifest-path normalizer/Cargo.toml -- --compact
```

## Development

```bash
cargo test --manifest-path normalizer/Cargo.toml
```
