@@ -8,25 +8,30 @@
## Trace format
Trace event schema (`TraceEvent`) includes `Observation`, `Action`, and free-form `meta`.
Assets are stored under `traces/<run_id>/{screenshots,dom,interactables}`.

## Validators
Validators are state-based postconditions, not action echoes. Supported types:
- `url_contains`, `url_matches`
- `dom_contains_text`
- `element_exists`
- `element_attribute_equals`
- `download_started` (stub)
- `comments_present_or_disabled` (Policy B): passes when comments container exists **or** deterministic disabled marker/text exists.

## Recovery
Implemented as a 2-stage idea:
1. shortlist/rank candidates (heuristic ranker now; remote pluggable API in `model_server/`)
2. execute best candidate + re-validate

Default `HeuristicRecoveryRanker` scores text similarity, role/tag match, and bbox proximity.

## Safety policies
- Typed sensitive values are redacted during recording.
- New domains blocked by default unless explicitly allowed.
- Dangerous click intents (delete/pay/subscribe/etc.) require explicit confirmation flag.
- For sensitive TYPE actions, params should be user-supplied rather than replayed secrets.

## Dynamic permission normalizer
The Rust normalizer in `normalizer/` is designed as a lightweight pre-policy stage for runtime permission grants. It accepts UIA-style browser actions or generic tool calls and emits a stable permission request containing a canonical action, capability string, resource scope, sensitivity class, deterministic risk score, decision hint, redaction list, and provenance metadata.

This keeps expensive LLM-layer review out of the hot path for low-risk actions while still escalating medium/high/critical operations such as destructive clicks, credential entry, write tools, network calls, and shell execution. The default thresholds are low `0-24`, medium `25-49`, high `50-79`, and critical `80-100`.