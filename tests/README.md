# tests

Offline, hermetic tests for `sentinel-harness`. **They make ZERO AWS calls** and
need no credentials, no network, and no live account. They validate the *shape* of
what the `sentinel_harness.core` builder functions emit — the same invariants the
Amazon Bedrock AgentCore control plane enforces server-side, checked locally so a
bad harness config fails in CI instead of silently at deploy time.

## What is covered

`test_config_validation.py`:

| Invariant | Why it matters |
|---|---|
| Harness name matches `[a-zA-Z][a-zA-Z0-9_]{0,39}` | The control plane rejects hyphens, leading digits/underscores, non-ASCII, and names over 40 chars. All shipped scenario names are checked against the rule. |
| `systemPrompt` normalized to the GA list shape `[{"text": ...}]` | `create_harness` accepts a plain string and must wrap it; the wrong shape is a silent server-side rejection. |
| `runtimeSessionId` >= 33 chars (`new_session`) | The data plane requires session ids of at least 33 characters; a hyphenated UUID (36) is safe. Uniqueness is also checked. |
| Tool config shapes (`code_interpreter` / `remote_mcp` / `gateway` / `inline`) | Each tool builder must emit the exact `type` / `name` / `config` envelope the harness expects. |
| Model + memory builder shapes (`bedrock_model`, `managed_memory`, `byo_memory`) | `bedrockModelConfig` / `managedMemoryConfiguration` / `agentCoreMemoryConfiguration` envelopes and optional-field handling. |
| `create_harness` field forwarding | Optional args are forwarded when set, omitted when `None`, and `0` values (e.g. `max_iterations=0`) are preserved (guarded with `is not None`). Missing execution role raises loudly. |

## How the tests stay offline

`sentinel_harness.core` constructs boto3 clients at import time, but client
construction is offline (no network, no credential lookup). Two things keep the
suite hermetic:

1. **Dummy env before import** — `SENTINEL_REGION`, `AWS_DEFAULT_REGION`,
   `SENTINEL_EXECUTION_ROLE_ARN`, and dummy AWS keys are set so nothing tries to
   resolve a real region/profile/credentials.
2. **Monkeypatched control-plane client** — the `capture_create` fixture replaces
   `core._control` with a fake that records the request kwargs `create_harness`
   *would* have sent, so the call never leaves the process. Tests assert on those
   captured kwargs.

## Running

```bash
# with plain pip + pytest
pip install -r requirements.txt pytest
pytest -q tests

# or with uv (no project build needed)
uv run --no-project --with pytest --with boto3 python -m pytest -q tests
```

Lint (optional, matches CI):

```bash
ruff check .
```

## CI

`.github/workflows/ci.yml` runs this suite on Python 3.10 / 3.11 / 3.12, runs
`ruff` if available, and runs a **secret-and-name scan** that fails the build if it
finds a customer/company name, a hardcoded 12-digit AWS account ID (the all-zeros
`000000000000` placeholder is allowed), or an AWS access key ID (`AKIA`/`ASIA`).
This repo is public open source, so that scan is a hard gate.
