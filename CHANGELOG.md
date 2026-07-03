# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **HITL loop closed** — `core.invoke_with_tool_result()` resumes a paused session via
  the two-message `toolUse`→`toolResult` contract; `core.invoke` reconstructs the paused
  call (`toolUseId` + accumulated input) as `result["tool_use"]`. Live pause→approve→resume
  trace in `scenarios/scenario_hitl_resume.py` (`evidence/hitl_resume_result.json`).
- **YAML→harness loader** (`sentinel_harness/loader.py`) + `sentinel create <harness.yaml>`
  — `${ENV_VAR}` expansion, `system_prompt.md` resolution, inline-HITL-gate injection, and
  `model`/`tools`/`memory`/`allowedTools` passthrough, so `harnesses/*.yaml` are live, not illustrative.
- **Layer 2 — Play Mode** (`sentinel_harness/simulation.py`, `scenarios/scenario_play_mode.py`):
  adversary emulation where every offensive step is human-gated, with checkpoint/resume;
  live-validated (`every_step_gated`, `reject_halts_plan`, `checkpoint_roundtrip`).
- **Layer 3 — governance** (`sentinel_harness/registry.py`, `sentinel_harness/sandbox_hooks.py`):
  a dual-gate tool/skill registry (live only if registered *and* code-mapped) and a
  PreToolUse sandbox hook (command allowlist + path containment).
- **Unit coverage for previously untested code**: the functional `sigma_yara_lint` linter,
  the four reference tool handlers, and the `sentinel` CLI.

### Fixed
- CLI BYO-memory config silently dropped its retrieval tuning: `_build_memory` read the
  removed `messages_count` key and passed it to `core.byo_memory`, whose second parameter
  is now `retrieval_config` (`retrievalConfig`). Now reads the correct key (regression-tested).
- Corrected two stale "roadmap item" comments (`core.tool_inline`, `loader.py` header) that
  described already-shipped, live-validated features.

### Changed
- Detection-gen scenario defines success on **substance** (an independent verdict was
  reached + the flawed rule was withheld from publish + no stray shell) with a robust prose
  parser as fallback, rather than on whether the model emitted a structured tool call — a
  known model-behavior quirk that `allowedTools` narrows but cannot force. Documented honestly.

### Tests
- Offline suite grown **42 → 213** (still zero AWS calls): `test_sigma_yara_lint.py` (24),
  `test_tool_handlers.py` (29), `test_cli.py` (23), `test_sandbox_hooks.py` (33),
  `test_registry.py` (20), `test_loader.py` (10), `test_simulation.py` (11), and
  `test_detection_gen_scenario.py` (21) alongside the original config-validation set.

### Planned
- Wire the reference `tools/` handlers to a live AgentCore Gateway; add an end-to-end
  named-supervisor scenario that creates from `harnesses/*.yaml`.
- Layer 3 remainder: Agent Factory provisioning, LiteLLM specialists, a Gateway CDK stack.
- BAS / attack-path on a genuinely long-running Runtime (beyond the Play Mode driver).

## [0.1.0] — 2026-07-03

First public release. A Layer-1 reference implementation of SecOps agents as
configuration on Amazon Bedrock AgentCore Harness.

### Added
- **Core library** (`sentinel_harness/core.py`): `create_harness` / `wait_ready` /
  `invoke` (streaming) / `delete_harness` / `cleanup`, plus builders for
  code-interpreter, remote-MCP, gateway, inline-function tools and managed/BYO memory.
  12-factor (env-parameterized: `SENTINEL_EXECUTION_ROLE_ARN` / `SENTINEL_REGION`).
- **CLI** (`sentinel`): `create` / `invoke` / `list` / `delete` / `cleanup` / `run-scenario`.
- **Three live-validated Layer-1 scenarios**: CVE triage (deterministic compute + HITL
  pause + managed memory), multi-harness parallel + supervisor (≈2.6× measured speedup),
  and detection-generation with an independent adversarial-reviewer harness + publish gate.
- **Reference tool templates** (`tools/`): a real deterministic `sigma_yara_lint`, plus
  offline-safe `nvd_lookup` / `epss_kev` / `attack_lookup` / `web_search` stubs.
- **Agent Skills** (`skills/`): `cve-triage-rubric`, `detection-writing-sop`,
  `ioc-vetting`, `attack-path-reasoning` (AgentSkills.io format).
- **Illustrative harness configs** (`harnesses/`) for the three Layer-1 supervisors.
- **Docs**: `README`, `ARCHITECTURE`, `BLUEPRINT`, `SETUP`, `HARNESSES`, and a
  self-audit `FIDELITY-REPORT`; SVG logo + architecture diagram under `assets/`.
- **CI** with an offline test matrix (Python 3.10–3.12) and a customer-name / secret scan gate.
- **42 offline config-validation tests** (no AWS calls).

### Security
- Execution-role sample policy deliberately **omits** `bedrock-agentcore:InvokeAgentRuntimeCommand`
  (it bypasses the LLM and `allowedTools`); documented as an explicit least-privilege decision.
- Egress control: no raw-download tool; `web_search` returns text only.
- Fully anonymized — no organization-specific data, hardcoded account IDs, or secrets.

### Known limitations
- Layers 2–3 are design specs with reference stubs, not runnable end-to-end (see the
  status matrix in the README).
- The human-in-the-loop scenarios demonstrate the *pause* half; the two-message resume
  is a roadmap item.
- Long-term (semantic) memory extraction is asynchronous (minutes-scale) — expected
  AgentCore behavior, documented in `SETUP.md` / `evidence/README.md`.

[Unreleased]: https://github.com/neosun100/sentinel-harness/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/neosun100/sentinel-harness/releases/tag/v0.1.0
