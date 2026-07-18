# sentinel-harness v0.4.0 — the detection-engineering suite, and 100 defects hardened away

`sentinel-harness` is a reference implementation of production security-operations
agents built as **configuration** — model, prompt, tools, skills, memory, limits —
on [Amazon Bedrock AgentCore Harness](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html);
you declare the agent and AWS runs the loop. Where v0.3.0 delivered the world-class
depth of milestone **M13** (benchmark model, all-domain eval, autonomy controller,
tracing, SIEM/ticketing connectors), **v0.4.0** is about **making it bulletproof and
turning detection engineering into a first-class, CI-gateable capability** (M14).

Two themes:

1. **A complete, deterministic, LLM-free detection-engineering suite** — seven
   composable tools from authoring to a one-command CI gate.
2. **Relentless adversarial hardening** — eight hostile-finder/skeptic-verifier
   audit rounds plus a service-model drift scan cleared **100 confirmed defects**,
   each with a regression test.

The whole thing is anchored by **2352 offline tests** (+6 skipped when optional deps
are absent) across 119 test files — deterministic, hermetic, zero AWS by default —
at 90% coverage.

## Highlights

- **Detection-engineering suite (7 tools, all deterministic / LLM-free / offline,
  conservative with an explicit "cannot analyze" ledger):**
  `sigma_yara_lint` (validate) → `detection_translate` (port one Sigma rule to
  **YARA · Suricata · Splunk SPL · Elastic EQL**) → `detection_dedup` (provable
  duplicate/subsumption/overlap) → `detection_coverage` (which ATT&CK techniques are
  **uncovered** blind spots) → `detection_audit` (one 0–100 health score) →
  `detection_navigator` (ATT&CK Navigator layer JSON) → `detection_baseline`
  (regression gate: set-diff catches churn a flat score hides). Every tool refuses
  to over-claim — a sub-technique tag covers its parent but never the reverse; a
  lossy translation lands in `untranslatable`, never silently dropped.
- **The suite is a CLI, and a one-command CI gate.**
  `sentinel detection audit <dir>` (health report + `--navigator` export +
  `--min-score` gate), `sentinel detection baseline <dir>` (snapshot / compare),
  and `sentinel detection ci <dir>` — audit + baseline-regression + Navigator export
  with a **single combined exit code**, so a pipeline runs one step.
- **100 confirmed defects fixed across eight adversarial-audit rounds + a
  service-model drift scan.** A hostile-finder → independent skeptic-verifier
  pipeline (default-REFUTE, CONFIRMED-only) swept every surface: the detection
  tools, the core M8–M13 modules, loader/factory/cli/mockdata, gateway/exporter/
  observability, specialist agents, and the CDK/deploy/CI supply chain. Refute rates
  of 40–68% throughout are the health signal that the verifier is not rubber-stamping.
- **A new audit lens: service-model drift.** Validating every AWS-payload-building
  module against the REAL botocore service model (offline) found **5 "offline-green /
  live-red"** shape defects — payloads that pass every mocked test but
  `ValidationException` against the live service (botocore checks types at call time,
  but not string patterns, min/max length, or Create-vs-Update shape asymmetry).
  Fixes: `UpdateHarness.memory` `optionalValue` wrapper, `clientToken` pattern+length
  sanitize, factory tag-read via `ListTagsForResource`, tag-value string validation.
- **A live proof of a drift fix.** On a non-production account, a model-legal
  underscore-named Registry (`alert_triage`) was created live — which the pre-fix
  code could not do (its derived `clientToken` was pattern-illegal, so the service
  returned `ValidationException`, invisible to every offline test) — then torn down
  (zero residue). Evidence: `evidence/drift_fix_registry_clienttoken_live.json`.

## By the numbers

| Metric | Count |
|---|--:|
| Offline tests passing (+6 skipped w/o optional deps) | 2352 |
| Test coverage | 90% |
| Test files | 119 |
| Confirmed defects fixed (8 audit rounds + drift scan), each regression-tested | 100 |
| MCP tool templates (incl. the 7-tool detection suite) | 20 |
| Runnable scenarios | 21 |
| Committed evidence JSON artifacts | 36 |
| Agent Skills (`SKILL.md`) | 9 |
| Declarative harnesses | 8 |
| CDK stacks (`iac-cdk/lib/*-stack.ts`) | 9 |

## Detection suite at a glance

```bash
# health-check a Sigma rule directory (lint + dedup + ATT&CK coverage)
sentinel detection audit rules/ --techniques T1059,T1190

# port one Sigma rule to four engines (opt-in targets; default is yara+suricata)
#   detection_translate: YARA · Suricata · Splunk SPL · Elastic EQL

# capture a regression baseline, then gate CI on it
sentinel detection baseline rules/ --snapshot baseline.json
sentinel detection ci rules/ --min-score 90 --against baseline.json \
                             --navigator-out layer.json   # ONE combined exit code
```

All of the above run with **zero AWS / zero network** and are byte-for-byte
deterministic.

## Live-validated on AWS (non-production)

All on a **non-production** dev/test account; account IDs are scrubbed to
`000000000000` in every committed artifact. The full `[EXTERNAL]` proof set from
v0.2.0–v0.3.0 (Gateway lifecycle, Guardrail masking, Cognito CUSTOM_JWT, private-VPC
egress, Registry governance, Runtime A2A, managed + online Evaluate, cross-session
Memory recall, the end-to-end closed loop) remains validated. New in v0.4.0:

- A drift fix proven live: an underscore-named Registry created (pre-fix: server
  `ValidationException`) and torn down — `evidence/drift_fix_registry_clienttoken_live.json`.

## Upgrade notes

- **Backward-compatible.** `detection_translate`'s default targets stay
  `yara`+`suricata`; SPL/EQL are opt-in via an explicit `targets` list. No public API
  removed. `update_harness(memory=...)` now wraps memory in the `optionalValue`
  envelope the live `UpdateHarness` API requires (previously it emitted the
  `CreateHarness` shape and failed live) — transparent to callers.
- **New CLI surface:** `sentinel detection audit | baseline | ci`.

## Known limitations / not yet

- `detection_translate`'s SPL/EQL output is a **human-review skeleton** — it flattens
  the boolean condition (OR-of-selections) and surfaces non-trivial structure
  (negation, aggregates) in `untranslatable`; a human reconstructs the exact logic.
- The remaining `[EXTERNAL]` items that need `InvokeHarness`/`CreateAgentRuntime`
  quota beyond the dev account are unchanged from v0.3.0.
