# sentinel-harness — Roadmap & Development Guide

> The authoritative, build-it-by-the-numbers plan for evolving `sentinel-harness`.
> Generic SecOps content only — **no organization-, customer-, or deployment-specific
> data.** Bring your own data planes, identities, and criteria behind the env vars and
> MCP bridges described here.

**North star (one line):** evolve `sentinel-harness` from *hand-authored, fixed SecOps
agents* into an **agent that builds agents** — a self-iterating security-operations
platform where natural language / alerts / framework errors flow in, and the platform
**auto-builds → tests → evaluates → iterates → promotes** agents, self-improving over
time, fully **controllable (HITL gates)** and **observable (OTEL / eval traces)**, all
on **Amazon Bedrock AgentCore Harness**.

**Two rules that must never be broken:**
1. **Do not rewrite what is already live-validated** (`core` / `loader` / `factory` /
   `registry` / the three shipped harnesses / nine scenarios / nine tools / the Gateway
   helper / `sandbox_hooks` / `simulation`). Layer on top of them.
2. **Every milestone ships live evidence** into `evidence/` (the existing "if it ran, it
   dropped a JSON + log" habit). Evidence precedes any "done" claim.

---

## 0. Current-state ground truth (read before building)

Legend: ✅ live-validated (has `evidence/`) · 🟩 built + tested (unit-tested, not yet
live) · 🟡 skeleton / partial · 🔴 gap.

### 0.1 Core library `sentinel_harness/` (~2,100 lines, library-grade — extend, don't rewrite)

| File | Lines | Responsibility | Status | Key real API |
|---|--:|---|:--:|---|
| `core.py` | 270 | Thin AgentCore Harness wrapper | ✅ | `create_harness(name, system_prompt, *, model, tools, skills, memory, allowed_tools, max_iterations, max_tokens, timeout_seconds)`; `wait_ready(id, timeout=360)`; `invoke(arn, session_id, text, *, actor_id, **overrides)→{text,events,stop_reason,tools_used,tool_use,metadata}`; `invoke_with_tool_result(...)` (the **two-message HITL resume contract**); tool/memory builders; `new_session(prefix)` (≥33 chars); `delete_harness/cleanup/list_harnesses`. Model env: `SENTINEL_MODEL_{OPUS,SONNET,HAIKU}` |
| `factory.py` | 259 | Agent Factory (fleet provisioning, idempotency, cross-env tag-guard) — **the base for self-iteration** | 🟩 | `provision_fleet(manifest, *, dry_run)` (`would_create/created/exists`, `sentinel:env` tag-guard refuses cross-env overwrite); `teardown_fleet(...)`; `FactoryError` |
| `loader.py` | 224 | `harness.yaml` → `create_harness` kwargs | 🟩 | `load_harness_config(path)` (offline; `${ENV_VAR}` expansion, keeps `${arn:...}`, reads `systemPrompt` file, **injects inline HITL gates**); `create_from_config(path)`. Built-in gates: `request_publish_approval` / `request_containment_approval` / `request_human_review` |
| `registry.py` | 264 | Tool/skill dual-gate governance | 🟩 | `ToolRegistry(factory_map)`; `.resolve(name)` (live only if registry-approved **and** code-mapped); `.governance_check()→GovernanceReport`; `load_registry()` |
| `gateway.py` | 240 | AgentCore Gateway helper (create→READY→delete live-validated) | 🟩 | create/wait/delete gateway + target builders. **OAuth/JWT + Guardrail interceptor not yet wired** |
| `simulation.py` | 392 | Play Mode (every offensive step HITL-gated) | ✅ | see `scenario_play_mode.py` |
| `sandbox_hooks.py` | 127 | PreToolUse sandbox (path confinement / command allowlist / read-only cloud) | 🟩 | `validate_command` / `validate_path` |
| `cli.py` | 303 | `sentinel create/...` CLI | 🟩 | `sentinel create <harness.yaml>` etc. |

### 0.2 Declarative assets

| Dir | Contents | Status | Gap |
|---|---|:--:|---|
| `harnesses/` | `alert-triage` / `detection-eng` / `research-supervisor` | ✅ loader-consumed | missing meta / ops / self-improving harnesses |
| `scenarios/` | `cve_triage` / `detection_gen` / `hitl_resume` / `multi_harness` / `named_supervisor` / `play_mode` (all runnable, evidence present) | ✅ | missing the self-iteration loop scenario |
| `tools/` | `attack_lookup` / `epss_kev` / `nvd_lookup` / `sigma_yara_lint` / `web_search` (Lambda handlers, reference stubs) | 🟡 | **missing** `siem_query` / `asset_lookup` / `enrich_ioc` / `create_ticket` / `search_registry` / `invoke_specialist` / `harness_ops` |
| `skills/` | `cve-triage-rubric` / `attack-path-reasoning` / `detection-writing-sop` / `ioc-vetting` | 🟩 | add domain skills as your SecOps program needs them |
| `specialists/` | `cve-intel` only (import-safe A2A skeleton; container not built) | 🟡 | **missing** `attack-mapper` / `threat-hunt` / `adversarial-reviewer` |
| `longrunning/` | `bas-runner` only (async-gen skeleton) | 🟡 | BAS case-generation + detection-replay logic, detonation microVM orchestration |
| `iac-cdk/lib/` | 8 synth-green stacks — `gateway` / `registry` / `memory` / `network` / `identity` / `guardrail` / `observability` / `harness` (+ `iam`); `iac-terraform/` mirror is `terraform validate`-clean | ✅ | `guardrail` / `identity` / `observability` LIVE-deployed (us-east-1); `runtime` stack still to add |
| `tests/` | 38 files, **740 offline passing** (+4 skipped) | ✅ | add tests with each new module |
| `evidence/` | 13 live-evidence sets | ✅ | add one per milestone |

### 0.3 Fit score (vs. a full three-layer SecOps agent program)

**L1 Strategy iteration ~80% · L2 Attack validation ~35% · L3 Foundation ~45% ·
self-iteration north star ~15%.**
→ Priority: **north star first (M1/M2), then land L2/L3 (M3/M4), then connect real data
planes (M5/M6), then packaging (M7).**

---

## 1. Code map: data / control flow (so you don't re-read the source)

```
declarative harness.yaml ──loader.load_harness_config──► create_harness kwargs
                                                              │
                        factory.provision_fleet ─────────────┤ (fleet, dry-run, idempotent, env tag-guard)
                                                              ▼
                                              core.create_harness ──► AgentCore control plane
                                                              │  wait_ready → READY
                                                              ▼
   runtime contract (core.invoke / invoke_with_tool_result):
   invoke(arn, session, text) ──► {text, stop_reason, tools_used, tool_use, metadata}
        └─ stop_reason == "tool_use"  ⇒ hit an inline_function (HITL gate); loop pauses
              └─ human decides ──► invoke_with_tool_result(arn, SAME session, tool_use, decision)
                    (two messages: assistant.toolUse + user.toolResult, same toolUseId, sent together)

   tools: tool_gateway(GATEWAY_ARN) exposes every MCP tool on the Gateway to the harness;
          allowedTools is an explicit allowlist (never '*');
          registry.ToolRegistry dual-gate (approved ∧ code-mapped) decides what is truly live.

   memory: managed_memory([SEMANTIC, SUMMARIZATION]) + actorId namespace = multi-tenant + feedback loop.
```

**Facts to internalize before writing code:**
- Harness is **Bedrock-model-only**; non-Bedrock (LiteLLM) lives only in a specialist's
  **Runtime container**.
- Delegation (build/invoke/evaluate a harness, call a specialist) is a **deterministic
  MCP tool** — never let the LLM hand-write HTTP.
- Long tasks are **async + polled**; never block inline past `timeoutSeconds`.
- Provisioning is fire-and-forget → always `wait_ready`; server-side config validation is
  silent → guard locally with `factory.provision_fleet(dry_run=True)` + `test_config_validation.py`.

---

## 2. Verified platform capabilities (checked against the installed SDK)

Introspected against boto3/botocore **1.43.39**, `bedrock-agentcore-control` — these
determine milestone feasibility, so they were confirmed, not assumed:

| Capability | Operations present | Verdict for the roadmap |
|---|---|---|
| **Harness update** | `UpdateHarness` ✅ | The meta-agent's "modify an agent" is a real in-place update — no delete+recreate fallback needed. |
| **Harness promotion** | `CreateHarnessEndpoint` / `GetHarnessEndpoint` / `UpdateHarnessEndpoint` / `ListHarnessEndpoints` / `ListHarnessVersions` ✅ | "Promote to production only if it passes" maps to a real **endpoint + version** mechanism — not an env-tag hack. |
| **Evaluation** | `CreateEvaluator` / `GetEvaluator` / `ListEvaluators` / `UpdateEvaluator` + `CreateOnlineEvaluationConfig` / `GetOnlineEvaluationConfig` / `ListOnlineEvaluationConfigs` ✅ | The self-improving loop can use a **managed Evaluator** (offline + online) — no need to self-build an LLM-judge to start. |
| **Datasets** | `CreateDatasetVersion` / `ListDatasetVersions` ✅ | Fixed evaluation datasets are versionable on-platform. |

> These are present in the SDK model; **confirm they are enabled in your target region /
> account** before M1/M2 (a live `list_evaluators` / `list_harness_endpoints` smoke call).
> `core.py` currently wraps only `create_harness` + `delete_harness`; M1 adds thin wrappers
> for `update_harness`, and M2 for the endpoint + evaluator operations.

---

## 3. Biggest gap & core design: the meta-agent self-iteration engine

The north star and the current top gap. `factory.py` today is *config-driven human
provisioning*, not *agent-driven natural-language provisioning*. Add a **three-layer
multi-agent orchestration**, layered on top of the existing base:

```
natural-language request / meeting notes / framework's own error
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ ① Meta Agent (orchestrator · Opus)                             │
│   - parse the request → emit a structured harness spec         │
│     {system_prompt, model, tools[], skills[], memory, limits}  │
│   - reuse loader.py's harness.yaml schema as the output target │
└───────────────┬───────────────────────────────────────────────┘
                ▼
┌───────────────────────────────────────────────────────────────┐
│ ② Agent Ops (executor · Sonnet)                                │
│   - call core.create_harness / update_harness to build/modify  │
│   - call core.invoke to batch-test against a fixed dataset     │
│   - reuse factory.py (cross-env tag-guard, dry-run, idempotent)│
└───────────────┬───────────────────────────────────────────────┘
                ▼
┌───────────────────────────────────────────────────────────────┐
│ ③ Self-Improving Agent (evaluation-driven loop)                │
│   - score ②'s agent with a managed Evaluator (LLM-judge/batch) │
│   - below bar → return reasoning to ② to adjust                │
│     (prompt / tool / skill)                                    │
│   - at/above bar → CreateHarnessEndpoint → production          │
│   - write Memory throughout (experience compounding)           │
└───────────────┬───────────────────────────────────────────────┘
                ▼
        test → staging → production (staged HITL gates)
```

**Implementation keys:**
1. **All three layers are themselves Harnesses** (harness builds harness) — harness
   create/update/invoke/endpoint are standard APIs, ideal to be orchestrated by another
   agent. Ship them as `harnesses/meta-agent/`, `harnesses/agent-ops/`,
   `harnesses/self-improving/`; delegation flows through Gateway MCP tools
   (`harness_ops`, `run_evaluation`) — deterministic, never model-authored HTTP.
2. **Evaluation-driven is the soul**: use the managed Evaluator API with a **fixed
   dataset** for an offline baseline + online signal; the pass bar is caller-defined
   (`eval/criteria.yaml`).
3. **Every step is HITL-gateable** (test → staging → prod); the production gate is an
   `inline_function`.
4. **Diverse intake**: natural language / meeting notes / the framework's own errors →
   an `intake/adapter.py` that normalizes all of these into the meta-agent's input
   ("an error auto-becomes a dev request" is an explicit goal).
5. **Platform self-improvement**: the meta-agent can also target *platform* harnesses
   (add capabilities to the platform itself) — a bootstrapping loop. Start with the
   human-gated version; never go fully autonomous first.

> ⚠️ This layer is **additive** — do not touch the live-validated L1 scenarios. Build it
> as an upper orchestration layer reusing `core` / `factory` / `loader` / `registry`.

---

## 4. Milestones (dependency-ordered; each = a deliverable, verifiable unit)

Each milestone gives: **goal / files / reused APIs / acceptance (live evidence) / traps.**
Suggest one feature branch per milestone.

### M0 — Environment & baseline reproduction (half a day)
**Goal:** on a fresh machine, get all 740 offline tests green and reproduce ≥1 live scenario.
- [ ] `uv sync` + `uv run pytest -q` → 740 passing (+4 skipped) (offline).
- [ ] Configure `SENTINEL_EXECUTION_ROLE_ARN` / `SENTINEL_REGION` / `AWS_PROFILE` (non-prod) — see `docs/SETUP.md`.
- [ ] Run `scenarios/scenario_cve_triage.py`; compare `evidence/cve_triage_result.json` shape.
- [ ] Run `scenarios/scenario_hitl_resume.py`; reproduce pause→approve→resume.
- [ ] **Smoke the live API surface** M1/M2 depend on: `list_harness_endpoints`, `list_evaluators` in your region — confirm enabled (see §2).

**Acceptance:** offline green + two live scenarios reproduced + API availability recorded.
**Traps:** `runtimeSessionId ≥ 33`; `read_timeout=300` already set in core; call `stop_runtime_session` when done.

### M1 — [P0] Meta-agent self-iteration engine ("agent builds agents") — ✅ DELIVERED, live-validated
**Status:** shipped and proven on real GA AgentCore. `scenarios/scenario_agent_factory_loop.py`
runs end-to-end (`evidence/agent_factory_loop_result.json`, `closed: true`): a natural-language
request → the meta-agent (Opus) emits a harness spec → `harness_ops` really builds a new harness
→ it reaches READY and answers a real invoke → teardown. `core.update_harness`, `tools/harness_ops`,
`intake/adapter.py`, and `harnesses/{meta-agent,agent-ops}` all landed with offline tests.
Scoped: delegation is in-process (wiring `harness_ops` as a live Gateway MCP target so agent-ops
calls it autonomously is M4).

**Goal:** three orchestration harnesses so "natural-language request → auto build/modify/test a harness" works (the eval loop is M2).

**New files:**
```
tools/harness_ops/handler.py            # ★ deterministic MCP tool: harness lifecycle for an agent to call
                                        #   actions: create / update / invoke / wait_ready / list / delete / create_endpoint
                                        #   calls sentinel_harness.core.*, strict param validation, structured JSON out
registry/tools.yaml                     # append harness_ops (owner=platform, status=approved)
harnesses/meta-agent/{system_prompt.md,harness.yaml}    # model=Opus; emit a valid harness spec
harnesses/agent-ops/{system_prompt.md,harness.yaml}     # model=Sonnet; build/modify/batch-invoke via harness_ops
intake/adapter.py                       # normalize natural language / meeting notes / framework errors → meta input
scenarios/scenario_agent_factory_loop.py# end-to-end: one-line request → spec → build+test a new alert-triage variant
tests/test_harness_ops.py               # handler unit tests (mock core)
tests/test_intake_adapter.py
```

**Reuse & prereqs:** `core.create_harness/invoke/wait_ready/delete_harness`; loader's
`harness.yaml` schema as the meta-agent's **structured output target**;
`factory.provision_fleet(dry_run)` for pre-build local validation.
> **Prereq patch:** add a thin `core.update_harness(harness_id, **full_config)` wrapper
> (calls `_control.update_harness`, **full-replacement** semantics — `UpdateHarness` is
> confirmed present, see §2). `harness_ops`'s `update` action calls it.

**Implementation keys:**
1. `harness_ops` is **deterministic** (agent sends structured params, handler calls core/boto3).
2. Meta-agent output **must be a valid `harness.yaml` structure** (loader-consumable +
   factory dry-run-checkable) — give the schema in the prompt, validate handler-side before building.
3. Agent-ops must `wait_ready` before testing; test with a fixed small dataset.
4. Diverse intake via `intake/adapter.py`.

**Acceptance (evidence `evidence/agent_factory_loop_*.json`):** a one-line request →
meta emits a valid spec → ops `dry_run` passes → real build → `wait_ready=READY` →
`invoke` returns structured output → `delete_harness` cleanup. X-Ray shows meta→ops→new-harness chain.
**Traps:** create-vs-update memory shapes differ; **agent update = full replacement**;
harness name rule `[a-zA-Z][a-zA-Z0-9_]{0,39}` (no hyphens — `factory._NAME_RE` guards it).

### M2 — [P0] Evaluation-driven self-improvement loop — ✅ DELIVERED (mechanisms live-validated)
**Status:** shipped with each mechanism proven on real GA AgentCore (dev account, cleaned up):
a deliberately weak agent was scored **0.0** by the independent LLM-judge harness
(`run_evaluation.score_answer`), a full-replacement `update_harness` produced **version 2**, and
**`CreateHarnessEndpoint`** promoted a harness to a named production endpoint
(`evidence/endpoint_promote_result.json`). Ships `tools/run_evaluation`, `harnesses/{llm-judge,
self-improving}`, `eval/` datasets + criteria, the `request_promotion_approval` HITL gate, and
endpoint-aware teardown, with 55 offline tests. **Honest limit:** a full green *single* run needs
fresh account InvokeHarness quota — a heavy test day exhausted it and the second re-score hit HTTP
403 (`second_eval_throttled`), an environment limit, not a defect. Scoring uses a self-built judge
(the managed Evaluate API needs OTEL/CloudWatch telemetry = M4).

**Goal:** score M1's agents, retry-with-reasoning when below bar, promote (create endpoint) only when at/above bar. The soul of self-iteration.

**New files:**
```
tools/run_evaluation/handler.py          # wrap the managed Evaluator API (see §2) as an MCP tool
tools/harness_ops/handler.py             # [extend] add a promote action → CreateHarnessEndpoint
harnesses/self-improving/{system_prompt.md,harness.yaml}  # read eval → judge → retry-with-reasoning → promote
eval/datasets/                           # fixed offline datasets: cve_triage.jsonl / detection_gen.jsonl ...
eval/criteria.yaml                       # caller-defined pass bar
loader.py                                # [edit] add request_promotion_approval to _INLINE_GATES
scenarios/scenario_self_improve_loop.py  # end-to-end: build → fail eval → retry → pass → HITL approve → promote
tests/test_run_evaluation.py
```

**Reuse:** M1's `harness_ops`; `core.invoke_with_tool_result` (the promotion gate resume);
the managed Evaluator + Harness endpoint APIs (§2).

**Implementation keys:**
1. **Retry with reasoning**: self-improving reads eval attribution → concrete
   "change prompt / swap tool / add skill" suggestions → agent-ops rebuilds → re-eval
   (max N rounds, no infinite loop).
2. **Promote only when passing**: eval ≥ `eval/criteria.yaml` **and** human
   `request_promotion_approval` → `CreateHarnessEndpoint` (the confirmed promotion
   mechanism). Stage with `SENTINEL_ENV` test→staging→prod (factory tag-guard isolates).
3. Write Memory throughout (experience compounding).

**Acceptance (`evidence/self_improve_loop_*.json`):** a deliberately-underspecified agent
→ eval fails + attributes → retry improves prompt → re-eval passes → blocks at
`request_promotion_approval` → approve creates the endpoint; reject once → assert no promotion.
**Traps:** eval is async → poll; hard cap the retry loop + require a reasoning change each round.

### M3 — L2 attack validation & simulation — ✅ DELIVERED (real core validated; detonation/specialists = honest skeletons)
**Status:** shipped. The provable core is REAL, deterministic, offline (no LLM, no invoke quota):
`tools/sigma_match` (a Sigma detection *matcher*, not a linter), `longrunning/bas-runner/bas_cases.py`
(BAS case-gen + detection-replay), and `scenarios/scenario_bas_replay.py` — live-validated offline:
4 ATT&CK techniques × 2 Sigma rules → detected {T1059.001, T1046}, **blind spots {T1003.001,
T1547.001}**, coverage 0.5 (`evidence/bas_replay_result.json`). `specialists/attack-mapper` ships a
real `build_attack_paths()` graph reasoner + `tools/asset_lookup`; `specialists/threat-hunt` a real
`build_hunt_plan()`. **Honest skeletons (import-safe, SIMULATED — no real malware/VM/exploit/network):**
`longrunning/detonation/` models the one-shot-microVM-per-session lifecycle (destroy-after-use enforced,
every action gated through `sandbox_hooks`, samples referenced only by an `s3://` dropbox URI, offensive
steps HITL-gated); the A2A serving wrappers use guarded imports. 112 new tests; suite → 591 (+3 skips).

**Goal:** BAS case auto-generation + detection-replay, sample detonation in a one-shot microVM, attack-path reasoning.
```
longrunning/bas-runner/runner_loop.py       # [implement] BAS case gen + replay vs. current detection rules
longrunning/detonation/bedrock_entrypoint.py# sample detonation Runtime (async-gen + checkpoint)
longrunning/detonation/src/vm.py            # one-shot microVM per session → destroy after use
tools/asset_lookup/handler.py               # exposure/asset surface for attack-path (stub first, real in M5)
specialists/attack-mapper/agent_a2a.py      # attack-path reasoning (exposure → topology → high-risk chains)
specialists/threat-hunt/agent_a2a.py        # threat-hunting specialist
scenarios/scenario_bas_replay.py            # BAS gen → replay → report "detection blind spots"
tests/test_detonation.py / test_attack_mapper.py
```
**Reuse:** `longrunning/bas-runner` async-gen/checkpoint skeleton; `sandbox_hooks.py`;
`simulation.py` (Play Mode gating); `specialists/cve-intel` as the A2A template.
**Keys:** samples enter via a **controlled S3 dropbox — never live fetch**; each detonation
= isolated microVM destroyed after use; long tasks async + Memory across restarts.
**Acceptance (`evidence/bas_replay_*.json`):** a set of ATT&CK techniques → auto BAS cases →
replay vs. Sigma rules → "undetected techniques" list; detonation negative test:
path-traversal / disallowed command blocked by `sandbox_hooks`.

### M4 — L3 foundation: identity / gateway / egress / observability — ✅ DELIVERED (3 stacks live-deployed + validated)
**Status:** shipped as dual-track IaC (CDK main + Terraform mirror), authored on verified recon
facts and partially deployed live on the dev account (us-east-1), free-tier stacks left running:
- **Guardrail** (`iac-cdk/lib/guardrail-stack.ts`): deployed; `ApplyGuardrail` really intervened
  (`GUARDRAIL_INTERVENED`) masking a fake AWS key → `{aws-access-key-id}` and an sk- token →
  `{generic-api-token}` (`evidence/m4_guardrail_result.json`).
- **Identity** (`iac-cdk/lib/identity-stack.ts`): Cognito user pool + resource server + domain +
  human/M2M clients deployed; OIDC discovery endpoint reachable (RS256, token_endpoint), and
  `gateway.cognito_jwt_authorizer()` wires it into a CUSTOM_JWT gateway (human aud vs M2M allowedClients).
- **Observability** (`iac-cdk/lib/observability-stack.ts`): CloudWatch dashboard + `TokensPerScenario`
  metric + log group + monthly Budgets alarm deployed.
- **Network** (`iac-cdk/lib/network-stack.ts`): private VPC, isolated subnet, no NAT/IGW; the
  PrivateLink interface endpoints (the only standing ~$30/mo cost) are cost-gated OFF by default
  (`-c sentinel:deployVpcEndpoints=true` opts in). **Egress control LIVE-validated**: deployed with
  endpoints, `scenario_egress_control.py` proved no IGW / no 0.0.0.0/0 route / PrivateLink-only
  (`evidence/egress_control_result.json`, closed:true); endpoints then torn down to drop the cost.
  All 4 M4 acceptance items are now live-proven (egress, Guardrail masking, observability, JWT).
- **Harness** (`iac-cdk/lib/harness-stack.ts`): the NATIVE `AWS::BedrockAgentCore::Harness` CFN type
  (recon corrected the old "needs a custom resource" assumption). Terraform mirror in `iac-terraform/`
  (`terraform validate` clean). Evidence: `evidence/m4_live_deploy_result.json`.

**Goal:** enterprise MCP gateway (JWT + API-key auth + Guardrail injection defense + audit),
private VPC + egress allowlist, a unified LiteLLM inference gateway, CloudWatch observability + cost.
```
iac-cdk/lib/network-stack.ts        # private VPC (no PUBLIC networkMode) + NAT egress allowlist
iac-cdk/lib/harness-cr-stack.ts     # CFN Custom Resource for harness lifecycle (adopt-or-delete/backoff)
iac-cdk/lib/runtime-stack.ts        # specialist + longrunning Runtime provisioning
iac-cdk/lib/observability-stack.ts  # CW GenAI dashboard + X-Ray + TokensPerScenario + Budgets alarm
gateway.py                          # [extend] CUSTOM_JWT authorizer + API-key auth + Guardrail interceptor
litellm/gateway/                    # standalone LiteLLM inference gateway (single model entry + audit)
scenarios/runner.py                 # [edit] parse per-invocation tokens from metadata stream → TokensPerScenario CW metric
```
**Keys:** humans via **JWT + API key** (no per-person IAM); agents→AWS via execution role;
**only `web_search` reaches the internet**; every tool response passes a **Guardrail**;
Runtime in a **private VPC, not PUBLIC**.
**Acceptance (`evidence/infra_*.json` + screenshots):** `cdk synth` green → deploy → ①
raw-download from a specialist microVM fails, `web_search` succeeds ② injected secret in a
tool response is masked by Guardrail (visible in trace) ③ CW dashboard shows per-session
trace + `TokensPerScenario` + a Budgets alarm ④ JWT/API-key auth paths work.
**Traps:** Harness has no native CDK construct → CFN Custom Resource (adopt-or-delete on
`ConflictException`, backoff on `AccessDenied`, delete-and-wait); pin SDK versions.

### M5 — Data planes + domain skills + multi-account ops — ✅ DELIVERED (DIY mock world, offline)
**Goal:** stand up data-plane tools, domain skills, and multi-account ops automation against a
self-contained **DIY mock world** (no customer data required for demo/POC); each tool keeps a
`*_LIVE` opt-in as the seam to a real backend later.
- [x] `tools/siem_query` / `asset_lookup` / `enrich_ioc` / `create_ticket`: deterministic tools reading the
      cross-linked fictional world in `mockdata/` (RFC-5737 IPs, `example.test`); `*_LIVE` opts into a real
      SIEM / search store / asset system / ticketing via MCP or API bridge through the Gateway. — `mockdata/`, `tools/`
- [x] Domain skills under `skills/<name>/SKILL.md` (generic SecOps: `cve-asset-triage`, `soc-ip-lookup`,
      `soc-triage`, `incident-ticketing`, `multi-account-ops`) — each references only real repo tools; the
      ops tool is registered in `registry/tools.yaml` under the dual-gate. — `skills/`, `tools/ops_query/`
- [x] `harnesses/ops-automation/`: a multi-account ops supervisor over a fictional 4-account inventory
      (`mockdata/accounts.py`) via the read-only `tools/ops_query` tool (`OPS_QUERY_LIVE` → AWS Organizations /
      support API / per-account CloudWatch later); every change gated on HITL. — `harnesses/ops-automation/`
- [x] End-to-end CVE triage against the mock asset plane: id → `nvd_lookup`+`epss_kev` → `asset_lookup` →
      structured `CVETriage` (blast radius + KEV) → HITL — `scenarios/scenario_cve_asset_triage.py`.

**Acceptance (`evidence/cve_asset_triage_result.json`, closed:true):** Log4Shell `CVE-2021-44228` resolves to
`web-01` as the affected host (CVSS + CISA-KEV exploited), computes a blast radius (reachable `app-01`,
internet-exposed), recommends `patch_now_exposed_and_exploited`, and requires analyst sign-off before any
action; a CVE affecting no mock host yields an empty affected-host list (no crash). Deterministic + offline.

**Reuse:** M1/M4 Gateway + registry dual-gate + JWT/API-key. **Trap:** data planes vary →
use `tool_remote_mcp(url, headers=${arn:...})` (token via the vault, agent never sees plaintext).
**Honest limit:** the world is DIY mock, not a live customer plane; the `*_LIVE` env on each tool is the
un-exercised seam to a real backend (needs a target account + the backend's MCP/API contract).

### M6 — Feedback-loop automation (strategy self-iteration closed) — ✅ DELIVERED (offline, deterministic)
**Goal:** disposition results auto-feed strategy.
- [x] After alert-triage writes TP/FP to Memory `facts/{tenant}` (a `managed_memory_writer` seam),
      **auto-trigger** whitelist optimization / rule regeneration — event-driven via
      `feedback.detect_triggers` (fp_rate + min_events thresholds), not just a memory write. — `sentinel_harness/feedback.py`
- [x] Wire the M1/M2 self-iteration engine into the strategy domain: an only-FP / hit-rate-drop rule
      auto-generates a `rule_regeneration` task handed toward `harnesses/self-improving` (via `harness_ops`). — `scenarios/scenario_feedback_loop.py`

**Acceptance (`evidence/feedback_loop_result.json`, closed:true):** a batch of FP dispositions for the
noisy rule "Known-Good CDN Traffic" auto-triggered a `whitelist_optimization` task; `tools/whitelist_optimizer`
synthesized a Sigma filter (`dst_domain|endswith: assets.example.com`) that suppresses 3/3 FPs while
**provably preserving the Log4Shell true positive**; the healthy TP rule produced no task; and nothing
publishes except through the `request_publish_approval` HITL gate. Deterministic + offline; the rule-regen
hand-off reuses the live-capable M1/M2 engine (driven offline here, labeled a wiring point).

### M7 — Delivery form (one-command deploy + no lock-in) — ✅ DELIVERED
- [x] Top-level `Makefile` — one ergonomic entry point (`make help` lists 13 targets): `test` / `lint` /
      `synth` / `deploy` / `deploy-endpoints` / `seed-registry` / `create-harnesses` / `smoke` / `demo` /
      `reset` / `destroy` / `clean`; `deploy`/`destroy` delegate to the existing M4 `deploy/deploy.sh`+`destroy.sh`
      (confirm account+region) rather than reimplementing deploy. — `Makefile`
- [x] `make seed-registry` (offline dual-gate governance check + prints approved tools) /
      `make create-harnesses` (**DRY_RUN=1 offline validate by default** — 8 harnesses `would_create`, zero AWS;
      `DRY_RUN=0` + creds to really create) / `make smoke` / `make reset`. — `deploy/seed_registry.sh`, `deploy/create_harnesses.sh`, `deploy/smoke.sh`
- [x] `sentinel export <harness.yaml|name> [-o out.py]`: emits editable **Strands** starter code (model · system
      prompt · tool allowlist · memory note) so a team can run the same agent on AgentCore Runtime / self-hosted
      and walk away from the managed harness — no lock-in. Pure text artifact (no `strands` import at export time). — `sentinel_harness/exporter.py`, `sentinel export`
- [x] `docs/QUICKSTART.md`: 60-second offline path (`make test` → `make demo` → `evidence/`) + the live path
      (`make deploy`, cost note, `make destroy`) + the no-lock-in export. — `docs/QUICKSTART.md`
- [x] `tests/smoke/`: offline acceptance suite (default offline; `SENTINEL_SMOKE_LIVE=1` opt-in for live). — `tests/smoke/`

**Acceptance:** `make test` → 1155 offline tests green; `make seed-registry` → dual-gate `ok`;
`make create-harnesses` (DRY_RUN=1) → 8 harnesses validate offline with zero AWS; `sentinel export` → valid
compilable Strands Python; `make smoke` → the offline acceptance suite green. A fresh non-prod account can then
run `make deploy` (free-tier foundation) and the live scenarios; `make destroy` tears it all down.

---

## 5. Key specs (P0 detail; other milestones self-expand at this granularity)

### 5.1 `tools/harness_ops/handler.py` (M1 core, write first)
- Input: `{action, params}`, `action ∈ {create, update, invoke, wait_ready, list, delete, create_endpoint}`.
- Each action **only validates params + calls `sentinel_harness.core.*`**, returns
  structured JSON (`harnessId/arn/status/text/tools_used/tool_use`).
- `create` pre-validates with `factory._resolve_entry`-style checks (name rule + `${ENV}` expansion + dry check).
- `update` = **read existing config → merge → full replacement** (agent update semantics).
- Registered as a Gateway MCP target; `registry/tools.yaml` adds `harness_ops`
  (`owner: platform, status: approved`); code side into `TOOL_FACTORY_MAP` →
  `registry.governance_check().ok` must be true.

### 5.2 meta-agent system_prompt (essentials)
"You are the platform's meta-orchestration agent. Decompose the user's request into **one
valid harness spec** (strictly output the `harness.yaml` structure:
`harnessName / model / systemPrompt / tools / allowedTools / memory / maxIterations /
timeoutSeconds`). `allowedTools` must be explicit — never `*`. Model choice: Opus for deep
research, Sonnet for rules/orchestration, Haiku for high-volume triage. Do not invent tool
names — only registry-approved tools. Emit the spec and hand off to agent-ops; do not build yourself."

### 5.3 self-improving retry protocol
```
loop (max 3):
  eval = run_evaluation(harness, dataset)         # async → poll
  if eval.score >= criteria: break
  reasoning = analyze(eval.failures)              # attribute: weak prompt? missing tool? missing skill?
  spec' = agent_ops.revise(spec, reasoning)       # concrete change WITH reasoning
  harness = harness_ops.update(spec')             # full replacement
if eval.score >= criteria:
  request_promotion_approval(...)                 # HITL gate (inline_function)
  if approved: harness_ops.create_endpoint(...)   # promote (CreateHarnessEndpoint)
```

---

## 6. Testing & acceptance charter
- **offline**: every new module gets `tests/test_*.py` (mock AWS); keep `uv run pytest -q` green (now 740, +4 skipped, only grows).
- **config parity**: every new `harness.yaml` must pass `factory.provision_fleet(dry_run=True)` + `test_config_validation.py`.
- **live evidence**: each milestone runs one real call, drops `evidence/<milestone>_result.json` + `.log`.
- **governance**: each new tool keeps `registry.governance_check().ok == True`.
- **negative tests**: egress block / Guardrail masking / HITL-unapproved-no-execute / sandbox path-traversal block — each with a "must fail" assertion.

---

## 7. Ironclad rules (pre-baked to avoid traps)
1. `allowedTools` is always an explicit list — **never `['*']`** (the single most important guardrail).
2. Harness is **Bedrock-model-only**; LiteLLM/non-Bedrock only in a specialist Runtime container.
3. Delegation (build/invoke/evaluate a harness, call a specialist) is a **deterministic MCP tool** — **never LLM-authored HTTP**.
4. Registry `autoApproval=false`; **a tool is live only if registry-approved ∧ code-mapped**.
5. `runtimeSessionId ≥ 33 chars`; **serialize same-session calls** (concurrent same-session corrupts memory).
6. Provisioning is fire-and-forget → **always `wait_ready`**; pre-build **`dry_run`** locally (server validation is silent).
7. create-vs-update harness memory shapes differ; **agent/harness update = full replacement**.
8. Long tasks **async + poll**; never block inline past `timeoutSeconds`; malware/BAS/detonation use the long-running skeleton.
9. Runtime in a **private VPC, not PUBLIC**; **only `web_search` reaches the internet, no raw-download**; samples via S3 dropbox, never live fetch.
10. HITL resume is a **two-message contract** (assistant.toolUse + user.toolResult, same toolUseId, sent together) — else the session corrupts (see `core.invoke_with_tool_result`).
11. Cleanup in order: harness → Memory → role; leave no `DELETE_FAILED` orphans; preserve the shared X-Ray delivery destination.
12. **HITL kills hallucination**: an independent adversarial-reviewer (no self-approval bias) + inline_function gates + prompts that force tool/memory grounding and forbid confabulation.
13. **No customer PII/secrets in this repo** — generic SecOps only; real data lives in your account, reached via `${arn:...}` token-vault refs so the agent never sees plaintext.
14. Push via the standard git-operations workflow; never leak a token in a URL/command.

---

## 8. Recommended build order (one line)

**M0 reproduce baseline → M1 agent-building engine → M2 evaluation self-iteration loop →
(north star reached) → M3 land L2 → M4 L3 foundation → M5 connect real data planes →
M6 feedback loop → M7 one-command delivery.**
M0–M2 are the shortest path to the "agent builds agents, controllable and observable" north
star — do them first.

---

## Appendix A — Deployment prerequisites to confirm before M5

Not code — align these with your platform/security owners before M5, or it will stall:
- [ ] **Test account + credits**: an enabled account with AgentCore/Bedrock model access in your region.
- [ ] **Data-plane connections**: which SIEM / internal search store / warehouse / asset system /
      ticketing you use — decides how M5's `siem_query` / `asset_lookup` / `create_ticket` connect (MCP or API bridge).
- [ ] **Identity**: confirm JWT + API-key auth (no per-person IAM); what your existing IdP/OAuth is.
- [ ] **Model access**: which models are available in the account; whether LiteLLM is needed for self-hosted/third-party models.
- [ ] **Evaluations availability**: confirm the managed Evaluator API is enabled in your region (see §2); otherwise fall back to an offline fixed dataset + a self-built LLM-judge harness.
- [ ] **Domain skill inventory**: the exact names / inputs / outputs of your existing SecOps skills, so M5 fills in `skills/` accordingly.
- [ ] **Sample-handling process (detonation)**: how samples enter (controlled S3 dropbox), the detonation targets, and the compliance boundary (never live fetch).
- [ ] **Multi-account ops scope**: the account range and any subnet/IP constraints affecting Runtime deployment.

> `sentinel-harness` stays **generic SecOps, zero deployment secrets**; account-specific
> details live only in your private environment, reached via `${arn:...}` token-vault refs.

## Appendix B — Requirement → milestone traceability

| Requirement | Milestone |
|---|---|
| Agent builds agents, self-iterating, controllable & observable (**north star**) | **M1 + M2** |
| Unified framework circulating skills/MCP (share capability) + registry governance | M1 (dual-gate present) + M5 |
| Sample detonation VM long tasks + memory | M3 |
| Strategy-research self-iteration / CVE evaluation | M2 (strategy loop) + M5 (real assets) / M1 (cve_triage present) |
| Identity parity / API key / OAuth | M4 |
| Egress control (web_search, no raw-download) + isolate-and-destroy | M4 + M3 |
| Cost visibility + Runtime billing advantage | M4 |
| Multi-account ops automation | M5 |
| Console-wide observability | M4 |
| Disposition → strategy feedback loop | M6 |
| One-command delivery + no lock-in | M7 |
| Backstop: multi-round agents + human review + kill hallucination | throughout (HITL gates + adversarial-reviewer, present) |
