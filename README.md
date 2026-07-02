<h1 align="center">sentinel-harness</h1>

<p align="center">
  <b>Production security-operations agents, built as <i>configuration</i> — on Amazon Bedrock AgentCore Harness.</b><br/>
  <sub>Strategy iteration · attack simulation · foundation — a reference SecOps agent platform. Zero orchestration code.</sub>
</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-MIT--0-30d158"/>
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-2997ff"/>
  <img alt="bedrock-agentcore" src="https://img.shields.io/badge/Amazon%20Bedrock-AgentCore%20Harness-ff9900"/>
  <img alt="live-validated" src="https://img.shields.io/badge/scenarios-live%20validated-1D8102"/>
</p>

---

## Why

A SecOps team usually already has models, internal MCP servers, and a pile of skills — but **no framework to circulate those capabilities** so that "what one analyst has, everyone has." `sentinel-harness` is that framework, built on the [Amazon Bedrock AgentCore **Harness**](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html): you declare an agent (model + system prompt + tools + skills + memory + limits) and AWS runs the whole agent loop. Swapping a model, adding a tool, or replacing a skill is **a config change, not a rebuild**.

Everything here is **generic security-ops** content and **runs on a non-production dev account** — no proprietary data, no real vulnerable assets, no real malware.

## The model: three layers

| Layer | What it does | How it maps to the harness |
|---|---|---|
| **1 · Strategy iteration** | research → detection-rule generation + cross-review → alert triage → feedback loop | `research-supervisor` + specialists; `detection-eng` (generate → adversarial review → human-merge gate); `alert-triage`; verdicts persisted to Memory to close the loop |
| **2 · Simulation** | BAS / attack-path / adversary emulation (Play Mode, human-confirmed) | long-running Runtime skeleton; every offensive step behind an `inline_function` human gate |
| **3 · Foundation** | sandbox isolation · platform self-iteration · AI coding · cyber-skills | one microVM per session + PreToolUse security hooks; Agent Factory provisioning; LiteLLM + Gateway; versioned `SKILL.md` skills + a central tool/skill registry |

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design and **[docs/BLUEPRINT.md](docs/BLUEPRINT.md)** for the layer→primitive mapping and the AWS-sample patterns it borrows.

## ✅ Live-validated scenarios

Each scenario is a runnable script under [`scenarios/`](scenarios/), validated against the GA API on a non-production account. Evidence lands in [`evidence/`](evidence/).

| Scenario | Proves | Layer |
|---|---|---|
| [`scenario_cve_triage.py`](scenarios/scenario_cve_triage.py) | CVE triage with **deterministic compute** (code interpreter) + a **mandatory human-in-the-loop gate** + managed memory — zero orchestration code | L1 research |
| [`scenario_multi_harness.py`](scenarios/scenario_multi_harness.py) | **Multi-harness parallelism** (3 specialists + a supervisor) — the answer to "a harness is single-agent"; measured wall-clock speedup vs serial | L1 collaboration |
| [`scenario_detection_gen.py`](scenarios/scenario_detection_gen.py) | Detection-rule generation with an **independent adversarial-reviewer harness** (generation ≠ evaluation) + a publish human-gate | L1 detection |

## Design principles (baked into the core library)

- **Multi-agent = multiple harnesses + a supervisor.** One harness is single-agent + multi-tool; parallelism comes from running many and synthesizing.
- **Human-in-the-loop kills hallucination.** High-stakes security decisions pass through an `inline_function` gate; an independent reviewer harness attacks generated artifacts.
- **Egress is controlled.** Prefer a `web_search`-style tool (text only) over raw download; there is no raw-download tool.
- **Auth done right.** An IAM *execution role* scopes which internal AWS resources the agent may touch (least privilege — not per-person mapping). Human callers use OAuth/JWT (`customJWTAuthorizer`); third-party secrets live in the AgentCore Identity token vault — the agent never sees raw credentials.
- **No lock-in.** When config isn't enough, `agentcore export harness` emits editable Strands code that runs on the same platform.

## Quick start

```bash
git clone <this repo> && cd sentinel-harness
pip install -e .

# configure (12-factor; nothing hardcoded)
export AWS_PROFILE=<your-non-prod-profile>          # never production
export SENTINEL_REGION=us-east-1
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<your-harness-role>"

# run a scenario end-to-end (creates harnesses, invokes, prints evidence)
python scenarios/scenario_cve_triage.py
python scenarios/scenario_multi_harness.py

# or via the CLI
sentinel run-scenario cve_triage
sentinel cleanup sentinel_        # tear down all harnesses this repo created
```

The execution-role least-privilege policy is in **[docs/SETUP.md](docs/SETUP.md)**.

## Repo layout

```
sentinel-harness/
├── sentinel_harness/        core library (core.py) + CLI
├── harnesses/               declarative harness configs (Layer 1 supervisors)
├── skills/                  Agent Skills (SKILL.md, AgentSkills.io format)
├── tools/                   Lambda-style MCP tool templates (nvd/epss/attack/web_search/sigma-lint)
├── scenarios/               runnable, live-validated scenario scripts
├── evidence/                captured live-run results (proof, not claims)
├── docs/                    ARCHITECTURE / BLUEPRINT / SETUP / HARNESSES
├── tests/                   offline config-validation tests
└── .github/workflows/       CI incl. a customer-name / secret scan gate
```

## Safety & scope

This is a **reference implementation and educational sample** for authorized, defensive security operations. It ships stubbed/mockable tools and uses only public threat examples. Bring your own least-privilege role, VPC, and data controls before any real use.

## License

[MIT-0](LICENSE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
