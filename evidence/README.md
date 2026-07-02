# Evidence — live validation

These are **captured results from real runs** against the GA Amazon Bedrock AgentCore
Harness API on a **non-production dev account**. Account IDs have been scrubbed to
`<ACCOUNT_ID>`. Each `*_result.json` is written by the matching script in
`scenarios/`; each `*.log` is the raw run log. Proof, not claims.

## Scenario 1 — CVE triage with a human-in-the-loop gate
`scenarios/scenario_cve_triage.py` → `cve_triage_result.json`

| Check | Result |
|---|---|
| `hit_human_review_gate` | ✅ `true` — the agent called `request_human_review` and stopped (`stopReason=tool_use`) before recommending anything |
| `did_deterministic_calc` | ✅ `true` — used the code interpreter for the affected-asset math instead of guessing |

One harness combines a code interpreter, an `inline_function` human gate, and managed
memory — **zero orchestration code**. Security decisions are not made by the AI alone.

## Scenario 2 — Multi-harness parallelism + supervisor
`scenarios/scenario_multi_harness.py` → `multi_harness_result.json`

| Check | Result |
|---|---|
| pattern | multi-harness parallel + supervisor synthesis |
| **parallel speedup vs serial** | ✅ **~2.6×** (3 specialist harnesses run concurrently; a supervisor merges them) |

This is the answer to "a harness is single-agent": parallelism comes from running
**multiple** harnesses and synthesizing. (Speedup varies run to run with model latency.)

## Scenario 3 — Detection generation with an independent adversarial reviewer
`scenarios/scenario_detection_gen.py` → `detection_gen_result.json`

| Check | Result |
|---|---|
| `generator_and_reviewer_are_separate_harnesses` | ✅ `true` — generator and reviewer are distinct harnesses |
| `adversarial_review_ran` | ⚠️ reviewer was **invoked**, but in this captured run it returned only a preamble and did not emit the parseable `VERDICT: approve\|revise` line (`approved_signal:false`). Re-run with larger reviewer `max_iterations`/`max_tokens` to capture a full verdict. |
| `hit_publish_human_gate` | ✅ `true` — the publish step required analyst sign-off via `inline_function` (pause reached; see HITL note below) |

Demonstrates the **structure** of generation ≠ evaluation (the reviewer is a distinct
harness with no self-approval bias) and a human publish gate. The reviewer's *content*
verdict was not fully captured in this run — an honest caveat, not a hidden failure.

## Honest limitations (as observed live)

- **Long-term memory extraction is asynchronous (minutes-scale).** A cross-session
  semantic recall issued seconds after a write can return empty. In demos: teach → wait
  → recall. This is expected behavior, not a defect.
- **A single harness is single-agent.** Multi-agent orchestration/graph/hooks are not
  native; use multiple harnesses + a supervisor (shown here), or export to Strands code
  and run on AgentCore Runtime.

## Reproduce

```bash
export AWS_PROFILE=<non-prod>; export SENTINEL_REGION=us-east-1
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<role>"
python scenarios/scenario_cve_triage.py
python scenarios/scenario_multi_harness.py
python scenarios/scenario_detection_gen.py
sentinel cleanup sentinel_        # tear down
```
