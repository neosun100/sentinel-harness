"""
Scenario — deployment cost / latency / ops BENCHMARK (procurement proof)
========================================================================
Turns the repo's "managed Harness beats DIY / EKS" claim into a reproducible
number a security team can put in a procurement doc.

.. warning::
   **DETERMINISTIC OFFLINE MODEL — zero AWS, zero network, no clock.** It prices
   what three deployment modes *would* cost/latency/toil for a workload from
   dated public list prices (``sentinel_harness.benchmark_models``). It does not
   bill a real account. VERIFY the unit prices (``benchmark_models.AS_OF``) before
   quoting. Same workload in → byte-identical report out.

WHY this scenario exists
------------------------
The customer's sharpest procurement question was cost: "we already run a standing
32c/64G cluster for our bursty SecOps automation — why move to a managed loop?"
Every other scenario answers a *capability* question; this one answers the
*money + toil* question, and writes both an ``evidence/*.json`` artifact and a
paste-ready Markdown table (``evidence/benchmark_report.md``).

What it proves
--------------
For a generic bursty SecOps workload (default: 6,000 invokes/mo), the managed
AgentCore Harness is cheapest because a standing cluster bills 24×7 while the
managed mode's compute is idle-free — AND the platform, not you, owns the agent
loop / scaling / HITL toil. The model-token cost is identical across all modes
(you pay Bedrock the same per token however you host the loop); the honest,
load-bearing differentiators are compute and ops-hours.

Egress & secrets posture
------------------------
Zero network / AWS / LLM I/O by default. No secrets, no account ids/ARNs; the
evidence writer scrubs any 12-digit id defensively, mirroring the other scenarios.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import benchmark as bm  # noqa: E402
from sentinel_harness.benchmark_models import (  # noqa: E402
    AS_OF,
    DEFAULT_WORKLOAD,
    MODEL_PRICES,
    Workload,
)

RESULT: dict = {"scenario": "benchmark", "steps": []}


def rec(step: str, ok: bool, data: Any) -> None:
    """Append one auditable step to the evidence trail (same shape as siblings)."""
    RESULT["steps"].append({"step": step, "ok": bool(ok), "data": data})


_ACCT_RE = re.compile(r"\b\d{12}\b")


def _scrub(obj: Any) -> Any:
    """Recursively replace any 12-digit account id with the 000000000000 placeholder.

    Defensive only — this scenario never touches an account — but kept identical to
    the other scenarios so the evidence-writing contract is uniform."""
    if isinstance(obj, str):
        return _ACCT_RE.sub("000000000000", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def run(workload: Workload = DEFAULT_WORKLOAD, model_id: str = "sonnet") -> dict:
    """Run the benchmark end to end and build the evidence RESULT.

    Deterministic: model → report → dict/markdown, asserting the managed mode wins
    the default bursty workload (the procurement headline). Returns RESULT."""
    rec("inputs", True, {
        "workload": workload.name,
        "invokes_per_month": workload.invokes_per_month,
        "input_tokens": workload.input_tokens,
        "output_tokens": workload.output_tokens,
        "model_id": model_id,
        "prices_as_of": AS_OF,
    })

    report = bm.run_benchmark(workload, model_id)
    report_dict = bm.report_to_dict(report)
    rec("run_benchmark", True, report_dict)

    # The load-bearing honesty invariant: model cost equal across every mode.
    model_costs = {m["model_usd"] for m in report_dict["modes"]}
    model_cost_identical = len(model_costs) == 1
    rec("model_cost_identical_across_modes", model_cost_identical, {
        "model_usd_values": sorted(model_costs),
    })

    managed_cheapest = report.cheapest_mode == "agentcore_harness"
    rec("managed_mode_cheapest", managed_cheapest, {
        "cheapest_mode": report.cheapest_mode,
        "baseline_mode": report.baseline_mode,
        "savings_usd": report.savings_vs_baseline_usd,
        "savings_pct": report.savings_vs_baseline_pct,
    })

    RESULT["markdown"] = bm.report_to_markdown(report)

    closed = model_cost_identical and managed_cheapest
    RESULT["verdict"] = {
        "cheapest_mode": report.cheapest_mode,
        "baseline_mode": report.baseline_mode,
        "savings_vs_baseline_usd": report.savings_vs_baseline_usd,
        "savings_vs_baseline_pct": report.savings_vs_baseline_pct,
        "model_cost_identical_across_modes": model_cost_identical,
        "managed_mode_cheapest": managed_cheapest,
        "closed": closed,
        "note": (
            "Deterministic offline model over dated list prices; verify prices "
            "before quoting. Model-token cost is identical across modes — the "
            "differentiators are idle-free compute and platform-owned ops toil."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="sonnet", choices=sorted(MODEL_PRICES),
                        help="Bedrock model family to price (default: sonnet)")
    parser.add_argument("--invokes", type=int, default=DEFAULT_WORKLOAD.invokes_per_month,
                        help="invokes per month (default: the generic SecOps sizing)")
    parser.add_argument("--input-tokens", type=int, default=DEFAULT_WORKLOAD.input_tokens)
    parser.add_argument("--output-tokens", type=int, default=DEFAULT_WORKLOAD.output_tokens)
    args = parser.parse_args()

    workload = Workload(
        name=DEFAULT_WORKLOAD.name,
        invokes_per_month=args.invokes,
        input_tokens=args.input_tokens,
        output_tokens=args.output_tokens,
    )
    run(workload, args.model)

    out = os.path.join(REPO_ROOT, "evidence", "benchmark_result.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)

    md_out = os.path.join(REPO_ROOT, "evidence", "benchmark_report.md")
    with open(md_out, "w") as fh:
        fh.write(RESULT["markdown"])

    print(RESULT["markdown"])
    print("\nsaved evidence/benchmark_result.json + evidence/benchmark_report.md  ·  verdict:",
          json.dumps(RESULT.get("verdict"), ensure_ascii=False))
