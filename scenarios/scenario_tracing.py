"""
Scenario — end-to-end OTEL/GenAI trace over the self-iteration chain
====================================================================
Emits ONE distributed trace spanning the whole north-star chain — meta-agent →
agent-ops (build) → run_evaluation (judge) → agent-ops (promote) — so the managed
online-eval path (which scores the ``aws/spans`` Transaction-Search source) has
code-emitted GenAI spans to score, not only runtime-produced ones. Closes the
``docs/OBSERVABILITY.md`` "future item".

.. warning::
   **DETERMINISTIC OFFLINE — zero AWS, zero network, no clock.** Spans are emitted
   as structured JSON lines by ``sentinel_harness.tracing`` (the default path);
   setting ``SENTINEL_OTEL=1`` ALSO drives real OpenTelemetry spans into X-Ray /
   Transaction Search (lazy import, gated). Same inputs → byte-identical evidence.

What it proves (verdict.closed)
-------------------------------
1. A single trace_id ties every step of the chain together.
2. The spans nest correctly (judge under build; build+promote under the run root).
3. Each span carries GenAI semantic-convention attributes (gen_ai.system /
   operation / model / usage tokens) + sentinel context (scenario / harness / score).
4. A failed step surfaces as an ERROR span (not a swallowed success) — traced,
   re-raised, recorded.

Egress & secrets posture
------------------------
Zero network / AWS / LLM I/O. No secrets/account ids; the evidence writer scrubs
12-digit ids defensively, like the other scenarios.
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

from sentinel_harness import tracing as T  # noqa: E402

RESULT: dict = {"scenario": "tracing", "steps": []}


def rec(step: str, ok: bool, data: Any) -> None:
    RESULT["steps"].append({"step": step, "ok": bool(ok), "data": data})


_ACCT_RE = re.compile(r"\b\d{12}\b")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ACCT_RE.sub("000000000000", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def run() -> dict:
    """Emit the north-star chain as one trace and build the evidence RESULT."""
    lines: list = []
    tr = T.Tracer("self_iteration_trace", log=lines.append)

    # meta → ops(build) → judge → ops(promote): the full agent-builds-agents chain.
    with tr.span("meta_agent.emit_spec",
                 **T.genai_attributes(operation="chat", model="opus",
                                      scenario="self_iteration", input_tokens=1200,
                                      output_tokens=300)):
        with tr.span("agent_ops.build_harness",
                     **T.genai_attributes(operation="create_harness",
                                          harness_id="alert-triage-v2", scenario="self_iteration")):
            with tr.span("run_evaluation.score",
                         **T.genai_attributes(operation="evaluate", model="sonnet",
                                              scenario="self_iteration", eval_score=0.95,
                                              passed=True)):
                pass
        with tr.span("agent_ops.promote",
                     **T.genai_attributes(operation="create_endpoint",
                                          harness_id="alert-triage-v2", scenario="self_iteration",
                                          hitl_gate="request_promotion_approval")):
            pass

    trace = tr.trace_to_dict()
    rec("emit_trace", len(trace["spans"]) == 4, {
        "trace_id": trace["trace_id"], "span_count": len(trace["spans"]),
        "span_names": [s["span"] for s in trace["spans"]],
    })

    # 1) one trace id across all spans
    one_trace = len({s["trace_id"] for s in trace["spans"]}) == 1
    rec("single_trace_id", one_trace, {"trace_id": trace["trace_id"]})

    # 2) nesting: judge under build; build+promote under meta root
    by_name = {s["span"]: s for s in trace["spans"]}
    root = by_name["meta_agent.emit_spec"]
    nesting_ok = (
        root["parent_span_id"] is None
        and by_name["agent_ops.build_harness"]["parent_span_id"] == root["span_id"]
        and by_name["run_evaluation.score"]["parent_span_id"] == by_name["agent_ops.build_harness"]["span_id"]
        and by_name["agent_ops.promote"]["parent_span_id"] == root["span_id"]
    )
    rec("correct_nesting", nesting_ok, {
        "root": "meta_agent.emit_spec",
        "judge_parent_is_build": by_name["run_evaluation.score"]["parent_span_id"]
        == by_name["agent_ops.build_harness"]["span_id"],
    })

    # 3) GenAI semantic-convention attributes present on the invoke spans
    genai_ok = all(
        by_name[n]["attributes"].get("gen_ai.system") == T.GEN_AI_SYSTEM
        for n in ("meta_agent.emit_spec", "run_evaluation.score")
    )
    rec("genai_attributes", genai_ok, {
        "meta_model": root["attributes"].get("gen_ai.request.model"),
        "judge_score": by_name["run_evaluation.score"]["attributes"].get("sentinel.eval_score"),
    })

    # 4) a failed step surfaces as an ERROR span (separate mini-trace)
    err_tr = T.Tracer("failing_step", log=lambda x: None)
    error_captured = False
    try:
        with err_tr.span("agent_ops.build_harness",
                         **T.genai_attributes(operation="create_harness")):
            raise RuntimeError("simulated build failure")
    except RuntimeError:
        error_captured = True
    err_span = err_tr.spans[0]
    error_ok = (error_captured and err_span.status == T.STATUS_ERROR
                and any(e["event"] == "exception" for e in err_span.events))
    rec("error_span_recorded", error_ok, {
        "status": err_span.status,
        "has_exception_event": bool(err_span.events),
    })

    closed = one_trace and nesting_ok and genai_ok and error_ok and len(trace["spans"]) == 4
    RESULT["trace"] = trace
    RESULT["verdict"] = {
        "trace_id": trace["trace_id"],
        "span_count": len(trace["spans"]),
        "single_trace_id": one_trace,
        "correct_nesting": nesting_ok,
        "genai_attributes": genai_ok,
        "error_span_recorded": error_ok,
        "closed": closed,
        "note": (
            "Code-emitted GenAI spans over the meta→ops→judge→promote chain feed "
            "the aws/spans Transaction-Search source managed online-eval scores. "
            "Offline = structured JSON lines (deterministic); SENTINEL_OTEL=1 also "
            "drives real OpenTelemetry spans into X-Ray."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    run()
    out = os.path.join(REPO_ROOT, "evidence", "tracing_result.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("saved evidence/tracing_result.json  ·  closed:", RESULT["verdict"]["closed"])
    print("trace_id:", RESULT["verdict"]["trace_id"], "· spans:", RESULT["verdict"]["span_count"])
