"""
Offline test for scenarios/scenario_tracing.py.

Runs the scenario in-process (zero AWS/network/clock) and asserts the trace
contract: one trace_id, correct meta→ops→judge→promote nesting, GenAI attributes,
a recorded ERROR span, verdict.closed true.
"""
from __future__ import annotations

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_tracing.py")
_spec = importlib.util.spec_from_file_location("scenario_tracing_undertest", _PATH)
scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scenario)


def _fresh():
    scenario.RESULT.clear()
    scenario.RESULT.update({"scenario": "tracing", "steps": []})


def test_scenario_closes():
    _fresh()
    r = scenario.run()
    assert r["verdict"]["closed"] is True
    assert all(s["ok"] for s in r["steps"])


def test_single_trace_four_spans():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["span_count"] == 4
    assert v["single_trace_id"] is True


def test_nesting_and_genai_and_error_recorded():
    _fresh()
    v = scenario.run()["verdict"]
    assert v["correct_nesting"] is True
    assert v["genai_attributes"] is True
    assert v["error_span_recorded"] is True


def test_trace_present_in_result():
    _fresh()
    r = scenario.run()
    assert r["trace"]["trace_id"] == r["verdict"]["trace_id"]
    assert len(r["trace"]["spans"]) == 4
