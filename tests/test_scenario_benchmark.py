"""
Offline test for scenarios/scenario_benchmark.py — the procurement benchmark.

Runs the scenario's ``run()`` in-process (zero AWS/network/clock) and asserts the
evidence contract: every step ``ok``, the model-cost invariant holds, the managed
mode wins the default workload, ``verdict.closed`` is true, and the markdown
carries the headline. Mirrors the other ``test_scenario_*`` offline checks.
"""
from __future__ import annotations

import importlib.util
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH = os.path.join(REPO_ROOT, "scenarios", "scenario_benchmark.py")
_spec = importlib.util.spec_from_file_location("scenario_benchmark_undertest", _PATH)
scenario = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scenario)


def _fresh_result():
    # scenario.RESULT is module-global; reset it so repeated test runs are clean.
    scenario.RESULT.clear()
    scenario.RESULT.update({"scenario": "benchmark", "steps": []})


def test_scenario_runs_and_closes():
    _fresh_result()
    result = scenario.run()
    assert result["verdict"]["closed"] is True
    assert all(step["ok"] for step in result["steps"])


def test_model_cost_invariant_step_present():
    _fresh_result()
    result = scenario.run()
    steps = {s["step"]: s for s in result["steps"]}
    assert steps["model_cost_identical_across_modes"]["ok"] is True
    assert len(steps["run_benchmark"]["data"]["modes"]) >= 3


def test_managed_mode_cheapest_on_default_workload():
    _fresh_result()
    result = scenario.run()
    assert result["verdict"]["cheapest_mode"] == "agentcore_harness"
    assert result["verdict"]["savings_vs_baseline_pct"] > 0


def test_markdown_and_scrub_present():
    _fresh_result()
    result = scenario.run()
    assert "Headline" in result["markdown"]
    # _scrub must be a no-op on clean data but never crash
    scrubbed = scenario._scrub(result)
    assert scrubbed["scenario"] == "benchmark"


def test_scrub_masks_account_ids():
    assert scenario._scrub("arn:aws:iam::123456789012:role/x") == \
        "arn:aws:iam::000000000000:role/x"
    assert scenario._scrub({"a": ["123456789012"]}) == {"a": ["000000000000"]}
