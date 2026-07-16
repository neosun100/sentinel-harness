"""
Offline unit tests for the detection_baseline tool.
================================================================================
``tools/detection_baseline`` turns a ``detection_audit`` result into a regression
gate: ``snapshot`` reduces it to a compact comparable baseline; ``compare`` diffs a
current audit against a baseline and flags a regression.

Pinned here: the compact-snapshot shape, the regression conditions (score drop AND
set-growth — the churn case a scalar hides), improvements never fail, the
allow_score_drop tolerance, determinism, and validation.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_blundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("detection_baseline")


def _audit(*, score, invalid=(), uncovered=(), duplicates=(), rule_count=3):
    """Build a minimal detection_audit-shaped result."""
    return {
        "ok": True,
        "health_score": score,
        "rule_count": rule_count,
        "totals": {"invalid_rules": len(invalid), "duplicate_pairs": len(duplicates),
                   "uncovered_techniques": len(uncovered), "subsumptions": 0,
                   "overlaps": 0, "untagged_rules": 0, "invalid_tags": 0,
                   "rules_with_warnings": 0},
        "lint": {"invalid": [{"rule": r, "errors": ["e"]} for r in invalid], "warnings": []},
        "dedup": {"duplicates": [{"a": a, "b": b} for (a, b) in duplicates]},
        "coverage": {"uncovered": list(uncovered)},
    }


def snapshot(audit):
    return bl.handler({"mode": "snapshot", "audit": audit}, None)


def compare(audit, baseline, allow=0):
    return bl.handler({"mode": "compare", "audit": audit, "baseline": baseline,
                       "allow_score_drop": allow}, None)


# --------------------------------------------------------------------------- #
# snapshot                                                                    #
# --------------------------------------------------------------------------- #
def test_snapshot_compact_shape():
    snap = snapshot(_audit(score=90, uncovered=["T1190"]))
    assert snap["ok"] and snap["mode"] == "snapshot"
    b = snap["baseline"]
    assert b["health_score"] == 90
    assert b["uncovered_techniques"] == ["T1190"]
    assert set(b) >= {"health_score", "rule_count", "totals", "invalid_rules",
                      "uncovered_techniques", "duplicate_pairs"}


def test_snapshot_canonicalizes_duplicate_pairs():
    # a pair (b,a) and (a,b) must normalize to the same "a|b" key
    snap = snapshot(_audit(score=80, duplicates=[("r2", "r1")]))
    assert snap["baseline"]["duplicate_pairs"] == ["r1|r2"]


# --------------------------------------------------------------------------- #
# compare — no regression                                                     #
# --------------------------------------------------------------------------- #
def test_identical_no_regression():
    a = _audit(score=90, uncovered=["T1190"])
    base = snapshot(a)["baseline"]
    r = compare(a, base)
    assert r["regressed"] is False and r["health_delta"] == 0


def test_improvement_never_fails_and_is_reported():
    base = snapshot(_audit(score=90, uncovered=["T1190"]))["baseline"]
    better = _audit(score=100, uncovered=[])
    r = compare(better, base)
    assert r["regressed"] is False
    assert any("improved" in i for i in r["improvements"])
    assert any("resolved" in i for i in r["improvements"])


# --------------------------------------------------------------------------- #
# compare — regressions                                                       #
# --------------------------------------------------------------------------- #
def test_score_drop_regresses():
    base = snapshot(_audit(score=90))["baseline"]
    r = compare(_audit(score=70), base)
    assert r["regressed"] is True
    assert r["health_delta"] == -20
    assert any("dropped" in x for x in r["reasons"])


def test_new_invalid_rule_regresses_even_at_flat_score():
    """The load-bearing property: a NEW invalid rule is a regression even when the
    health score is unchanged (churn a scalar gate would miss)."""
    base = snapshot(_audit(score=90))["baseline"]
    churn = _audit(score=90, invalid=["r-x"])
    # force the score equal so ONLY the set-diff can trigger the regression
    churn["health_score"] = 90
    r = compare(churn, base)
    assert r["regressed"] is True
    assert any("new invalid rule" in x for x in r["reasons"])


def test_new_uncovered_technique_regresses():
    base = snapshot(_audit(score=90, uncovered=["T1190"]))["baseline"]
    r = compare(_audit(score=90, uncovered=["T1190", "T1046"]), base)
    assert r["regressed"] is True
    assert any("T1046" in x for x in r["reasons"])


def test_new_duplicate_pair_regresses():
    base = snapshot(_audit(score=90))["baseline"]
    r = compare(_audit(score=90, duplicates=[("r1", "r2")]), base)
    assert r["regressed"] is True
    assert any("duplicate pair" in x for x in r["reasons"])


def test_allow_score_drop_tolerance():
    base = snapshot(_audit(score=90))["baseline"]
    # a 2-point drop within a 5-point tolerance is NOT a regression
    assert compare(_audit(score=88), base, allow=5)["regressed"] is False
    # a 10-point drop exceeds it
    assert compare(_audit(score=80), base, allow=5)["regressed"] is True


# --------------------------------------------------------------------------- #
# determinism + validation                                                    #
# --------------------------------------------------------------------------- #
def test_deterministic():
    a = _audit(score=90, uncovered=["T1190", "T1046"], invalid=["r-x"])
    s1 = json.dumps(snapshot(a), sort_keys=True)
    s2 = json.dumps(snapshot(a), sort_keys=True)
    assert s1 == s2


def test_bad_mode_is_validation_error():
    r = bl.handler({"mode": "nope", "audit": _audit(score=90)}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_ok_audit_rejected():
    r = bl.handler({"mode": "snapshot", "audit": {"ok": False}}, None)
    assert r["ok"] is False


def test_compare_without_baseline_rejected():
    r = bl.handler({"mode": "compare", "audit": _audit(score=90)}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_bad_allow_score_drop_rejected():
    base = snapshot(_audit(score=90))["baseline"]
    r = bl.handler({"mode": "compare", "audit": _audit(score=90), "baseline": base,
                    "allow_score_drop": "lots"}, None)
    assert r["ok"] is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
