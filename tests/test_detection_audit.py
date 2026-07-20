"""
Offline unit tests for the detection_audit aggregator tool.
================================================================================
``tools/detection_audit`` composes sigma_yara_lint + detection_dedup +
detection_coverage into one governance report + a transparent health score.

Properties pinned here:
  * COMPOSITION FIDELITY — the aggregate totals/sub-reports match what the three
    tools produce individually (the aggregator adds no new judgement, so it must
    not silently drop or alter a sub-result).
  * HEALTH SCORE is deterministic, saturating, and clamped to [0, 100].
  * FINDINGS are worst-first and only fire on real defects.
  * Robustness — a structurally-broken or non-dict rule is surfaced (lint error /
    not_analyzed), never a crash.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_auditundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


da = _load("detection_audit")
dd = _load("detection_dedup")
cov = _load("detection_coverage")
lint = _load("sigma_yara_lint")


def audit(rules, techniques=None) -> dict:
    ev = {"rules": rules}
    if techniques is not None:
        ev["techniques"] = techniques
    return da.handler(ev, None)


def _rule(rid, tags=None, value="-EncodedCommand", *, product="windows",
          category="ps_script", full=True) -> str:
    tagblock = ""
    if tags:
        tagblock = "tags:\n" + "".join(f"    - {t}\n" for t in tags)
    if full:
        return (
            f"title: {rid}\nid: {rid}\nstatus: experimental\nlevel: high\n"
            f"logsource:\n    product: {product}\n    category: {category}\n"
            f"{tagblock}"
            f"falsepositives:\n    - legitimate usage\n"
            f"detection:\n    selection:\n"
            f"        Image|endswith: '\\\\powershell.exe'\n"
            f"        CommandLine|contains: '{value}'\n"
            f"        ParentImage|endswith: '\\\\explorer.exe'\n"
            f"    condition: selection\n"
        )
    # a structurally broken rule (no logsource, no condition)
    return f"title: {rid}\ndetection:\n    selection:\n        x: y\n"


# --------------------------------------------------------------------------- #
# happy path + composition fidelity                                           #
# --------------------------------------------------------------------------- #
def test_clean_library_scores_100():
    rules = [_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1190"], value="-decode")]
    out = audit(rules, ["T1059", "T1190"])
    assert out["ok"] and out["health_score"] == 100
    assert out["totals"]["invalid_rules"] == 0
    assert out["totals"]["duplicate_pairs"] == 0
    assert out["totals"]["uncovered_techniques"] == 0
    assert out["findings"] == []


def test_totals_match_individual_tools():
    rules = [_rule("r1", ["attack.t1059"]), _rule("r2", ["attack.t1059"])]
    techniques = ["T1059", "T1046"]
    out = audit(rules, techniques)
    # dedup run independently
    dd_res = dd.handler({"rules": rules}, None)
    cov_res = cov.handler({"rules": rules, "techniques": techniques}, None)
    assert out["totals"]["duplicate_pairs"] == len(dd_res["duplicates"])
    assert out["totals"]["uncovered_techniques"] == len(cov_res["uncovered"])
    assert out["dedup"]["duplicates"] == dd_res["duplicates"]
    assert out["coverage"]["uncovered"] == cov_res["uncovered"]


def test_invalid_rule_is_surfaced_in_lint_and_findings():
    out = audit([_rule("broken", full=False)])
    assert out["totals"]["invalid_rules"] == 1
    assert out["lint"]["invalid"][0]["rule"].startswith("broken")
    assert any(f.startswith("[critical]") for f in out["findings"])


def test_duplicate_detected_and_scored():
    out = audit([_rule("a", ["attack.t1059"]), _rule("b", ["attack.t1059"])])
    assert out["totals"]["duplicate_pairs"] == 1
    assert any("duplicate rules" in f for f in out["findings"])
    assert out["health_score"] < 100


def test_uncovered_only_penalized_when_targets_given():
    rules = [_rule("r1", ["attack.t1059"])]
    # no techniques → coverage is inventory-only, uncovered not penalized
    no_target = audit(rules)
    assert no_target["coverage"] is None
    assert no_target["totals"]["uncovered_techniques"] == 0
    # with a target it does not cover → penalized
    with_target = audit(rules, ["T1190"])
    assert with_target["totals"]["uncovered_techniques"] == 1
    assert with_target["health_score"] < no_target["health_score"]


# --------------------------------------------------------------------------- #
# health score properties                                                     #
# --------------------------------------------------------------------------- #
def test_health_score_bounded_and_deterministic():
    rules = [_rule("broken", full=False)] * 20  # many invalid
    out1 = audit(rules, ["T1059", "T1190", "T1046", "T1195"])
    out2 = audit(rules, ["T1059", "T1190", "T1046", "T1195"])
    assert 0 <= out1["health_score"] <= 100
    assert out1["health_score"] == out2["health_score"]  # deterministic


def test_score_saturates_not_negative():
    # a pathologically bad library must clamp within [0, 100], never go negative,
    # even when every defect class is maxed (invalid + uncovered + dup + untagged).
    dups = [_rule("dup", ["attack.t1059"]) for _ in range(10)]  # many identical → dup pairs
    broken = [_rule(f"broken{i}", full=False) for i in range(50)]
    out = audit(dups + broken, [f"T{1000+i}" for i in range(30)])
    assert out["health_score"] == 0  # all five classes saturate → clamps to 0


def test_findings_are_worst_first():
    rules = [_rule("broken", full=False),
             _rule("a", ["attack.t1059"]), _rule("b", ["attack.t1059"])]
    out = audit(rules, ["T1059", "T1190"])
    # critical (invalid) precedes high (uncovered) precedes medium (dup)
    tags = [f.split("]")[0] + "]" for f in out["findings"]]
    order = {"[critical]": 0, "[high]": 1, "[medium]": 2, "[low]": 3}
    ranks = [order[t] for t in tags]
    assert ranks == sorted(ranks)


# --------------------------------------------------------------------------- #
# robustness + validation                                                     #
# --------------------------------------------------------------------------- #
def test_parsed_dict_rules_accepted():
    r = {"title": "r1", "id": "r1", "logsource": {"product": "windows"},
         "tags": ["attack.t1059"],
         "detection": {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}}
    out = audit([r], ["T1059"])
    assert out["ok"] and out["totals"]["invalid_rules"] == 0
    assert out["coverage"]["covered"][0]["rules"] == ["r1"]


def test_non_dict_non_str_rule_does_not_crash():
    out = audit([12345])
    assert out["ok"] is True
    # surfaced as an invalid (unlintable) rule, never a crash
    assert out["totals"]["invalid_rules"] >= 1


def test_empty_rules_is_validation_error():
    r = da.handler({"rules": []}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_non_list_techniques_is_validation_error():
    r = da.handler({"rules": [_rule("r1", ["attack.t1059"])], "techniques": "T1059"}, None)
    assert r["ok"] is False and r["error"] == "validation_error"


def test_single_rule_key_wrapped():
    r = da.handler({"rule": _rule("solo", ["attack.t1059"])}, None)
    assert r["ok"] is True and r["rule_count"] == 1


def test_summary_reports_health_and_counts():
    out = audit([_rule("broken", full=False)], ["T1059"])
    assert "health" in out["summary"] and "invalid" in out["summary"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
