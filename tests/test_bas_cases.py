"""
Offline unit tests for longrunning/bas-runner/bas_cases.py
==========================================================
``bas_cases`` is the real, deterministic, LLM-free heart of the M3 BAS
detection-replay loop: it generates SIMULATED attack telemetry from a built-in
ATT&CK case library and replays it against a set of Sigma rules via the sibling
``tools/sigma_match`` matcher to enumerate **detection blind spots** (techniques
no rule catches). Because the blind-spot verdict a detection program acts on
depends on this being correct, every branch — case shape, filtering, the
DETECTED vs BLIND-SPOT decision, coverage arithmetic, and the empty-rules edge —
gets regression protection.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS, no LLM. Both ``bas_cases`` and
``sigma_match`` are pure Python by design, so every case runs fully offline with
no mocking.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# bas_cases lives under longrunning/bas-runner/ (a flat scripts tree with a
# hyphen in the dir name, so it is not importable as a package). Load it by
# absolute path, the same way the matcher's own tests load sigma_match.
_MODULE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "longrunning", "bas-runner", "bas_cases.py",
)
_spec = importlib.util.spec_from_file_location("bas_cases", _MODULE_PATH)
bas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bas)


# --------------------------------------------------------------------------- #
# Rules used across the replay tests                                          #
# --------------------------------------------------------------------------- #
# Catches the T1059.001 PowerShell case (Image endswith powershell.exe +
# CommandLine contains -enc). Matches the built-in PowerShell telemetry.
POWERSHELL_RULE = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""

# Catches the T1547.001 run-key persistence case via the registry TargetObject.
RUNKEY_RULE = """
title: Registry Run Key Persistence
id: aaaabbbb-cccc-dddd-eeee-ffff00001111
status: experimental
level: medium
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\\CurrentVersion\\Run'
    condition: selection
"""

# A rule that matches NOTHING in the library (a fabricated field/value).
NEVER_MATCH_RULE = """
title: Never Matches Anything
id: 99999999-0000-0000-0000-000000000000
status: experimental
level: low
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\definitely_not_present_binary.exe'
    condition: selection
"""


# --------------------------------------------------------------------------- #
# generate_cases                                                              #
# --------------------------------------------------------------------------- #
def test_generate_all_cases_are_well_formed():
    cases = bas.generate_cases()
    assert len(cases) == len(bas.BAS_CASES)
    assert len(cases) >= 4  # PowerShell, LSASS, network scan, run-key at minimum

    seen_ids = set()
    for case in cases:
        # shape
        assert set(case) == {"technique_id", "name", "simulated_events"}
        assert isinstance(case["technique_id"], str) and case["technique_id"]
        assert isinstance(case["name"], str) and case["name"]
        assert isinstance(case["simulated_events"], list)
        assert case["simulated_events"], "each case must carry >=1 event"
        for event in case["simulated_events"]:
            assert isinstance(event, dict) and event
            # SIMULATED telemetry uses string field values (Sigma-style fields).
            assert all(isinstance(k, str) for k in event)
        # unique techniques
        assert case["technique_id"] not in seen_ids
        seen_ids.add(case["technique_id"])

    # The techniques named in the task brief are present.
    assert {"T1059.001", "T1003.001", "T1046", "T1547.001"} <= seen_ids


def test_generated_cases_are_defensive_copies():
    # Mutating a returned case must not corrupt the library or later calls.
    first = bas.generate_cases(["T1059.001"])[0]
    first["simulated_events"][0]["CommandLine"] = "TAMPERED"
    fresh = bas.generate_cases(["T1059.001"])[0]
    assert fresh["simulated_events"][0]["CommandLine"] != "TAMPERED"


def test_filter_by_technique_id_subset_and_order():
    cases = bas.generate_cases(["T1547.001", "T1046"])
    assert [c["technique_id"] for c in cases] == ["T1547.001", "T1046"]


def test_filter_is_case_insensitive_and_deduplicates():
    cases = bas.generate_cases(["t1059.001", "T1059.001"])
    assert [c["technique_id"] for c in cases] == ["T1059.001"]


def test_filter_accepts_bare_string():
    cases = bas.generate_cases("T1046")
    assert [c["technique_id"] for c in cases] == ["T1046"]


def test_unknown_technique_id_raises():
    with pytest.raises(ValueError):
        bas.generate_cases(["T9999"])


def test_empty_technique_id_raises():
    with pytest.raises(ValueError):
        bas.generate_cases([""])


# --------------------------------------------------------------------------- #
# replay — DETECTED vs BLIND SPOT                                             #
# --------------------------------------------------------------------------- #
def test_replay_marks_technique_detected_when_matching_rule_present():
    cases = bas.generate_cases(["T1059.001"])
    report = bas.replay(cases, [POWERSHELL_RULE])

    assert report["total_cases"] == 1
    assert report["detected_count"] == 1
    assert report["blind_spots"] == []
    assert report["coverage"] == 1.0

    result = report["results"][0]
    assert result["technique_id"] == "T1059.001"
    assert result["detected"] is True
    # The firing rule is labeled by its Sigma title.
    assert result["matched_rules"] == ["Suspicious PowerShell Encoded Command"]


def test_replay_marks_technique_blind_spot_when_no_rule_matches():
    cases = bas.generate_cases(["T1059.001"])
    report = bas.replay(cases, [NEVER_MATCH_RULE])

    assert report["detected_count"] == 0
    assert report["blind_spots"] == ["T1059.001"]
    assert report["coverage"] == 0.0
    result = report["results"][0]
    assert result["detected"] is False
    assert result["matched_rules"] == []


def test_replay_mixed_detected_and_blind_spot():
    # One rule catches PowerShell only; LSASS + network-scan stay blind spots.
    cases = bas.generate_cases(["T1059.001", "T1003.001", "T1046"])
    report = bas.replay(cases, [POWERSHELL_RULE])

    assert report["total_cases"] == 3
    assert report["detected_count"] == 1
    # blind_spots follow input case order.
    assert report["blind_spots"] == ["T1003.001", "T1046"]
    assert report["coverage"] == pytest.approx(1 / 3)

    by_id = {r["technique_id"]: r for r in report["results"]}
    assert by_id["T1059.001"]["detected"] is True
    assert by_id["T1003.001"]["detected"] is False
    assert by_id["T1046"]["detected"] is False


def test_replay_two_rules_cover_two_techniques():
    cases = bas.generate_cases(["T1059.001", "T1547.001"])
    report = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])

    assert report["detected_count"] == 2
    assert report["blind_spots"] == []
    assert report["coverage"] == 1.0

    by_id = {r["technique_id"]: r for r in report["results"]}
    assert by_id["T1059.001"]["matched_rules"] == [
        "Suspicious PowerShell Encoded Command"
    ]
    assert by_id["T1547.001"]["matched_rules"] == ["Registry Run Key Persistence"]


# --------------------------------------------------------------------------- #
# replay — coverage math + empty-rules edge                                   #
# --------------------------------------------------------------------------- #
def test_empty_rules_makes_everything_a_blind_spot():
    cases = bas.generate_cases()
    report = bas.replay(cases, [])

    assert report["total_cases"] == len(cases)
    assert report["detected_count"] == 0
    assert report["coverage"] == 0.0
    assert report["blind_spots"] == [c["technique_id"] for c in cases]
    assert all(r["detected"] is False for r in report["results"])
    assert all(r["matched_rules"] == [] for r in report["results"])


def test_coverage_ratio_math_full_and_partial():
    cases = bas.generate_cases()  # 4 built-in cases
    # A single PowerShell rule covers exactly one of them.
    partial = bas.replay(cases, [POWERSHELL_RULE])
    assert partial["coverage"] == pytest.approx(
        partial["detected_count"] / partial["total_cases"]
    )
    assert partial["detected_count"] == 1

    # Zero cases -> coverage is defined as 0.0 (no ZeroDivisionError).
    empty = bas.replay([], [POWERSHELL_RULE])
    assert empty["total_cases"] == 0
    assert empty["coverage"] == 0.0
    assert empty["blind_spots"] == []


def test_replay_determinism():
    cases = bas.generate_cases()
    r1 = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])
    r2 = bas.replay(cases, [POWERSHELL_RULE, RUNKEY_RULE])
    assert r1 == r2


# --------------------------------------------------------------------------- #
# replay — accepts parsed-dict rules and surfaces bad rules                   #
# --------------------------------------------------------------------------- #
def test_replay_accepts_parsed_dict_rule():
    dict_rule = {
        "title": "PowerShell Encoded (dict form)",
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    report = bas.replay(bas.generate_cases(["T1059.001"]), [dict_rule])
    assert report["detected_count"] == 1
    assert report["results"][0]["matched_rules"] == ["PowerShell Encoded (dict form)"]


def test_replay_surfaces_matcher_validation_error():
    # A rule with no 'detection' block is rejected by sigma_match; replay must
    # surface that rather than silently marking the technique a blind spot.
    bad_rule = {"title": "no detection block"}
    with pytest.raises(ValueError):
        bas.replay(bas.generate_cases(["T1059.001"]), [bad_rule])


def test_replay_rejects_malformed_case():
    with pytest.raises(ValueError):
        bas.replay([{"name": "missing technique id"}], [POWERSHELL_RULE])
