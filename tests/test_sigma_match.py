"""
Offline unit tests for the sigma_match tool handler
===================================================
``tools/sigma_match`` is the *real, deterministic, LLM-free* core of the M3
BAS detection-replay loop: it decides whether a log EVENT is caught by a Sigma
RULE (the sibling ``sigma_yara_lint`` only lints rule syntax; it never matches
events). Because blind-spot enumeration depends entirely on this matcher being
correct, its every branch — each modifier, each condition combinator, and the
missing-field / malformed-input edges — needs regression protection.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS. The tool is pure Python by
design, so every case runs fully offline with no mocking.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# The tool handlers live under tools/<name>/handler.py — a scripts tree, not an
# installed package. Load the module directly by path so the tests don't depend
# on tools/ being importable.
_HANDLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "sigma_match", "handler.py",
)
_spec = importlib.util.spec_from_file_location("sigma_match_handler", _HANDLER_PATH)
sm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sm)


def match(rule, log_event) -> dict:
    return sm.handler({"rule": rule, "log_event": log_event}, None)


# --------------------------------------------------------------------------- #
# A rule that MATCHES an event, and one that does NOT                          #
# --------------------------------------------------------------------------- #
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


def test_rule_matches_event():
    ev = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
    }
    r = match(POWERSHELL_RULE, ev)
    assert r["ok"] is True
    assert r["matched"] is True
    assert r["matched_selections"] == ["selection"]
    assert r["condition"] == "selection"


def test_rule_does_not_match_event():
    # Same rule, but CommandLine lacks '-enc' so the selection cannot fire.
    ev = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -File setup.ps1",
    }
    r = match(POWERSHELL_RULE, ev)
    assert r["ok"] is True
    assert r["matched"] is False
    assert r["matched_selections"] == []


def test_rule_accepts_already_parsed_dict():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4688},
            "condition": "selection",
        },
    }
    assert match(rule, {"EventID": 4688})["matched"] is True
    assert match(rule, {"EventID": 4624})["matched"] is False


# --------------------------------------------------------------------------- #
# Each value modifier                                                         #
# --------------------------------------------------------------------------- #
def _rule_with_selection(sel_body: str) -> str:
    return f"""
title: x
logsource:
    product: windows
detection:
    selection:
{sel_body}
    condition: selection
"""


def test_modifier_contains():
    rule = _rule_with_selection("        CommandLine|contains: 'mimikatz'")
    assert match(rule, {"CommandLine": "run MIMIKATZ.exe now"})["matched"] is True
    assert match(rule, {"CommandLine": "run notepad"})["matched"] is False


def test_modifier_startswith():
    # Use a forward-slash path so backslash escaping doesn't muddy the fixture;
    # the modifier logic is identical regardless of separator.
    rule = _rule_with_selection("        Image|startswith: '/usr/tmp'")
    assert match(rule, {"Image": "/USR/TMP/evil.bin"})["matched"] is True
    assert match(rule, {"Image": "/usr/bin/evil.bin"})["matched"] is False


def test_modifier_endswith():
    rule = _rule_with_selection("        Image|endswith: '.exe'")
    assert match(rule, {"Image": "C:\\a\\PAYLOAD.EXE"})["matched"] is True
    assert match(rule, {"Image": "C:\\a\\payload.dll"})["matched"] is False


def test_modifier_regex():
    rule = _rule_with_selection("        CommandLine|re: 'iex\\s*\\('")
    assert match(rule, {"CommandLine": "IEX ( new-object net.webclient )"})["matched"] is True
    assert match(rule, {"CommandLine": "echo hello"})["matched"] is False


def test_modifier_all_list_and():
    # |contains|all: every listed substring must be present (AND).
    rule = _rule_with_selection(
        "        CommandLine|contains|all:\n"
        "            - '-enc'\n"
        "            - 'hidden'\n"
    )
    assert match(rule, {"CommandLine": "pwsh -enc AAAA -windowstyle hidden"})["matched"] is True
    # Missing 'hidden' -> all() fails.
    assert match(rule, {"CommandLine": "pwsh -enc AAAA"})["matched"] is False


def test_plain_equality_case_insensitive():
    rule = _rule_with_selection("        User: 'Administrator'")
    assert match(rule, {"User": "administrator"})["matched"] is True
    assert match(rule, {"User": "guest"})["matched"] is False


def test_list_of_values_is_or():
    # A plain list value = OR (any element matches).
    rule = _rule_with_selection(
        "        Image|endswith:\n"
        "            - 'cmd.exe'\n"
        "            - 'powershell.exe'\n"
    )
    assert match(rule, {"Image": "C:/w/CMD.EXE"})["matched"] is True
    assert match(rule, {"Image": "C:/w/powershell.exe"})["matched"] is True
    assert match(rule, {"Image": "C:/w/explorer.exe"})["matched"] is False


# --------------------------------------------------------------------------- #
# Condition combinators                                                       #
# --------------------------------------------------------------------------- #
MULTI_SELECTION_RULE = """
title: x
logsource:
    product: windows
detection:
    selection_a:
        EventID: 4688
    selection_b:
        User: 'admin'
    condition: {cond}
"""


def _multi(cond: str, log_event) -> dict:
    return match(MULTI_SELECTION_RULE.format(cond=cond), log_event)


def test_condition_1_of_them():
    # Only selection_a fires.
    r = _multi("1 of them", {"EventID": 4688, "User": "guest"})
    assert r["matched"] is True
    assert r["matched_selections"] == ["selection_a"]
    # Neither fires.
    assert _multi("1 of them", {"EventID": 1, "User": "guest"})["matched"] is False


def test_condition_all_of_them():
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("all of them", both)["matched"] is True
    # Only one fires -> all of them is False.
    assert _multi("all of them", {"EventID": 4688, "User": "guest"})["matched"] is False


def test_condition_wildcard_1_of_prefix():
    # '1 of selection_*' resolves both selections by prefix.
    r = _multi("1 of selection_*", {"EventID": 4688, "User": "guest"})
    assert r["matched"] is True
    assert _multi("1 of selection_*", {"EventID": 0, "User": "guest"})["matched"] is False


def test_condition_all_of_wildcard_prefix():
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("all of selection_*", both)["matched"] is True
    assert _multi("all of selection_*", {"EventID": 4688, "User": "x"})["matched"] is False


def test_condition_and_or_combinators():
    both = {"EventID": 4688, "User": "admin"}
    only_a = {"EventID": 4688, "User": "guest"}
    assert _multi("selection_a and selection_b", both)["matched"] is True
    assert _multi("selection_a and selection_b", only_a)["matched"] is False
    assert _multi("selection_a or selection_b", only_a)["matched"] is True


def test_condition_not_combinator():
    # 'selection_a and not selection_b' — a fires, b must NOT.
    only_a = {"EventID": 4688, "User": "guest"}
    both = {"EventID": 4688, "User": "admin"}
    assert _multi("selection_a and not selection_b", only_a)["matched"] is True
    assert _multi("selection_a and not selection_b", both)["matched"] is False


def test_condition_parentheses_precedence():
    # (a or b) and not b  — with only b firing, inner is True but 'not b' kills it.
    only_b = {"EventID": 0, "User": "admin"}
    assert _multi("(selection_a or selection_b) and not selection_b", only_b)["matched"] is False
    only_a = {"EventID": 4688, "User": "guest"}
    assert _multi("(selection_a or selection_b) and not selection_b", only_a)["matched"] is True


# --------------------------------------------------------------------------- #
# Missing field — no match, no crash                                          #
# --------------------------------------------------------------------------- #
def test_missing_field_does_not_match_and_does_not_crash():
    rule = _rule_with_selection("        CommandLine|contains: '-enc'")
    # log_event has no 'CommandLine' key at all.
    r = match(rule, {"Image": "powershell.exe"})
    assert r["ok"] is True
    assert r["matched"] is False
    assert r["matched_selections"] == []


def test_partial_selection_absent_key_fails_the_and():
    # selection needs BOTH keys; one key's field is absent -> selection fails.
    rule = _rule_with_selection(
        "        Image|endswith: '\\\\powershell.exe'\n"
        "        CommandLine|contains: '-enc'"
    )
    r = match(rule, {"Image": "x\\powershell.exe"})  # no CommandLine
    assert r["matched"] is False


# --------------------------------------------------------------------------- #
# List-of-maps selection (implicit OR across sub-maps)                        #
# --------------------------------------------------------------------------- #
def test_selection_list_of_maps_is_or():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": [
                {"Image|endswith": "\\cmd.exe"},
                {"Image|endswith": "\\powershell.exe"},
            ],
            "condition": "selection",
        },
    }
    assert match(rule, {"Image": "a\\CMD.EXE"})["matched"] is True
    assert match(rule, {"Image": "a\\explorer.exe"})["matched"] is False


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_determinism_same_input_same_output():
    ev = {"Image": "x\\powershell.exe", "CommandLine": "p -enc AA"}
    a = match(POWERSHELL_RULE, ev)
    b = match(POWERSHELL_RULE, ev)
    assert a == b


# --------------------------------------------------------------------------- #
# Malformed input -> validation_error                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("event", [
    {},                                                    # nothing
    {"rule": POWERSHELL_RULE},                             # no log_event
    {"rule": POWERSHELL_RULE, "log_event": "not-a-dict"},  # bad log_event type
    {"rule": 123, "log_event": {}},                        # rule wrong type
    {"rule": "   ", "log_event": {}},                      # empty rule string
    {"rule": "title: x\nlogsource: {}", "log_event": {}},  # no detection block
])
def test_malformed_input_is_validation_error(event):
    r = sm.handler(event, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_detection_without_condition_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}},  # no 'condition'
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "condition" in r["message"]


def test_detection_without_selection_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {"condition": "selection"},  # no selection defined
    }
    r = sm.handler({"rule": rule, "log_event": {}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


def test_condition_referencing_undefined_selection_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_a": {"EventID": 1},
            "condition": "selection_a and ghost",  # 'ghost' undefined
        },
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"
    assert "undefined selection" in r["message"]


def test_malformed_condition_unbalanced_parens_is_validation_error():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 1},
            "condition": "(selection and",  # unbalanced / dangling
        },
    }
    r = sm.handler({"rule": rule, "log_event": {"EventID": 1}}, None)
    assert r["ok"] is False
    assert r["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# List-of-conditions is OR-joined                                             #
# --------------------------------------------------------------------------- #
def test_list_condition_is_or_joined():
    rule = {
        "title": "x",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_a": {"EventID": 4688},
            "selection_b": {"User": "admin"},
            "condition": ["selection_a", "selection_b"],  # list => OR
        },
    }
    # Only selection_b fires; OR-join still matches.
    r = sm.handler({"rule": rule, "log_event": {"EventID": 0, "User": "admin"}}, None)
    assert r["matched"] is True
    assert r["condition"] == "(selection_a) or (selection_b)"
