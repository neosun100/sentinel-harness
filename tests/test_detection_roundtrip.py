"""
Round-trip property tests for the detection-engineering pipeline (round-3 audit).
================================================================================
The load-bearing contract these tools advertise:

    detection_translate emits YARA/Suricata that sigma_yara_lint accepts as
    syntactically valid — for ANY in-contract Sigma input, including adversarial
    ones (metacharacters, negation, aggregators, null/empty values, digit titles).

Round-3's adversarial audit found 17 confirmed defects that all violate that
contract in one of two directions:
  * the TRANSLATOR emitted rules the engine (and our own linter) would reject —
    output-injection via unescaped ``"`` / newline / ``;`` / ``|`` / ``(`` in a
    value or title, or an illegal YARA rule name from a leading-digit title; and
  * the LINTER falsely rejected VALID rules — counting braces inside hex strings /
    regex literals, or splitting Suricata options on a ``;`` inside a quoted value.

This file is the regression harness for every one of those fixes PLUS a
property-style sweep: a matrix of hostile Sigma values is translated and the
emitted YARA/Suricata is fed straight back through the linter, asserting the
round-trip stays clean and that lossy semantics land in ``untranslatable``.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python, fully offline.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_rtundertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tr = _load("detection_translate")
syl = _load("sigma_yara_lint")


def translate(sigma: str, targets=None) -> dict:
    ev = {"sigma": sigma}
    if targets is not None:
        ev["targets"] = targets
    return tr.handler(ev, None)


def lint(rule_type: str, content: str) -> dict:
    return syl.handler({"rule_type": rule_type, "content": content}, None)


def _yaml_dq(s: str) -> str:
    """Encode an arbitrary string as a YAML double-quoted scalar so ANY text
    (newlines, quotes, backslashes, unicode) round-trips through the parser
    intact. This keeps the FIXTURE valid YAML — the tool under test is what must
    then survive the hostile content, not the test's own rule builder."""
    esc = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f'"{esc}"'


def _sigma(title: str, value: str, *, field="CommandLine", modifier="contains",
           condition="selection") -> str:
    """Build a minimal single-selection Sigma rule. ``title`` and ``value`` are
    embedded as YAML double-quoted scalars so arbitrary hostile text is valid YAML
    and reaches the translator verbatim."""
    key = f"{field}|{modifier}" if modifier else field
    return (
        f"title: {_yaml_dq(title)}\n"
        f"logsource:\n    category: proxy\n"
        f"detection:\n"
        f"    selection:\n"
        f"        {key}: {_yaml_dq(value)}\n"
        f"    condition: {condition}\n"
    )


# --------------------------------------------------------------------------- #
# THE property: translate → lint stays clean across hostile values/titles     #
# --------------------------------------------------------------------------- #
HOSTILE_VALUES = [
    'plain-value',
    'a|b|c',                       # Suricata hex-block delimiter
    'a;b;c',                       # Suricata option separator
    'quote " inside',              # closes a quoted literal
    'back\\slash',                 # escape char
    'brace{inside}here',           # YARA brace inside a string
    '${jndi:ldap://x}',            # Log4Shell — braces + colon + slashes
    'tab\tand\nnewline',           # control chars
    'unicode-☠-字',               # non-ASCII
    'paren(in)value',              # parens
    'regex-ish /a}b/ text',        # slashes + brace
    'colon:in:value',
]

HOSTILE_TITLES = [
    'plain title',
    '4625 brute force',            # leading digit → illegal YARA name
    '404 anomaly',
    'PsExec "service" install',    # double-quote in title
    'has; semicolon',              # Suricata msg separator
    'has (paren) title',           # Suricata paren balance
    'has\nnewline title',          # splits a single-line Suricata rule
    'back\\slash title',
    'unicode ☠ title',
]


@pytest.mark.parametrize("value", HOSTILE_VALUES)
def test_roundtrip_hostile_value_lints_clean(value):
    """Any hostile VALUE must produce YARA + Suricata that lint clean."""
    out = translate(_sigma("rt value test", value))
    y = lint("yara", out["translations"]["yara"])
    s = lint("suricata", out["translations"]["suricata"])
    assert y["valid"], (value, "YARA", y["errors"])
    assert s["valid"], (value, "Suricata", s["errors"])


@pytest.mark.parametrize("title", HOSTILE_TITLES)
def test_roundtrip_hostile_title_lints_clean(title):
    """Any hostile TITLE must produce YARA + Suricata that lint clean (the title
    flows into the YARA rule name + meta, and the Suricata msg)."""
    out = translate(_sigma(title, "benign-value"))
    y = lint("yara", out["translations"]["yara"])
    s = lint("suricata", out["translations"]["suricata"])
    assert y["valid"], (title, "YARA", y["errors"])
    assert s["valid"], (title, "Suricata", s["errors"])


def test_roundtrip_full_matrix_value_x_title():
    """Cartesian sweep: every hostile title × hostile value round-trips clean."""
    for title in HOSTILE_TITLES:
        for value in HOSTILE_VALUES:
            out = translate(_sigma(title, value))
            for rt in ("yara", "suricata"):
                r = lint(rt, out["translations"][rt])
                assert r["valid"], (title, value, rt, r["errors"])


# --------------------------------------------------------------------------- #
# translator regressions — one per round-3 confirmed finding                  #
# --------------------------------------------------------------------------- #
def test_negation_condition_is_untranslatable():
    """#1/#15 — 'not' inverts exclusion→inclusion; must be flagged untranslatable."""
    sigma = (
        "title: neg\nlogsource:\n    category: proxy\n"
        "detection:\n"
        "    selection:\n        CommandLine|contains: 'powershell -enc'\n"
        "    filter:\n        CommandLine|contains: 'Trusted'\n"
        "    condition: selection and not filter\n"
    )
    out = translate(sigma)
    assert any("NEGATION" in u or "not" in u.lower() for u in out["untranslatable"])


def test_all_aggregator_is_untranslatable():
    """#3 — '|all' (AND-of-values) is not preserved by the OR skeleton."""
    sigma = (
        "title: agg\nlogsource:\n    category: proxy\n"
        "detection:\n"
        "    selection:\n        CommandLine|contains|all:\n            - foo\n            - bar\n"
        "    condition: selection\n"
    )
    out = translate(sigma)
    assert any("|all" in u and "AND" in u for u in out["untranslatable"])


def test_null_value_is_untranslatable_not_literal_none():
    """#8 — a null Sigma value must NOT become a content match for 'None'."""
    sigma = (
        "title: nul\nlogsource:\n    category: proxy\n"
        "detection:\n    sel:\n        TargetFilename:\n    condition: sel\n"
    )
    out = translate(sigma)
    assert any("null" in u.lower() or "None" in u for u in out["untranslatable"])
    assert '"None"' not in out["translations"]["yara"]
    assert 'content:"None"' not in out["translations"]["suricata"]


def test_empty_value_is_untranslatable():
    """#17 — an empty-string value has no valid literal match."""
    out = translate(_sigma("empty", ""))
    assert any("empty" in u.lower() for u in out["untranslatable"])
    # no empty content literal is emitted
    assert 'content:""' not in out["translations"]["suricata"]
    assert '= ""' not in out["translations"]["yara"]


def test_digit_title_yields_legal_yara_name():
    """#13 — a leading-digit title must not produce an illegal YARA rule name."""
    out = translate(_sigma("4625 brute force", "x"))
    assert out["translations"]["yara"].lstrip().startswith("rule r_")
    assert lint("yara", out["translations"]["yara"])["valid"]


def test_suricata_pipe_value_is_hex_encoded():
    """#6 — a '|' in a value must be hex-encoded (|7C|), not a raw hex-block delim."""
    out = translate(_sigma("pipe", "a|b"))
    assert "|7C|" in out["translations"]["suricata"]
    assert lint("suricata", out["translations"]["suricata"])["valid"]


def test_yara_title_quote_escaped_in_meta():
    """#4/#16 — a double-quote in the title must be escaped in the YARA meta."""
    out = translate(_sigma('PsExec "svc" install', "x"))
    y = out["translations"]["yara"]
    assert '\\"svc\\"' in y
    assert lint("yara", y)["valid"]


def test_value_newline_does_not_break_yara():
    """#5 — a newline in a value becomes a \\n escape, not a raw line break, so the
    string literal stays on one line and the rule lints clean."""
    out = translate(_sigma("nl", "line1\nline2"))
    y = out["translations"]["yara"]
    # the emitted string literal carries the escaped '\n' (two chars), never a raw LF
    string_line = next(ln for ln in y.splitlines() if "$s1 =" in ln)
    assert "\\n" in string_line
    assert "line1" in string_line and "line2" in string_line  # both on ONE line
    assert lint("yara", y)["valid"]


# --------------------------------------------------------------------------- #
# linter regressions — false-rejection fixes                                  #
# --------------------------------------------------------------------------- #
YARA_HEX = "rule R {\n strings:\n  $h = { E2 34 56 }\n condition:\n  $h\n}\n"
YARA_REGEX_BRACE = "rule R {\n strings:\n  $re = /a}b{c/\n condition:\n  $re\n}\n"
YARA_REAL_IMBALANCE = 'rule R {\n strings:\n  $a = "x"\n condition: $a\n'
YARA_MISSING_COND = 'rule R {\n strings:\n  $a = "x"\n}\n'


def test_yara_hex_string_lints_clean():
    """#2 — a hex-string '{ .. }' must not truncate body / fake an imbalance."""
    assert lint("yara", YARA_HEX)["valid"]


def test_yara_regex_literal_brace_lints_clean():
    """#11 — a brace inside a /regex/ literal must not count as structural."""
    assert lint("yara", YARA_REGEX_BRACE)["valid"]


def test_yara_genuine_imbalance_still_caught():
    r = lint("yara", YARA_REAL_IMBALANCE)
    assert not r["valid"] and any("unbalanced" in e for e in r["errors"])


def test_yara_genuine_missing_condition_still_caught():
    r = lint("yara", YARA_MISSING_COND)
    assert not r["valid"] and any("condition" in e for e in r["errors"])


def test_suricata_semicolon_in_msg_does_not_fake_options():
    """#9 — a ';' inside a quoted msg must not fabricate sid/rev options."""
    rule = 'alert tcp any any -> any any (msg:"foo; sid:1; rev:1"; content:"x";)'
    r = lint("suricata", rule)
    assert not r["valid"]
    assert any("sid" in e for e in r["errors"]) and any("rev" in e for e in r["errors"])


def test_suricata_sid_token_in_msg_does_not_reject_valid_rule():
    """#10 — 'sid:' inside a quoted msg must not shadow the real numeric sid."""
    rule = 'alert tcp any any -> any any (msg:"blocked sid:evil"; sid:12345; rev:1; classtype:x;)'
    assert lint("suricata", rule)["valid"]


def test_suricata_paren_in_msg_does_not_reject_valid_rule():
    """#12/#14 — a '(' inside a quoted msg must not trip paren balance."""
    rule = 'alert tcp any any -> any any (msg:"smiley :-("; sid:1; rev:1; classtype:x;)'
    assert lint("suricata", rule)["valid"]


def test_suricata_genuine_unbalanced_paren_still_caught():
    rule = 'alert tcp any any -> any any (msg:"x"; sid:1; rev:1;'
    r = lint("suricata", rule)
    assert not r["valid"]


def test_suricata_nonnumeric_sid_still_caught():
    rule = 'alert tcp any any -> any any (msg:"x"; content:"y"; sid:notanumber; rev:1;)'
    r = lint("suricata", rule)
    assert not r["valid"] and any("numeric" in e for e in r["errors"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
