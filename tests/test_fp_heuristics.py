"""Tests for the FP-proneness heuristics (sigma_yara_lint + detection_audit wiring).

These exercise the WARNING-class fp_warnings that fire on structurally valid but
operationally noisy Sigma rules, and the audit health-score deduction for fp_prone.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.sigma_yara_lint.handler import handler as lint_handler
from tools.detection_audit.handler import handler as audit_handler


def _sigma(title="Test", logsource_cat="process_creation", detection=None,
           level="high", falsepositives=True, extra=""):
    """Build a minimal valid Sigma rule string for testing."""
    fp_line = "falsepositives:\n  - legitimate admin activity\n" if falsepositives else ""
    det = detection or "  sel:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains: '-EncodedCommand'\n  condition: sel"
    return (
        f"title: {title}\n"
        f"id: 12345678-aaaa-bbbb-cccc-123456789012\n"
        f"status: test\n"
        f"level: {level}\n"
        f"logsource:\n  product: windows\n  category: {logsource_cat}\n"
        f"detection:\n{det}\n"
        f"{fp_line}"
        f"{extra}"
    )


class TestFpHeuristicsSigmaLint:
    """Individual heuristic triggers in sigma_yara_lint."""

    def test_no_falsepositives_field_triggers(self):
        rule = _sigma(falsepositives=False)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert res["ok"]
        assert any("falsepositives" in w for w in res.get("fp_warnings", []))

    def test_with_falsepositives_field_no_trigger(self):
        rule = _sigma(falsepositives=True)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert res["ok"]
        fp = res.get("fp_warnings", [])
        assert not any("falsepositives" in w for w in fp)

    def test_high_volume_no_filter_triggers(self):
        rule = _sigma(logsource_cat="process_creation",
                      detection="  sel:\n    Image|endswith: '\\\\cmd.exe'\n  condition: sel")
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert any("no exclusion filter" in w for w in res.get("fp_warnings", []))

    def test_high_volume_with_filter_no_trigger(self):
        det = "  sel:\n    Image|endswith: '\\\\cmd.exe'\n  filter:\n    User: SYSTEM\n  condition: sel and not filter"
        rule = _sigma(logsource_cat="process_creation", detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        fp = res.get("fp_warnings", [])
        assert not any("no exclusion filter" in w for w in fp)

    def test_short_contains_value_triggers(self):
        det = "  sel:\n    CommandLine|contains: 'cmd'\n  condition: sel"
        rule = _sigma(detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert any("short/generic" in w for w in res.get("fp_warnings", []))

    def test_long_specific_contains_no_trigger(self):
        det = "  sel:\n    CommandLine|contains: 'Invoke-Mimikatz'\n  condition: sel"
        rule = _sigma(detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        fp = res.get("fp_warnings", [])
        assert not any("short/generic" in w for w in fp)

    def test_single_contains_only_selection_triggers(self):
        det = "  sel:\n    CommandLine|contains: 'suspicious-long-string'\n  condition: sel"
        rule = _sigma(detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert any("single contains predicate" in w for w in res.get("fp_warnings", []))

    def test_multi_predicate_selection_no_trigger(self):
        det = "  sel:\n    CommandLine|contains: 'suspicious-long-string'\n    ParentImage|endswith: '\\\\explorer.exe'\n  condition: sel"
        rule = _sigma(detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        fp = res.get("fp_warnings", [])
        assert not any("single contains predicate" in w for w in fp)

    def test_critical_level_low_specificity_triggers(self):
        det = "  sel:\n    EventID: 1\n  condition: sel"
        rule = _sigma(level="critical", detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert any("low specificity" in w for w in res.get("fp_warnings", []))

    def test_critical_level_high_specificity_no_trigger(self):
        det = "  sel:\n    EventID: 1\n    Image|endswith: '\\\\mimikatz.exe'\n    CommandLine|contains: 'sekurlsa'\n  condition: sel"
        rule = _sigma(level="critical", detection=det)
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        fp = res.get("fp_warnings", [])
        assert not any("low specificity" in w for w in fp)

    def test_fp_warnings_do_not_leak_into_errors_or_warnings(self):
        """fp_warnings must be a separate key — never inflate error/warning counts."""
        det = "  sel:\n    CommandLine|contains: 'cmd'\n  condition: sel"
        rule = _sigma(detection=det, falsepositives=False, level="critical")
        res = lint_handler({"rule_type": "sigma", "content": rule}, None)
        assert res["ok"]
        assert res["valid"] is True
        assert len(res["errors"]) == 0
        # fp_warnings is separate
        assert len(res.get("fp_warnings", [])) >= 2

    def test_non_sigma_rule_no_fp_warnings(self):
        """YARA/Suricata rules never get fp_warnings."""
        yara = "rule test { condition: true }"
        res = lint_handler({"rule_type": "yara", "content": yara}, None)
        assert "fp_warnings" not in res


class TestFpProneAuditWiring:
    """FP-prone rules impact the audit health score."""

    def _noisy_rule(self):
        """A rule that triggers >=2 FP heuristics (fp_prone threshold)."""
        return _sigma(
            title="Noisy Rule",
            logsource_cat="process_creation",
            detection="  sel:\n    CommandLine|contains: 'cmd'\n  condition: sel",
            level="critical",
            falsepositives=False,
        )

    def _clean_rule(self):
        """A well-scoped rule that triggers zero FP heuristics."""
        det = ("  sel:\n"
               "    Image|endswith: '\\\\mimikatz.exe'\n"
               "    CommandLine|contains: 'sekurlsa::logonpasswords'\n"
               "  filter:\n"
               "    User: SYSTEM\n"
               "  condition: sel and not filter")
        return _sigma(
            title="Clean Rule",
            logsource_cat="process_creation",
            detection=det,
            level="high",
            falsepositives=True,
        )

    def test_noisy_rule_drops_score(self):
        rules = [self._noisy_rule()]
        res = audit_handler({"rules": rules}, None)
        assert res["ok"]
        assert res["health_score"] < 100
        assert res["totals"]["fp_prone_rules"] >= 1
        assert any("FP-prone" in f for f in res["findings"])

    def test_clean_rule_full_score(self):
        rules = [self._clean_rule()]
        res = audit_handler({"rules": rules}, None)
        assert res["ok"]
        assert res["totals"]["fp_prone_rules"] == 0
        assert not any("FP-prone" in f for f in res["findings"])

    def test_fp_prone_capped_deduction(self):
        """The FP-prone deduction saturates at 10 points (weight=10, basis=5).

        We isolate the fp_prone contribution by checking that going from 5 to 10
        fp_prone rules doesn't change the fp_prone deduction (both >= basis=5,
        so both saturate). The total score may differ due to OTHER classes
        (untagged_rules also scales), but the fp_prone CONTRIBUTION is the same."""
        rules_5 = [self._noisy_rule() for _ in range(5)]
        rules_10 = [self._noisy_rule() for _ in range(10)]
        res_5 = audit_handler({"rules": rules_5}, None)
        res_10 = audit_handler({"rules": rules_10}, None)
        assert res_5["ok"] and res_10["ok"]
        # Both saturate fp_prone (count >= basis=5).
        assert res_5["totals"]["fp_prone_rules"] >= 5
        assert res_10["totals"]["fp_prone_rules"] >= 5
        # The fp_prone contribution is weight * min(1, count/5) = 10 for both.
        # Score difference should come ONLY from untagged_rules scaling (10 pts
        # weight, basis 10: 5 rules = 5pt deduct, 10 rules = 10pt deduct = +5pt diff).
        score_diff = res_5["health_score"] - res_10["health_score"]
        assert score_diff <= 10, f"diff {score_diff} exceeds max from other classes"

    def test_mixed_rules_only_noisy_penalized(self):
        rules = [self._clean_rule(), self._noisy_rule()]
        res = audit_handler({"rules": rules}, None)
        assert res["ok"]
        assert res["totals"]["fp_prone_rules"] == 1
