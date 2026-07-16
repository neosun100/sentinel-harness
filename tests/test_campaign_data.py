"""
Offline tests for mockdata.campaign — the time-series attack campaign + chains.

ZERO AWS, ZERO network, fast, deterministic. Asserts the campaign is a coherent,
hygienic, well-formed dataset: strictly-increasing timestamps, real enterprise
host ids, real ATT&CK ids, a TP intrusion + FP noise, and RFC-5737/secret hygiene.
"""
from __future__ import annotations

import ipaddress
import re

from mockdata import campaign, enterprise

_RFC5737 = ("192.0.2.", "198.51.100.", "203.0.113.")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_ALLOWED_NONROUTABLE = {"0.0.0.0", "127.0.0.1"}


def _enterprise_host_ids():
    return {h["id"] for h in enterprise.load_enterprise()["hosts"]}


# --------------------------------------------------------------------------- #
# determinism + populated                                                     #
# --------------------------------------------------------------------------- #
def test_deterministic_and_independent_copies():
    assert campaign.campaign_alerts() == campaign.campaign_alerts()
    a = campaign.campaign_alerts()
    a[0]["host"] = "MUTATED"
    assert campaign.campaign_alerts()[0]["host"] != "MUTATED"


def test_populated():
    s = campaign.stats()
    assert s["alerts"] >= 20
    assert s["true_positive"] > 0 and s["false_positive"] > 0
    assert s["stages"] >= 5
    assert s["threat_chains"] >= 6


# --------------------------------------------------------------------------- #
# coherence                                                                   #
# --------------------------------------------------------------------------- #
def test_timestamps_strictly_increasing():
    ts = [a["ts"] for a in campaign.campaign_alerts()]
    assert ts == sorted(ts), "campaign must be time-ordered"
    assert len(set(ts)) == len(ts), "timestamps must be unique (strictly increasing)"


def test_tp_and_fp_split_matches_accessors():
    alerts = campaign.campaign_alerts()
    tp = campaign.true_positive_alerts()
    fp = campaign.false_positive_alerts()
    assert len(tp) + len(fp) == len(alerts)
    assert all(a["true_positive"] for a in tp)
    assert all(not a["true_positive"] for a in fp)


def test_tp_intrusion_is_multistage():
    """The real intrusion must span several kill-chain stages (a coherent story)."""
    stages = {a["stage"] for a in campaign.true_positive_alerts()}
    assert len(stages) >= 5
    assert "initial_access" in stages
    assert "lateral_movement" in stages


def test_intrusion_reaches_a_crown_jewel_host():
    """The TP alerts must touch a crown-jewel host (the campaign's objective)."""
    crown = set(enterprise.crown_jewels())
    touched = {a["host"] for a in campaign.true_positive_alerts()}
    assert touched & crown, "the intrusion should reach a crown jewel"


# --------------------------------------------------------------------------- #
# validity: real hosts, real ATT&CK ids, valid stages                         #
# --------------------------------------------------------------------------- #
def test_every_alert_host_is_a_real_enterprise_host():
    valid = _enterprise_host_ids()
    for a in campaign.campaign_alerts():
        assert a["host"] in valid, f"{a['alert_id']} host {a['host']} not an enterprise host"


def test_every_technique_is_a_real_attack_id():
    for a in campaign.campaign_alerts():
        assert re.match(r"^T\d{4}", a["technique"]), f"{a['alert_id']} bad ATT&CK {a['technique']}"


def test_every_stage_is_in_vocabulary():
    for a in campaign.campaign_alerts():
        assert a["stage"] in campaign.STAGES, f"{a['alert_id']} bad stage {a['stage']}"


def test_alert_ids_unique():
    ids = [a["alert_id"] for a in campaign.campaign_alerts()]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# threat chains                                                               #
# --------------------------------------------------------------------------- #
def test_chains_reference_real_hosts_and_reach_high_value_targets():
    valid = _enterprise_host_ids()
    hosts = {h["id"]: h for h in enterprise.load_enterprise()["hosts"]}
    for c in campaign.threat_chains():
        for h in [c["entry_host"], c["target_host"], *c["hops"]]:
            assert h in valid, f"chain {c['id']} host {h} unknown"
        # A threat chain targets a HIGH-VALUE asset (critical crown jewel OR a
        # high-criticality host like a backup vault / session store) — not only
        # the strictly-'critical' set (a backup vault is a realistic exfil target).
        crit = hosts[c["target_host"]]["criticality"]
        assert crit in ("critical", "high"), (
            f"chain {c['id']} target {c['target_host']} is only {crit}-criticality"
        )
        for t in c["techniques"]:
            assert re.match(r"^T\d{4}", t), f"chain {c['id']} bad technique {t}"


def test_most_chains_reach_a_crown_jewel():
    """The majority of chains should reach a strictly-critical crown jewel (the
    highest-value targets); a couple may target high-criticality assets."""
    crown = set(enterprise.crown_jewels())
    chains = campaign.threat_chains()
    crown_hits = sum(1 for c in chains if c["target_host"] in crown)
    assert crown_hits >= len(chains) // 2, "most chains should reach a crown jewel"


def test_chains_entry_hosts_are_internet_exposed():
    surface = {h["id"]: h for h in enterprise.load_enterprise()["hosts"]}
    for c in campaign.threat_chains():
        assert surface[c["entry_host"]]["internet_exposed"], (
            f"chain {c['id']} entry {c['entry_host']} is not internet-exposed"
        )


# --------------------------------------------------------------------------- #
# hygiene                                                                     #
# --------------------------------------------------------------------------- #
def test_ip_hygiene():
    import json
    text = json.dumps(campaign.campaign_alerts()) + json.dumps(campaign.threat_chains())
    for ip in _IP_RE.findall(text):
        if ip in _ALLOWED_NONROUTABLE:
            continue
        ok = any(ip.startswith(p) for p in _RFC5737) or ipaddress.ip_address(ip).is_private
        assert ok, f"non-doc/non-private IP literal: {ip}"


def test_no_secrets_or_real_accounts():
    src = open(campaign.__file__, encoding="utf-8").read()
    for acct in re.findall(r"\b\d{12}\b", src):
        assert acct == "000000000000", f"non-placeholder account id: {acct}"
    for tok in ("AKIA", "ghp_", "xoxb-"):
        assert tok not in src, f"secret-looking prefix {tok!r}"
