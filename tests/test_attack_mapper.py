"""
Offline tests for the attack-mapper A2A specialist + asset_lookup tool
======================================================================
ZERO AWS calls, ZERO network, no real sleep. Two things under test:

1. ``specialists/attack-mapper/agent_a2a.py`` — mirrors the cve-intel skeleton:
   it must import WITHOUT the heavy specialist stack (strands / litellm /
   bedrock-agentcore), expose a well-formed agent-card, AND carry a REAL
   deterministic ``build_attack_paths`` reasoner that we exercise directly
   (no LLM, no network). The serving factory is exercised with stubbed deps or
   ``importorskip``, so CI stays green when the stack is absent.

2. ``tools/asset_lookup/handler.py`` — the deterministic offline exposure-surface
   tool the reasoner consumes. Validated input + surface shape, zero network.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

# Both units live outside the package tree. Each specialist ships a module
# literally named ``agent_a2a`` (and each tool a ``handler``), so importing them
# by bare name would collide in ``sys.modules`` with the OTHER specialists'/tools'
# same-named modules when the whole suite runs (whichever test file imports first
# wins the cache). To stay a good citizen we load ours from an explicit file path
# under a UNIQUE module name and never register the bare ``agent_a2a``/``handler``
# names — so this file cannot poison test_specialist / test_threat_hunt (or any
# tool test) regardless of collection order. No AWS, no network.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECIALIST_DIR = os.path.join(REPO_ROOT, "specialists", "attack-mapper")
ASSET_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "asset_lookup")


def _load_module(unique_name: str, path: str):
    """Import a standalone .py file under a unique name without polluting the
    bare module namespace shared by sibling specialists/tools."""
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Register under the UNIQUE name only (needed for dataclass/pickle lookups),
    # never as bare "agent_a2a"/"handler".
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


agent_a2a = _load_module(
    "attack_mapper_agent_a2a", os.path.join(SPECIALIST_DIR, "agent_a2a.py")
)
asset_handler = _load_module(
    "asset_lookup_handler", os.path.join(ASSET_TOOL_DIR, "handler.py")
)


# --------------------------------------------------------------------------- #
# agent_a2a imports without heavy deps; public surface present                #
# --------------------------------------------------------------------------- #
def test_module_imports_without_heavy_deps():
    """agent_a2a must import even when strands/litellm/bedrock-agentcore are
    absent — the heavy deps are imported lazily inside the factory, not at top."""
    assert agent_a2a.SPECIALIST_NAME == "attack-mapper"


def test_factory_and_public_surface_present():
    for attr in ("build_agent", "build_app", "serve", "agent_card",
                 "build_attack_paths"):
        assert callable(getattr(agent_a2a, attr)), f"{attr} must be callable"


# --------------------------------------------------------------------------- #
# Agent-card / capability metadata is well-formed                             #
# --------------------------------------------------------------------------- #
def test_agent_card_shape():
    card = agent_a2a.agent_card()
    assert card["name"] == "attack-mapper"
    assert card["version"] == agent_a2a.SPECIALIST_VERSION
    assert isinstance(card["description"], str) and card["description"].strip()
    assert card["protocol"] == "a2a"
    caps = card["capabilities"]
    assert isinstance(caps, list) and caps
    assert all(isinstance(c, str) and c for c in caps)
    assert "attack.path" in caps
    # A2A-native skills mirror capabilities so either discovery convention works.
    skill_ids = {s["id"] for s in card["skills"]}
    assert skill_ids == set(caps)
    for s in card["skills"]:
        assert s["name"] and s["description"]
    assert card["defaultInputModes"] == ["text"]
    assert card["defaultOutputModes"] == ["text"]


def test_agent_card_url_defaults_none_and_overridable():
    assert agent_a2a.agent_card()["url"] is None
    card = agent_a2a.agent_card(url="http://127.0.0.1:9000")
    assert card["url"] == "http://127.0.0.1:9000"


def test_agent_card_metadata_has_model_and_tool_hints():
    md = agent_a2a.agent_card()["metadata"]
    assert md["modelHint"] == agent_a2a.DEFAULT_MODEL_ID
    assert list(md["gatewayTools"]) == list(agent_a2a.GATEWAY_TOOLS)
    assert "asset_lookup" in md["gatewayTools"]


def test_agent_card_json_serializable():
    import json

    json.dumps(agent_a2a.agent_card())  # must not raise


def test_no_hardcoded_secrets_or_account_ids():
    """House rule: nothing customer- or account-specific baked in."""
    import re

    src = open(
        os.path.join(SPECIALIST_DIR, "agent_a2a.py"), encoding="utf-8"
    ).read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src


# --------------------------------------------------------------------------- #
# Tool loading is safe with no Gateway configured (no network)                #
# --------------------------------------------------------------------------- #
def test_load_gateway_tools_empty_without_url():
    assert agent_a2a._load_gateway_tools(None) == []
    assert agent_a2a._load_gateway_tools("") == []


# --------------------------------------------------------------------------- #
# build_agent() is callable with deps stubbed                                 #
# --------------------------------------------------------------------------- #
def test_build_agent_with_stubbed_strands(monkeypatch):
    """Exercise the factory contract without a real strands/litellm install."""
    captured = {}
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, system_prompt, tools, name, description):
            captured.update(
                model=model, system_prompt=system_prompt, tools=tools,
                name=name, description=description,
            )

    strands_mod.Agent = _Agent
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")

    class _LiteLLMModel:
        def __init__(self, *, model_id):
            self.model_id = model_id

    litellm_mod.LiteLLMModel = _LiteLLMModel

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)

    assert isinstance(agent, _Agent)
    assert captured["model"].model_id == "bedrock/test-model"
    assert captured["name"] == "attack-mapper"
    assert captured["description"] == agent_a2a.SPECIALIST_DESCRIPTION
    assert captured["system_prompt"] == agent_a2a.SYSTEM_PROMPT
    assert captured["tools"] == []


def test_build_agent_defaults_model_from_env(monkeypatch):
    captured = {}
    strands_mod = types.ModuleType("strands")

    class _Agent:
        def __init__(self, *, model, **kw):
            captured["model_id"] = model.model_id

    strands_mod.Agent = _Agent
    models_mod = types.ModuleType("strands.models")
    litellm_mod = types.ModuleType("strands.models.litellm")
    litellm_mod.LiteLLMModel = lambda *, model_id: types.SimpleNamespace(
        model_id=model_id
    )

    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.models", models_mod)
    monkeypatch.setitem(sys.modules, "strands.models.litellm", litellm_mod)
    monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])

    agent_a2a.build_agent()
    assert captured["model_id"] == agent_a2a.DEFAULT_MODEL_ID


# --------------------------------------------------------------------------- #
# Real-dependency path (skipped in CI without the specialist stack)           #
# --------------------------------------------------------------------------- #
def test_build_agent_with_real_strands():
    """If the real specialist stack IS installed, build_agent must work too.
    Skipped cleanly when the deps are absent so CI stays green."""
    pytest.importorskip("strands")
    pytest.importorskip("litellm")
    agent = agent_a2a.build_agent(model_id="bedrock/test-model", gateway_url=None)
    assert getattr(agent, "name", None) == "attack-mapper"


# --------------------------------------------------------------------------- #
# REAL deterministic reasoner: build_attack_paths                             #
# --------------------------------------------------------------------------- #
def _fixture_surface():
    """A small surface with one obvious high-risk chain to a crown-jewel db.

    web-01 (internet-exposed, known-vuln) --ssh_key_reuse--> app-01
        --shared_admin_cred--> db-01 (postgres, crown jewel)
    bastion-01 (internet-exposed, but fully patched — must not be an entry).
    """
    return {
        "hosts": [
            {
                "id": "web-01",
                "subnet": "10.0.0.0/24",
                "internet_exposed": True,
                "services": [
                    {"port": 443, "name": "https", "known_vuln": True,
                     "cve_id": "CVE-2021-44228"},
                ],
            },
            {
                "id": "app-01",
                "subnet": "10.0.1.0/24",
                "internet_exposed": False,
                "services": [
                    {"port": 8080, "name": "http-app", "known_vuln": False,
                     "cve_id": None},
                ],
            },
            {
                "id": "db-01",
                "subnet": "10.0.2.0/24",
                "internet_exposed": False,
                "services": [
                    {"port": 5432, "name": "postgres", "known_vuln": False,
                     "cve_id": None},
                ],
            },
            {
                "id": "bastion-01",
                "subnet": "10.0.0.0/24",
                "internet_exposed": True,
                "services": [
                    {"port": 22, "name": "ssh", "known_vuln": False,
                     "cve_id": None},
                ],
            },
        ],
        "trust_edges": [
            {"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"},
            {"src": "app-01", "dst": "db-01", "kind": "shared_admin_cred"},
        ],
    }


def test_build_attack_paths_finds_the_obvious_chain():
    chains = agent_a2a.build_attack_paths(_fixture_surface())
    assert chains, "expected at least one attack chain"
    # Every chain must enter at the only valid entry: the exposed known-vuln host.
    assert all(c["entry"] == "web-01" for c in chains)
    # The full pivot chain to the crown-jewel db must be found.
    full = [c for c in chains if c["path"] == ["web-01", "app-01", "db-01"]]
    assert len(full) == 1, "the web->app->db chain must be present exactly once"
    chain = full[0]
    assert chain["entry_cve"] == "CVE-2021-44228"
    assert chain["techniques"] == ["T1190", "T1021", "T1078"]
    assert chain["edges"] == ["ssh_key_reuse", "shared_admin_cred"]
    assert chain["impact"] == "critical"
    assert chain["score"] == pytest.approx(0.6)
    # The patched-but-exposed bastion is NEVER an entry (no known-vuln service).
    assert all(c["entry"] != "bastion-01" for c in chains)


def test_build_attack_paths_ranks_descending_and_deterministic():
    chains = agent_a2a.build_attack_paths(_fixture_surface())
    scores = [c["score"] for c in chains]
    assert scores == sorted(scores, reverse=True), "chains must rank by score desc"
    # Deterministic: same input yields identical output on a second call.
    again = agent_a2a.build_attack_paths(_fixture_surface())
    assert chains == again
    # The deep, higher-impact chain must out- or tie-rank the shallow 2-hop one,
    # and never rank below it.
    deep = next(c for c in chains if c["path"][-1] == "db-01")
    shallow = next(c for c in chains if c["path"] == ["web-01", "app-01"])
    assert deep["score"] >= shallow["score"]


def test_build_attack_paths_empty_on_fully_patched_surface():
    """A surface with no internet-exposed known-vuln entry has no attack path."""
    patched = _fixture_surface()
    for host in patched["hosts"]:
        for svc in host["services"]:
            svc["known_vuln"] = False
            svc["cve_id"] = None
    assert agent_a2a.build_attack_paths(patched) == []


def test_build_attack_paths_empty_when_vuln_not_internet_exposed():
    """A known-vuln host that is NOT internet-exposed is not INITIAL access."""
    surface = {
        "hosts": [
            {
                "id": "internal-01",
                "subnet": "10.0.9.0/24",
                "internet_exposed": False,
                "services": [
                    {"port": 443, "name": "https", "known_vuln": True,
                     "cve_id": "CVE-2021-44228"},
                ],
            },
        ],
        "trust_edges": [],
    }
    assert agent_a2a.build_attack_paths(surface) == []


def test_build_attack_paths_is_cycle_safe():
    """A trust-edge cycle must not loop forever; each host appears once per path."""
    surface = {
        "hosts": [
            {"id": "a", "subnet": "10.0.0.0/24", "internet_exposed": True,
             "services": [{"port": 443, "name": "https", "known_vuln": True,
                           "cve_id": "CVE-2021-44228"}]},
            {"id": "b", "subnet": "10.0.1.0/24", "internet_exposed": False,
             "services": [{"port": 8080, "name": "http-app",
                           "known_vuln": False, "cve_id": None}]},
        ],
        "trust_edges": [
            {"src": "a", "dst": "b", "kind": "ssh_key_reuse"},
            {"src": "b", "dst": "a", "kind": "flat_network"},  # cycle back
        ],
    }
    chains = agent_a2a.build_attack_paths(surface)
    for c in chains:
        assert len(c["path"]) == len(set(c["path"])), "no host repeats in a path"


def test_build_attack_paths_rejects_malformed_surface():
    with pytest.raises(ValueError):
        agent_a2a.build_attack_paths({"hosts": "not-a-list"})
    with pytest.raises(ValueError):
        agent_a2a.build_attack_paths({"hosts": [{"no_id": True}]})


# --------------------------------------------------------------------------- #
# asset_lookup tool: deterministic offline surface + input validation         #
# --------------------------------------------------------------------------- #
def test_asset_lookup_returns_offline_surface_for_wildcard():
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    surface = res["surface"]
    host_ids = {h["id"] for h in surface["hosts"]}
    assert {"web-01", "app-01", "db-01", "bastion-01"} <= host_ids
    # Every host has the required shape.
    for h in surface["hosts"]:
        assert isinstance(h["id"], str)
        assert isinstance(h["internet_exposed"], bool)
        for svc in h["services"]:
            assert set(svc) >= {"port", "proto", "name", "known_vuln", "cve_id"}
    # Trust edges present and well-formed.
    assert surface["trust_edges"]
    for e in surface["trust_edges"]:
        assert set(e) >= {"src", "dst", "kind"}


def test_asset_lookup_surface_feeds_reasoner_end_to_end():
    """The tool's offline surface must drive the reasoner to a real chain."""
    surface = asset_handler.handler({"query": "*"}, None)["surface"]
    chains = agent_a2a.build_attack_paths(surface)
    assert any(c["path"] == ["web-01", "app-01", "db-01"] for c in chains)


def test_asset_lookup_single_host_query():
    res = asset_handler.handler({"query": "web-01"}, None)
    assert res["ok"] is True
    ids = {h["id"] for h in res["surface"]["hosts"]}
    assert ids == {"web-01"}


def test_asset_lookup_subnet_query_matches_hosts_in_subnet():
    res = asset_handler.handler({"query": "10.0.0.0/24"}, None)
    assert res["ok"] is True
    ids = {h["id"] for h in res["surface"]["hosts"]}
    # web-01 and bastion-01 live in 10.0.0.0/24.
    assert ids == {"web-01", "bastion-01"}


def test_asset_lookup_broad_subnet_query_matches_all_tiers():
    res = asset_handler.handler({"query": "10.0.0.0/16"}, None)
    assert res["ok"] is True
    ids = {h["id"] for h in res["surface"]["hosts"]}
    assert {"web-01", "app-01", "db-01", "bastion-01"} <= ids


def test_asset_lookup_unknown_host_returns_empty_surface():
    res = asset_handler.handler({"query": "does-not-exist"}, None)
    assert res["ok"] is True
    assert res["surface"]["hosts"] == []
    assert res["surface"]["trust_edges"] == []


def test_asset_lookup_validation_errors():
    for bad in ({}, {"query": ""}, {"query": "   "}, {"query": 123},
                {"query": "10.0.0.0/99"}, {"query": "bad host!"}):
        res = asset_handler.handler(bad, None)
        assert res["ok"] is False
        assert res["error"] == "validation_error"
    # Non-dict event.
    res = asset_handler.handler("nope", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


def test_asset_lookup_is_deterministic():
    a = asset_handler.handler({"query": "*"}, None)
    b = asset_handler.handler({"query": "*"}, None)
    assert a == b


def test_asset_lookup_live_without_backend_surfaces_error(monkeypatch):
    """Opting into live with no backend must NOT silently fall back to fixtures —
    it surfaces an explicit upstream_error (honesty over false reassurance)."""
    monkeypatch.setenv("ASSET_LOOKUP_LIVE", "1")
    monkeypatch.delenv("ASSET_LOOKUP_URL", raising=False)
    res = asset_handler.handler({"query": "*"}, None)
    assert res["ok"] is False
    assert res["error"] == "upstream_error"
