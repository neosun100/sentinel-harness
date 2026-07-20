"""Packaging tripwire — the wheel must ship every tree the CLI/MCP server needs.

v0.4.0 shipped a broken wheel: ``[tool.setuptools] packages = ["sentinel_harness",
"intake"]`` silently dropped ``sentinel_harness.connectors`` (an explicit package
list does NOT imply subpackages) and the whole ``tools/`` + ``mockdata/`` trees —
so ``sentinel detection audit`` and ``sentinel mcp serve`` failed for every
pip-installed user with ``tool handler not found`` / ``No module named 'mockdata'``.

These tests read pyproject.toml as data (no build, no network) and fail if the
packaging config regresses to a shape that drops any required tree. A full
build-and-import proof lives in the release quality gate (the wheel smoke test).
"""
from __future__ import annotations

import os
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover — py3.10 fallback
    tomllib = None

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(_REPO_ROOT, "pyproject.toml")

# Every top-level tree the runtime discovers at import- or call-time. Dropping any
# of these from the wheel breaks a shipped command for pip-installed users:
#   sentinel_harness — the library (find() must include SUBpackages, e.g. connectors)
#   intake           — imported by the M1 meta-agent path
#   tools            — cli._load_tool_handler + mcp_server._discover_tools load
#                      tools/<name>/handler.py relative to the package parent
#   mockdata         — imported by enrich_ioc / ops_query / siem_query handlers
REQUIRED_TREES = ["sentinel_harness", "intake", "tools", "mockdata"]


@pytest.fixture(scope="module")
def pyproject() -> dict:
    if tomllib is None:
        pytest.skip("tomllib requires Python 3.11+ (config shape is version-independent)")
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def test_packaging_uses_find_not_explicit_list(pyproject: dict) -> None:
    """An explicit packages list is the failure mode that shipped the broken wheel
    (it silently drops subpackages). Require the find() directive."""
    setuptools_cfg = pyproject.get("tool", {}).get("setuptools", {})
    packages = setuptools_cfg.get("packages")
    assert isinstance(packages, dict) and "find" in packages, (
        "pyproject [tool.setuptools] packages must use the packages.find directive, "
        "not an explicit list — an explicit list drops subpackages (shipped broken "
        f"in 0.4.0); got {packages!r}"
    )


@pytest.mark.parametrize("tree", REQUIRED_TREES)
def test_find_include_covers_required_tree(pyproject: dict, tree: str) -> None:
    find_cfg = (
        pyproject.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    )
    include = find_cfg.get("include", [])
    assert any(
        pat == tree or pat == f"{tree}*" or pat.startswith(f"{tree}.")
        for pat in include
    ), (
        f"pyproject packages.find.include must cover {tree!r} — the wheel breaks a "
        f"shipped command without it (see module docstring). include={include}"
    )


def test_find_namespaces_enabled(pyproject: dict) -> None:
    """tools/<name>/ dirs have no __init__.py — they only ship with namespaces=true."""
    find_cfg = (
        pyproject.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    )
    assert find_cfg.get("namespaces") is True, (
        "packages.find.namespaces must be true: tools/ is a flat handler tree with "
        "no __init__.py files and is silently dropped without namespace discovery"
    )


@pytest.mark.parametrize("tree", REQUIRED_TREES)
def test_required_tree_exists(tree: str) -> None:
    assert os.path.isdir(os.path.join(_REPO_ROOT, tree)), f"{tree}/ missing from repo"
