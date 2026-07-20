"""Shared pytest configuration for the sentinel-harness test suite.

This module is imported by pytest before any test module is collected, so the
env-var block below runs *before* modules that read AWS / Sentinel settings at
import time (e.g. ``sentinel_harness.core`` reads ``SENTINEL_EXECUTION_ROLE_ARN``
on import). It provides a single authoritative fallback so that any test which
forgot the per-file credential boilerplate still runs against fake credentials
and never touches a real AWS account or the network.

``setdefault`` is used deliberately: tests that explicitly set their own values
(a specific role ARN, region, etc.) keep working unchanged.
"""

import os
import sys

# ---------------------------------------------------------------------------
# Credential / region fallback — runs at conftest import, before any test
# module import. Uses setdefault so explicit per-test values still win.
# ---------------------------------------------------------------------------
_ENV_FALLBACKS = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/test",
}


def _apply_env_fallbacks():
    """Point the suite at fake credentials without touching a real profile.

    ``AWS_PROFILE`` is *removed* rather than set: an empty string would make
    botocore look up a profile literally named "" and raise ProfileNotFound,
    and any real profile inherited from the shell must not win over the fake
    static keys below. With no profile set, botocore resolves the env-var keys.
    """
    os.environ.pop("AWS_PROFILE", None)
    for key, value in _ENV_FALLBACKS.items():
        os.environ.setdefault(key, value)


_apply_env_fallbacks()

# ---------------------------------------------------------------------------
# Make the repository root importable so test modules can eventually drop their
# per-file ``sys.path`` shims. tests/ lives directly under the repo root.
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


import pytest


@pytest.fixture(scope="session", autouse=True)
def _enforce_fake_aws_credentials():
    """Session-scoped guard that keeps the fake-credential fallback in place.

    The env vars are already set at conftest import time (above); this fixture
    reasserts the fallback so any code that ran between import and session start
    cannot leave the suite pointed at real credentials.
    """
    _apply_env_fallbacks()
    yield
