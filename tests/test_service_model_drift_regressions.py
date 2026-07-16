"""
Regression tests for the service-model payload-shape drift fixes.
================================================================================
A ``service-model-drift-scan`` workflow validated every AWS-payload-building module
against the REAL botocore service model and found 5 "offline-green, live-red"
shape defects — payloads that pass mocked/offline tests (botocore checks TYPES but
NOT string patterns / min-max / Create-vs-Update shape asymmetry at call time) yet
ParamValidationError or ValidationException against the live service. This file
pins each fix, validating the EMITTED shape against the installed botocore model so
a future drift is caught offline:

  * core.update_harness (HIGH) — UpdateHarness.memory needs an ``optionalValue``
    wrapper; the memory builders emit the CreateHarness shape (create-green,
    update-red). Now wrapped.
  * registry_live._client_token (HIGH) — embedded a raw resource name (underscore/
    dot/slash legal in names, ILLEGAL in a clientToken pattern). Now sanitized.
  * registry_live._client_token (MED) — never capped at the 256-char max. Now bounded.
  * factory._existing_env (MED) — read ``summary['tags']`` which ListHarnesses'
    HarnessSummary does not have (dead guard). Now reads ListTagsForResource.
  * factory._resolve_entry (MED) — forwarded non-string tag values (map<string,
    string>) → live ParamValidationError, missed by dry-run. Now validated.

HARD RULE: ZERO network — botocore's OFFLINE service model + validate_parameters is
the ground truth. No live AWS call.
"""
from __future__ import annotations

import os
import re

import pytest

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import botocore.session  # noqa: E402
from botocore.exceptions import ParamValidationError  # noqa: E402
from botocore.validate import validate_parameters  # noqa: E402

from sentinel_harness import core, factory  # noqa: E402
from sentinel_harness import registry_live as rl  # noqa: E402

_MODEL = botocore.session.get_session().get_service_model("bedrock-agentcore-control")


def _input_shape(op: str):
    return _MODEL.operation_model(op).input_shape


# --------------------------------------------------------------------------- #
# #1 (HIGH) — UpdateHarness.memory optionalValue wrapper                      #
# --------------------------------------------------------------------------- #
def _build_update_args(memory):
    """Reproduce the args dict update_harness builds for a given memory value,
    without calling AWS (mirrors core.update_harness's memory branch)."""
    args = {"harnessId": "h", "executionRoleArn": "arn:aws:iam::000000000000:role/x"}
    if memory is not None:
        args["memory"] = memory if "optionalValue" in memory else {"optionalValue": memory}
    return args


@pytest.mark.parametrize("builder", ["managed", "byo"])
def test_update_harness_memory_validates_against_model(builder):
    mem = (core.managed_memory(strategies=["SEMANTIC"]) if builder == "managed"
           else core.byo_memory("arn:aws:bedrock-agentcore:us-east-1:000000000000:memory/m"))
    args = _build_update_args(mem)
    # the wrapped shape must pass the REAL UpdateHarness input model
    validate_parameters(args, _input_shape("UpdateHarness"))  # must not raise


def test_bare_memory_would_have_failed_update(builder="managed"):
    """Guard the guard: the UNWRAPPED create-shape memory must still be REJECTED by
    UpdateHarness — proving the wrapper is load-bearing, not cosmetic."""
    bare = core.managed_memory(strategies=["SEMANTIC"])
    with pytest.raises(ParamValidationError):
        validate_parameters({"harnessId": "h", "executionRoleArn": "r", "memory": bare},
                            _input_shape("UpdateHarness"))


def test_create_harness_still_takes_bare_memory():
    """The create shape is unchanged — CreateHarness takes the bare dict directly."""
    bare = core.managed_memory(strategies=["SEMANTIC"])
    validate_parameters(
        {"harnessName": "h", "systemPrompt": [{"text": "x"}],
         "executionRoleArn": "arn:aws:iam::000000000000:role/x", "memory": bare},
        _input_shape("CreateHarness"),
    )


# --------------------------------------------------------------------------- #
# #2/#3 (HIGH/MED) — clientToken pattern + length                             #
# --------------------------------------------------------------------------- #
# The clientToken shape pattern from the model (alphanumerics + hyphens, no trailing).
_CT_SHAPE = _input_shape("CreateRegistry").members["clientToken"]
_CT_PATTERN = re.compile(_CT_SHAPE.metadata["pattern"])
_CT_MIN = _CT_SHAPE.metadata["min"]
_CT_MAX = _CT_SHAPE.metadata["max"]


@pytest.mark.parametrize("name", [
    "alert_triage",      # underscore (legal name, illegal token char)
    "detect.v2",         # dot
    "a/b/c",             # slash
    "UPPER_and_lower",
    "x",                 # short -> must pad to >=33
    "n" * 260,           # long -> must cap at <=256
    "ok-name",           # already valid
])
def test_client_token_matches_model_pattern_and_length(name):
    tok = rl._client_token(f"registry-{name}")
    assert re.fullmatch(_CT_PATTERN, tok), f"token {tok!r} violates clientToken pattern"
    assert _CT_MIN <= len(tok) <= _CT_MAX, f"token len {len(tok)} out of [{_CT_MIN},{_CT_MAX}]"


def test_client_token_deterministic_per_seed():
    assert rl._client_token("registry-alert_triage") == rl._client_token("registry-alert_triage")


# --------------------------------------------------------------------------- #
# #4 (MED) — factory reads tags via ListTagsForResource, not summary['tags']  #
# --------------------------------------------------------------------------- #
def test_existing_env_reads_via_list_tags(monkeypatch):
    """A summary with NO inline tags (as real ListHarnesses returns) must resolve the
    env by calling ListTagsForResource(resourceArn), not by reading a nonexistent key."""
    calls = {}

    class _Ctl:
        def list_tags_for_resource(self, resourceArn):
            calls["arn"] = resourceArn
            return {"tags": {factory.ENV_TAG_KEY: "prod"}}

    monkeypatch.setattr(factory.core, "_control", _Ctl())
    env = factory._existing_env({"harnessName": "h", "arn": "arn:aws:...:harness/h"})
    assert env == "prod"
    assert calls["arn"] == "arn:aws:...:harness/h"


def test_existing_env_none_when_untagged(monkeypatch):
    class _Ctl:
        def list_tags_for_resource(self, resourceArn):
            return {"tags": {}}
    monkeypatch.setattr(factory.core, "_control", _Ctl())
    assert factory._existing_env({"arn": "arn:x"}) is None


def test_existing_env_fails_safe_on_read_error(monkeypatch):
    class _Ctl:
        def list_tags_for_resource(self, resourceArn):
            raise RuntimeError("throttled")
    monkeypatch.setattr(factory.core, "_control", _Ctl())
    # a tag-read failure must not crash provisioning — treat as untagged.
    assert factory._existing_env({"arn": "arn:x"}) is None


def test_existing_env_honors_inline_tags(monkeypatch):
    # a test-fake summary that DOES carry inline tags is honored without an API call.
    class _Boom:
        def list_tags_for_resource(self, resourceArn):
            raise AssertionError("must not call the API when inline tags are present")
    monkeypatch.setattr(factory.core, "_control", _Boom())
    assert factory._existing_env({"tags": {factory.ENV_TAG_KEY: "dev"}}) == "dev"


# --------------------------------------------------------------------------- #
# #5 (MED) — factory rejects non-string tag values (map<string,string>)       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [{"build": 42}, {"critical": True}, {"ratio": 1.5}])
def test_resolve_entry_rejects_non_string_tag_value(bad):
    entry = {"name": "t_ok", "system_prompt": "hi", "tags": bad}
    with pytest.raises(factory.FactoryError, match="strings"):
        factory._resolve_entry(entry, {}, "dev", 0)


def test_resolve_entry_accepts_string_tags():
    entry = {"name": "t_ok", "system_prompt": "hi", "tags": {"team": "secops"}}
    r = factory._resolve_entry(entry, {}, "dev", 0)
    assert r["tags"]["team"] == "secops"
    # and the resolved tags validate against the real CreateHarness tags map.
    validate_parameters(
        {"harnessName": "t_ok", "systemPrompt": [{"text": "x"}],
         "executionRoleArn": "arn:aws:iam::000000000000:role/x", "tags": r["tags"]},
        _input_shape("CreateHarness"),
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
