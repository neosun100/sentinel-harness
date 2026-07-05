"""
Offline tests for the sample-detonation long-running Runtime skeleton
=====================================================================
ZERO AWS calls, ZERO network, ZERO real VM, ZERO real detonation. Everything is
the SIMULATED skeleton: the one-shot microVM is an in-memory abstraction, the
sample is a reference-only s3:// uri, and the plan is driven through the existing
Play-Mode gate with injected fake ``invoke_fn`` / ``resume_fn`` (as
``tests/test_bas_runner.py`` does), so nothing touches boto3 or the network.

Coverage:
  * ``bedrock_entrypoint`` imports WITHOUT ``bedrock_agentcore`` (guarded import).
  * ``OneShotMicroVM`` acquire -> run_action -> destroy lifecycle (simulated).
  * destroy-after-use is enforced: using a destroyed handle raises.
  * a path-traversal and a disallowed command are BLOCKED by the sandbox hooks
    (delegating to ``sentinel_harness.sandbox_hooks``).
  * a sample enters ONLY by s3:// reference; a live-fetch-shaped uri is rejected.
  * a simulated detonation step is HITL-gated (reuse Play Mode) and a reject halts.

HARD RULE: dummy AWS env set before import; the runner is fully DI'd here.
"""
from __future__ import annotations

import os
import sys

import pytest

# --- Make imports hermetic: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# detonation + bas-runner modules live under longrunning/, not in the package.
# ``longrunning`` is not a Python package and ``bas-runner`` cannot be one (its
# name has a dash), so these dirs are put on sys.path directly (the same
# convention tests/test_bas_runner.py uses). NOTE: the detonation entrypoint
# shares the basename ``bedrock_entrypoint`` with bas-runner's, so we load it by
# explicit file path via importlib (below) to avoid a module-name collision.
import importlib.util  # noqa: E402

_LR = os.path.join(os.path.dirname(__file__), "..", "longrunning")
sys.path.insert(0, os.path.abspath(os.path.join(_LR, "bas-runner")))
sys.path.insert(0, os.path.abspath(os.path.join(_LR, "detonation", "src")))

from sentinel_harness import simulation as sim  # noqa: E402

import runner_loop as rl  # noqa: E402
from runner_loop import BasRunnerLoop  # noqa: E402
from vm import (  # noqa: E402
    ACQUIRED,
    DESTROYED,
    ActionRefused,
    OneShotMicroVM,
    Sample,
    VMAlreadyDestroyedError,
    VMError,
)


def _load_detonation_entrypoint():
    """Load longrunning/detonation/bedrock_entrypoint.py under a unique module
    name so it never collides with bas-runner's identically-named module."""
    path = os.path.abspath(
        os.path.join(_LR, "detonation", "bedrock_entrypoint.py")
    )
    spec = importlib.util.spec_from_file_location("detonation_bedrock_entrypoint", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

ARN = "arn:aws:test:harness/hid-detonation"
SESSION = "detonation-test-session-000000000000000000000000"

# A generic SIMULATED detonation plan (technique ids illustrative, nothing real).
PLAN = [
    {"phase": "detonation-setup", "technique": "T1204", "objective": "sim stage sample"},
    {"phase": "execution", "technique": "T1059", "objective": "sim detonate"},
    {"phase": "collection", "technique": "T1005", "objective": "sim collect artifacts"},
]


# --------------------------------------------------------------------------- #
# Fake: scripted invoke/resume that make ZERO AWS calls (mirrors bas-runner)  #
# --------------------------------------------------------------------------- #
class FakeHarness:
    """Scripted harness that pauses on the gate every invoke (no AWS/network)."""

    def __init__(self, pause=True):
        self.pause = pause
        self.invokes = []
        self.resumes = []
        self._n = 0

    def invoke(self, harness_arn, session_id, text, **kw):
        self.invokes.append({"arn": harness_arn, "session": session_id})
        if not self.pause:
            return {"stop_reason": "end_turn", "tool_use": None, "text": "no gate"}
        self._n += 1
        return {
            "stop_reason": "tool_use",
            "tool_use": {"toolUseId": f"tu-{self._n}", "name": sim.PlayModeRunner.GATE_NAME,
                         "input": {"technique": f"T{self._n}"}},
            "text": "",
        }

    def resume(self, harness_arn, session_id, tool_use, result, status="success", **kw):
        self.resumes.append({"tool_use": tool_use, "result": result, "status": status})
        return {"stop_reason": "end_turn", "text": "resumed", "tool_use": None}


def make_loop(fake, *, decision_fn, mode=rl.CONTINUOUS, checkpoint_path=None, plan=None):
    runner = sim.PlayModeRunner(
        ARN,
        plan=plan or PLAN,
        session_id=SESSION,
        plan_id="detotest",
        checkpoint_path=checkpoint_path,
        invoke_fn=fake.invoke,
        resume_fn=fake.resume,
        decision_fn=decision_fn,
        logger=lambda m: None,
    )
    return BasRunnerLoop(runner, mode=mode)


# --------------------------------------------------------------------------- #
# 1. Entrypoint imports without bedrock_agentcore (guarded)                   #
# --------------------------------------------------------------------------- #
def test_entrypoint_imports_without_agentcore():
    """The @app.entrypoint module must import even when bedrock_agentcore is absent."""
    ep = _load_detonation_entrypoint()
    assert ep._HAS_AGENTCORE in (True, False)
    if not ep._HAS_AGENTCORE:
        assert ep.app is None
    # The pure-Python detonation driver is always importable/usable regardless.
    assert callable(ep.build_runner)
    assert callable(ep.run_detonation)


# --------------------------------------------------------------------------- #
# 2. One-shot microVM lifecycle: acquire -> run_action -> destroy (simulated) #
# --------------------------------------------------------------------------- #
def test_microvm_acquire_run_destroy_lifecycle():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    assert handle.state == ACQUIRED
    assert handle.is_live

    res = vm.run_action(handle, {"kind": "run", "command": "ls /workspace"})
    assert res["ok"] is True
    assert res["simulated"] is True  # NEVER a real execution
    assert "SIMULATED" in res["note"]
    assert handle.action_log and handle.action_log[-1] is res

    path_res = vm.run_action(handle, {"kind": "read", "path": "artifacts/report.txt"})
    assert path_res["simulated"] is True

    destroyed = vm.destroy(handle)
    assert destroyed["state"] == DESTROYED
    assert handle.state == DESTROYED


def test_one_shot_refuses_second_live_vm():
    """One-shot / no-reuse: can't acquire a second VM while one is live."""
    vm = OneShotMicroVM()
    h1 = vm.acquire(SESSION)
    with pytest.raises(VMError):
        vm.acquire("another-session")
    vm.destroy(h1)
    # after destroy, a fresh acquire is allowed
    h2 = vm.acquire("another-session")
    assert h2.is_live and h2.vm_id != h1.vm_id


# --------------------------------------------------------------------------- #
# 3. destroy-after-use is enforced: a destroyed handle cannot run actions     #
# --------------------------------------------------------------------------- #
def test_destroy_after_use_enforced():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    vm.destroy(handle)
    with pytest.raises(VMAlreadyDestroyedError):
        vm.run_action(handle, {"kind": "run", "command": "ls"})


def test_destroy_is_idempotent():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    first = vm.destroy(handle)
    second = vm.destroy(handle)
    assert first["idempotent_noop"] is False
    assert second["idempotent_noop"] is True


# --------------------------------------------------------------------------- #
# 4. Sandbox hooks BLOCK a path-traversal and a disallowed command            #
# --------------------------------------------------------------------------- #
def test_path_traversal_blocked_by_sandbox_hooks():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    with pytest.raises(ActionRefused) as ei:
        vm.run_action(handle, {"kind": "read", "path": "../../etc/passwd"})
    assert "traversal" in ei.value.reason
    # the refused action was NOT (simulated-)executed / logged.
    assert handle.action_log == []


def test_disallowed_command_blocked_by_sandbox_hooks():
    vm = OneShotMicroVM(sandbox_root="/workspace")
    handle = vm.acquire(SESSION)
    with pytest.raises(ActionRefused):
        vm.run_action(handle, {"kind": "run", "command": "rm -rf /"})
    assert handle.action_log == []


def test_unknown_action_kind_rejected():
    vm = OneShotMicroVM()
    handle = vm.acquire(SESSION)
    with pytest.raises(ValueError):
        vm.run_action(handle, {"kind": "detonate_for_real", "command": "x"})


# --------------------------------------------------------------------------- #
# 5. A sample enters ONLY by s3:// reference — never a live fetch             #
# --------------------------------------------------------------------------- #
def test_sample_reference_only():
    ok = Sample(s3_uri="s3://dropbox-bucket/quarantine/abc123", dropbox_id="drop-1")
    assert ok.s3_uri.startswith("s3://")
    assert ok.sha256 is None  # never computed here (bytes never read)
    # a live-fetch-shaped reference is rejected.
    for bad in ("https://evil.example/malware.bin", "/tmp/local/sample.exe", "ftp://x"):
        with pytest.raises(ValueError):
            Sample(s3_uri=bad)


# --------------------------------------------------------------------------- #
# 6. A simulated detonation step is HITL-gated (Play Mode); reject halts       #
# --------------------------------------------------------------------------- #
def test_detonation_step_is_hitl_gated_and_simulated():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve)
    turn = loop.run()
    assert turn.complete and not turn.halted
    # every detonation step paused on the gate ...
    assert all(s.tool_use_id is not None for s in loop.state.steps)
    # ... and "execution" was a SIMULATED no-op, never a real detonation.
    for s in loop.state.steps:
        assert s.status == sim.EXECUTED
        assert "SIMULATED" in (s.execution_log or "")
    v = loop.runner.verdict()
    assert v["every_step_gated"] is True
    assert v["approved_step_resumed"] is True


def test_detonation_reject_halts_plan():
    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_reject)
    turn = loop.run()
    assert turn.halted
    assert loop.state.steps[0].status == sim.REJECTED
    assert loop.state.steps[1].status == sim.PENDING
    assert loop.state.steps[2].status == sim.PENDING
    assert len(fake.invokes) == 1  # halted before later steps ran
    assert fake.resumes[-1]["status"] == "error"
    assert loop.runner.verdict()["reject_halts_plan"] is True


# --------------------------------------------------------------------------- #
# 7. End-to-end driver: acquire -> gated plan -> destroy-after-use            #
# --------------------------------------------------------------------------- #
def test_run_detonation_destroys_vm_after_use(tmp_path):
    ep = _load_detonation_entrypoint()

    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_approve,
                     checkpoint_path=str(tmp_path / "d.json"))
    vm = OneShotMicroVM()
    sample = Sample(s3_uri="s3://dropbox/quarantine/xyz")
    result = ep.run_detonation(loop, vm=vm, session_id=SESSION, sample=sample)

    assert result["event"] == "plan_complete"
    # destroy-after-use: the VM is torn down when the plan finishes.
    assert result["vm"]["state"] == DESTROYED
    assert result["vm"]["session_id"] == SESSION


def test_run_detonation_destroys_vm_even_when_halted(tmp_path):
    ep = _load_detonation_entrypoint()

    fake = FakeHarness()
    loop = make_loop(fake, decision_fn=sim.auto_reject,
                     checkpoint_path=str(tmp_path / "d.json"))
    vm = OneShotMicroVM()
    result = ep.run_detonation(loop, vm=vm, session_id=SESSION)

    assert result["event"] == "plan_halted"
    # destroy-after-use holds even on a halt (destroy is in a finally).
    assert result["vm"]["state"] == DESTROYED
