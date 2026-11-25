"""Tests for the policy loader: a policy loads only if it parses, checks and passes its own tests.

The shipped `policies/default.pol` must load from two starting states: a workspace under home
(as on a developer's machine) and the temporary-directory sandbox. The rest use small policies
written here, to show that a failing test refuses the policy, that `after` commands move the
session as the gate would, and that nothing is executed while testing.
"""

from __future__ import annotations

import shutil
from pathlib import PurePosixPath

import pytest

from compiler.parser import parse_source
from compiler.types import RuleId, SessionState, Verdict
from gate.executor import TempDirExecutor
from gate.policy_loader import (
    CHECKOUT,
    PolicyLoadError,
    check_expects,
    checkout_root,
    load_policy,
    load_policy_file,
    predicted_cwd,
)

DEFAULT = CHECKOUT / "policies" / "default.pol"
WS = PurePosixPath("/home/dev/project")
STATE = SessionState(
    cwd=WS, home=PurePosixPath("/home/dev"), workspace=WS, gate_root=PurePosixPath("/opt/agentguard")
)
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


def wrap(body: str) -> str:
    return 'policy "t" {\n' + body + "\n}\n"


# A small permissive policy for sequences: anything in the workspace is fine, chdir anywhere is
# fine, and reading the system zone is denied, so a relative read after `cd /etc` is caught only
# if the session really moved.
MOVING = """
  zone system ["/etc/**"]
  R4 allow read | write | delete where zone == workspace
  R4 allow chdir
  R4 deny  read where zone == system
  R10 allow exec where target known
"""


# --------------------------------------------------------------------------- the shipped policy


def test_default_policy_loads_on_a_developer_machine():
    policy = load_policy_file(DEFAULT, STATE)
    assert policy.name == "workspace-confined"
    assert len(policy.expects) >= 20


@needs_bash
def test_default_policy_loads_in_the_sandbox():
    with TempDirExecutor() as box:
        load_policy_file(DEFAULT, box.initial_state())


@needs_bash
def test_default_policy_loads_with_the_checkout_as_gate_root():
    with TempDirExecutor() as box:
        state = box.initial_state(gate_root=checkout_root())
        assert state.gate_root.is_absolute() and not state.workspace.is_relative_to(state.gate_root)
        load_policy_file(DEFAULT, state)


# --------------------------------------------------------------------------- refusing a policy


def test_a_file_with_errors_is_refused_with_every_error():
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(wrap("R4 deny remove\nR3 allow interpret"), STATE)
    assert len(caught.value.errors) == 2 and caught.value.failures == ()
    assert "line 2" in str(caught.value)


def test_a_policy_that_fails_its_own_test_is_refused():
    src = wrap(
        'R4 allow read where zone == workspace\nR10 allow exec where target known\nexpect deny "cat x"'
    )
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(src, STATE)
    (failure,) = caught.value.failures
    assert failure.verdict is Verdict.ALLOW
    assert "expect deny 'cat x': got allow" in str(failure)


def test_the_rule_named_by_a_test_must_be_among_the_reasons():
    src = wrap('R5 deny priv_change\nR4 deny priv_change\nexpect deny R5 "sudo ls"\nexpect deny R2 "sudo ls"')
    (failure,) = check_expects(_parsed(src), STATE)
    assert failure.expect.rule is RuleId.R2 and "not R2" in failure.detail


def _parsed(src: str):
    from compiler.policy_parser import parse_policy

    result = parse_policy(src)
    assert result.ok, result.errors
    return result.policy


def test_every_failing_test_is_reported():
    src = wrap('R5 deny priv_change\nexpect allow "sudo a"\nexpect allow "sudo b"\nexpect deny "sudo c"')
    assert [f.expect.command for f in check_expects(_parsed(src), STATE)] == ["sudo a", "sudo b"]


def test_escalate_is_compared_before_the_gate_refuses_it():
    # Nothing votes on an unknown program, so the policy escalates; the gate, with nobody to
    # approve, would refuse. The test is about the policy's decision.
    assert check_expects(_parsed(wrap('expect escalate "somebinary --flag"')), STATE) == []


def test_an_unparseable_command_is_r1():
    assert check_expects(_parsed(wrap('expect deny R1 "if true; then :; fi"')), STATE) == []


# --------------------------------------------------------------------------- sequences


def test_an_allowed_cd_in_after_moves_the_session():
    src = wrap(MOVING + '\nexpect deny R4 "cat passwd" after "cd /etc"\nexpect allow "cat passwd"')
    assert check_expects(_parsed(src), STATE) == []


def test_a_refused_cd_in_after_leaves_the_session_where_it_was():
    src = wrap(MOVING + '\nR4 deny chdir where zone == system\nexpect allow "cat passwd" after "cd /etc"')
    assert check_expects(_parsed(src), STATE) == []


def test_a_refusal_in_after_is_in_the_history_for_r9():
    src = wrap(
        'zone system ["/etc/**"]\nR4 deny write where zone == system\n'
        "R9 deny any where repeats denied target\n"
        'R10 allow exec where target known\nexpect deny R9 "echo x > /etc/motd" after "echo y > /etc/motd"'
    )
    assert check_expects(_parsed(src), STATE) == []


def test_each_test_starts_from_a_clean_history():
    src = wrap(
        "R5 deny priv_change\nR9 deny any where repeats denied target\n"
        'expect deny R5 "sudo ls"\nexpect deny R5 "sudo ls"'
    )
    history_state = load_policy(src, STATE)
    assert history_state is not None


# --------------------------------------------------------------------------- nothing runs


def test_predicted_cwd_follows_the_resolver():
    assert predicted_cwd(parse_source("cd sub && cd deeper"), STATE) == WS / "sub" / "deeper"
    assert predicted_cwd(parse_source("cd a; cd b"), STATE) == WS / "a" / "b"  # the success path
    assert predicted_cwd(parse_source("cd a || cd b"), STATE) is None  # either one may have succeeded
    assert predicted_cwd(parse_source("(cd sub)"), STATE) == WS  # a subshell moves nothing
    assert predicted_cwd(parse_source("cd sub &"), STATE) is None
    assert predicted_cwd(parse_source("true"), STATE) == WS


def test_nothing_is_executed_while_testing(tmp_path, monkeypatch):
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError("a policy test tried to run a process")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    load_policy_file(DEFAULT, STATE)
