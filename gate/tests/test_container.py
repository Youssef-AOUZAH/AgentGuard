"""Tests for the container executor, against a real Docker daemon.

Skipped unless Docker is running with Linux containers. Each test gets a fresh container, and every
command run here is written in this file. What is checked is what the container adds over the
temporary directory: no network, an unprivileged user, a clean environment, nothing left running,
and the host untouched; plus the same observations and session behaviour as the other backend.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from compiler.types import EffectKind, Unknown, Verdict
from gate.container import ContainerExecutor, docker_available
from gate.gate import Gate

pytestmark = pytest.mark.skipif(
    not docker_available(), reason="Docker with Linux containers is not available"
)


class AllowAll:
    def analyze(self, script, state):
        from compiler.types import Decision

        return frozenset(), Decision(Verdict.ALLOW)


@pytest.fixture
def box():
    with ContainerExecutor(timeout=5) as executor:
        yield executor


def make_gate(box) -> Gate:
    return Gate(box, box.initial_state(), analyzer=AllowAll())


def kinds(outcome) -> set[tuple[EffectKind, PurePosixPath]]:
    return {(e.kind, e.target) for e in outcome.result.observed}


def ws(*parts: str) -> PurePosixPath:
    return ContainerExecutor.workspace.joinpath(*parts)


def test_runs_as_nobody_in_the_workspace(box):
    outcome = make_gate(box).submit("id -u; pwd; echo ~")
    assert outcome.result.stdout == "65534\n/sandbox/workspace\n/sandbox/home\n"


def test_has_no_network(box):
    outcome = make_gate(box).submit("ls /sys/class/net")
    assert outcome.result.stdout.split() == ["lo"]


def test_environment_is_only_what_the_gate_passes(box):
    gate = make_gate(box)
    gate.submit("X=kept")
    names = {line.split("=", 1)[0] for line in gate.submit("env").result.stdout.splitlines()}
    assert names <= {"PATH", "HOME", "TMPDIR", "LC_ALL", "X", "PWD", "SHLVL", "_", "OLDPWD"}
    assert "X" in names


def test_cannot_write_outside_the_sandbox(box):
    outcome = make_gate(box).submit("touch /etc/agentguard; touch /usr/agentguard")
    assert outcome.result.exit_code != 0
    assert "Permission denied" in outcome.result.stderr
    assert outcome.result.observed == frozenset()


def test_observes_write_append_delete_and_privilege(box):
    gate = make_gate(box)
    first = gate.submit("echo one > a; echo one > b; echo one > c; mkdir d")
    assert kinds(first) == {(EffectKind.WRITE, ws(n)) for n in ("a", "b", "c", "d")}
    second = gate.submit("echo two >> a; echo new > b; rm c; chmod +x b; touch ~/h")
    assert kinds(second) == {
        (EffectKind.APPEND, ws("a")),
        (EffectKind.WRITE, ws("b")),
        (EffectKind.PRIV_CHANGE, ws("b")),
        (EffectKind.DELETE, ws("c")),
        (EffectKind.WRITE, PurePosixPath("/sandbox/home/h")),
    }


def test_session_follows_cd_and_variables(box):
    gate = make_gate(box)
    gate.submit("mkdir sub; cd sub; A='x y'; B=$(date)")
    assert gate.state.cwd == ws("sub")
    assert gate.state.variables["A"] == "x y" and isinstance(gate.state.variables["B"], Unknown)
    assert gate.submit('pwd; echo "$A|$B"').result.stdout == "/sandbox/workspace/sub\nx y|\n"


def test_timeout_is_reported(box):
    outcome = make_gate(box).submit("sleep 30")
    assert outcome.result.timed_out and outcome.result.exit_code is None
    assert outcome.result.duration < 15


def test_nothing_outlives_its_turn(box):
    gate = make_gate(box)
    outcome = gate.submit("sleep 300 > /dev/null 2>&1 &")
    assert outcome.result.duration < 4
    assert _sleepers(box) == 0


def _sleepers(box) -> int:
    """How many `sleep 300` processes are alive in the container, counted as root from outside."""
    count = """
import os
n = 0
for p in filter(str.isdigit, os.listdir('/proc')):
    try:
        n += open(f'/proc/{p}/cmdline', 'rb').read().split(bytes(1))[:2] == [b'sleep', b'300']
    except OSError:
        pass
print(n)
"""
    return int(box._exec_root(["python3", "-c", count], stdin=b"").stdout)


def test_the_probe_sees_a_live_process(box):
    """Guards the test above against passing because the probe is blind."""
    box._docker("exec", "--detach", "--user", "65534", box.name, "sleep", "300")
    import time

    time.sleep(1)
    assert _sleepers(box) == 1


def test_put_file_seeds_the_sandbox(box):
    box.put_file(ws("seed", "canary.txt"), b"secret-canary\n")
    outcome = make_gate(box).submit("cat seed/canary.txt")
    assert outcome.result.stdout == "secret-canary\n"


def test_output_is_cut_at_the_limit(box):
    box.output_limit = 10
    outcome = make_gate(box).submit("echo 0123456789abcdef")
    assert outcome.result.stdout == "0123456789" and outcome.result.truncated


def test_container_is_removed_on_close():
    executor = ContainerExecutor()
    name = executor.name
    executor.close()
    gone = executor._docker("inspect", name)
    assert gone.returncode != 0
