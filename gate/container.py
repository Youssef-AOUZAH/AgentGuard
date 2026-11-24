"""The container executor: runs an emitted command inside a Docker container (piece 3a).

Same interface and same `ExecResult` as `TempDirExecutor` in `gate/executor.py`, and the same
script around the command, snapshot format and effect mapping, which live there. What changes is
where the command runs, and that is what makes this the backend for the bypass corpus and the
agent experiments, where commands are destructive on purpose (`AGENTS.md`, hard rules).

**The container.** One long-lived container per executor, started from `image` with:

- no network (`--network none`), so a forbidden `NET_OUT` fails instead of reaching anyone;
- a memory limit, a process limit and one CPU, so `yes > f` or a fork loop hurts only itself;
- every capability dropped except the three the gate's own setup needs as root, and
  `no-new-privileges`, so a setuid binary cannot raise anyone's privileges;
- nothing from the host mounted: the sandbox's files live only in the container's filesystem,
  under `/sandbox/workspace`, `/sandbox/home` and `/sandbox/tmp`, and vanish with it.

**Each command** runs as the unprivileged user `nobody` (65534), through `env -i`, so it sees only
`PATH`, `HOME`, `TMPDIR`, `LC_ALL` and the session's known variables, never the image's own
environment. It runs under `timeout`, which kills the command's process group when time runs out.
After it returns, every process still running as `nobody` is killed, so a command cannot leave
something behind to act later, outside the turn the policy judged.

**Observation** runs as root inside the container with the image's `python3`, using the same
snapshot format as the temporary-directory backend, so `gate.executor.diff` maps both the same way.
Execute bits are real here, so `PRIV_CHANGE` is observed even when the host is Windows.

Requirements: Docker running with Linux containers, and an image with `bash`, `python3` and
coreutils `timeout`. The default image, `python:3.12-slim`, has all three.

Deliberately not handled: the time a backgrounded command keeps its output open. A command such as
`sleep 100 &` that keeps standard output open makes the run last until the timeout, because the
output is only complete when every writer has closed it; redirecting the background command's
output avoids that. Whether `&` is allowed at all is the policy's question (a rule id is still owed).
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import time
from pathlib import PurePosixPath

from compiler.syntax import Script
from compiler.types import SessionState
from gate.executor import (
    DEFAULT_OUTPUT_LIMIT,
    DEFAULT_TIMEOUT,
    HASH_LIMIT,
    Entry,
    Snapshot,
    command_script,
    decode_output,
    diff,
    known_variables,
    parse_cwd,
)
from gate.types import ExecResult

DEFAULT_IMAGE = "python:3.12-slim"
SANDBOX_USER = "65534:65534"  # nobody
CONTAINER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_ROOT = PurePosixPath("/sandbox")
_GATE = _ROOT / ".gate"
_CWD_FILE = _GATE / "out" / "cwd"
_ROOTS = {name: _ROOT / name for name in ("workspace", "home", "tmp")}

# Runs inside the container as root. Prints one JSON object: every entry under the roots, in the
# format of gate.executor.Entry, and in "after" mode also the prefix hashes asked for on stdin and
# the working directory the command reported (hex, since it is raw bytes).
_SNAPSHOT_PY = r"""
import hashlib, json, os, stat, sys

mode, limit, cwd_file, roots = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4:]

def digest(path, length):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(length))
    except OSError:
        return "unreadable"
    return h.hexdigest()

def entry(path):
    try:
        st = os.lstat(path)
    except OSError:
        return ["o", 0, 0, "vanished"]
    m = st.st_mode
    if stat.S_ISLNK(m):
        try:
            return ["l", 0, m, os.readlink(path)]
        except OSError:
            return ["l", 0, m, "unreadable"]
    if stat.S_ISDIR(m):
        return ["d", 0, m, ""]
    if not stat.S_ISREG(m):
        return ["o", 0, m, ""]
    if st.st_size > limit:
        return ["f", st.st_size, m, "large:%d:%d" % (st.st_size, st.st_mtime_ns)]
    return ["f", st.st_size, m, digest(path, st.st_size)]

out = {"entries": {}}
for root in roots:
    for here, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(here, name)
            out["entries"][path] = entry(path)
if mode == "after":
    asked = json.load(sys.stdin)
    out["prefix"] = {p: digest(p, n) for p, n in asked.items() if os.path.isfile(p)}
    try:
        with open(cwd_file, "rb") as f:
            out["cwd"] = f.read().hex()
    except OSError:
        out["cwd"] = None
json.dump(out, sys.stdout)
"""


def docker_available(docker: str | None = None) -> bool:
    """True when a Docker daemon is reachable and runs Linux containers."""
    found = docker or shutil.which("docker")
    if found is None:
        return False
    try:
        info = subprocess.run(
            [found, "info", "--format", "{{.OSType}}"], capture_output=True, timeout=20, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return info.returncode == 0 and info.stdout.decode().strip() == "linux"


class ContainerExecutor:
    """Runs commands in a disposable Docker container. Use as a context manager, or call `close`."""

    workspace = _ROOTS["workspace"]
    home = _ROOTS["home"]
    temp = _ROOTS["tmp"]

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        docker: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        memory: str = "512m",
        pids: int = 256,
    ) -> None:
        found = docker or shutil.which("docker")
        if found is None:
            raise RuntimeError("the container executor needs docker, and none was found on PATH")
        self.docker = found
        self.timeout = timeout
        self.output_limit = output_limit
        self.name = f"agentguard-{secrets.token_hex(6)}"
        # The container exists from here on, so anything that fails below must remove it.
        started = self._docker(
            "run", "--detach", "--rm", "--name", self.name,
            "--network", "none",
            "--memory", memory, "--pids-limit", str(pids), "--cpus", "1",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
            image, "sleep", "infinity",
            timeout=600,
        )  # fmt: skip
        if started.returncode != 0:
            raise RuntimeError(f"could not start the sandbox container: {started.stderr.decode().strip()}")
        try:
            self._setup()
        except BaseException:
            self.close()
            raise

    def _setup(self) -> None:
        roots = " ".join(str(p) for p in _ROOTS.values())
        out_dir = _CWD_FILE.parent
        setup = (
            "command -v bash >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null"
            " || { echo 'the image needs bash, python3 and timeout' >&2; exit 1; }; "
            f"mkdir -p {roots} {out_dir} && chown {SANDBOX_USER} {roots} {out_dir} && "
            f"chmod 755 {_ROOT} {_GATE} && cat > {_GATE / 'snapshot.py'}"
        )
        done = self._exec_root(["sh", "-c", setup], stdin=_SNAPSHOT_PY.encode())
        if done.returncode != 0:
            raise RuntimeError(f"could not prepare the sandbox: {done.stderr.decode().strip()}")

    # ------------------------------------------------------------------ the sandbox's roots

    def initial_state(self) -> SessionState:
        return SessionState(cwd=self.workspace, home=self.home, workspace=self.workspace, gate_root=_GATE)

    def put_file(self, path: PurePosixPath, data: bytes) -> None:
        """Create a file in the sandbox as the sandbox user, for the bench to seed canaries and
        fixtures before a run. Parent directories are created."""
        put = 'mkdir -p -- "$(dirname -- "$1")" && cat > "$1"'
        done = self._docker(
            "exec",
            "--interactive",
            "--user",
            SANDBOX_USER,
            self.name,
            "sh",
            "-c",
            put,
            "sh",
            str(path),
            stdin=data,
        )
        if done.returncode != 0:
            raise RuntimeError(f"could not write {path}: {done.stderr.decode().strip()}")

    def close(self) -> None:
        self._docker("rm", "--force", self.name, timeout=60)

    def __enter__(self) -> ContainerExecutor:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ running a command

    def run(self, emitted: str, state: SessionState, origin: Script) -> ExecResult:
        script = command_script(emitted, state.cwd, _CWD_FILE)
        prepare = (
            f"cat > {_GATE / 'command.sh'} && chmod 644 {_GATE / 'command.sh'} && rm -f {_CWD_FILE} && "
            + self._snapshot_command("before")
        )
        prepared = self._exec_root(["sh", "-c", prepare], stdin=script.encode("utf-8"))
        if prepared.returncode != 0:
            raise RuntimeError(f"could not prepare the command: {prepared.stderr.decode().strip()}")
        before = _entries(json.loads(prepared.stdout))

        variables = [f"{k}={v}" for k, v in known_variables(state).items()]
        start = time.perf_counter()
        ran = self._docker(
            "exec", "--user", SANDBOX_USER, "--workdir", str(self.workspace), self.name,
            "env", "-i", f"PATH={CONTAINER_PATH}", f"HOME={state.home}", f"TMPDIR={self.temp}",
            "LC_ALL=C.UTF-8",
            *variables,
            "timeout", "--kill-after=2", str(self.timeout),
            "bash", "--noprofile", "--norc", str(_GATE / "command.sh"),
            timeout=self.timeout + 60,
        )  # fmt: skip
        duration = time.perf_counter() - start
        timed_out = ran.returncode in (124, 137) and duration >= self.timeout

        # Nothing the command started may outlive its turn.
        self._docker("exec", "--user", SANDBOX_USER, self.name, "bash", "-c", "kill -9 -1 2>/dev/null; true")

        grown = {
            str(p): e.size for p, e in before.items() if e.kind == "f" and not e.digest.startswith("large:")
        }
        observed = self._exec_root(
            ["sh", "-c", self._snapshot_command("after")], stdin=json.dumps(grown).encode()
        )
        if observed.returncode != 0:
            raise RuntimeError(f"could not observe the command: {observed.stderr.decode().strip()}")
        report = json.loads(observed.stdout)
        after = _entries(report)
        prefixes: dict[str, str] = report.get("prefix", {})

        stdout, cut_out = decode_output(ran.stdout, self.output_limit)
        stderr, cut_err = decode_output(ran.stderr, self.output_limit)
        cwd = report.get("cwd")
        return ExecResult(
            exit_code=None if timed_out else ran.returncode,
            stdout=stdout,
            stderr=stderr,
            observed=frozenset(
                diff(before, after, origin, lambda p, _n: prefixes.get(str(p), "unknown"), posix_bits=True)
            ),
            cwd=parse_cwd(bytes.fromhex(cwd) if cwd is not None else None),
            duration=duration,
            timed_out=timed_out,
            truncated=cut_out or cut_err,
        )

    # ------------------------------------------------------------------ docker plumbing

    def _snapshot_command(self, mode: str) -> str:
        roots = " ".join(str(p) for p in _ROOTS.values())
        return f"python3 {_GATE / 'snapshot.py'} {mode} {HASH_LIMIT} {_CWD_FILE} {roots}"

    def _exec_root(self, argv: list[str], *, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
        return self._docker("exec", "--interactive", "--user", "0", self.name, *argv, stdin=stdin)

    def _docker(
        self, *args: str, stdin: bytes | None = None, timeout: float = 120
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.docker, *args],
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )


def _entries(report: dict) -> Snapshot:
    return {PurePosixPath(p): Entry(k, int(s), int(m), d) for p, (k, s, m, d) in report["entries"].items()}
