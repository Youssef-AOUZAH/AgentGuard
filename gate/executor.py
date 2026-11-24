"""The sandboxed executor: runs an emitted command in a throwaway directory and reports what changed.

Takes in the canonical command from `compiler/emit.py` and the session state, and returns an
`ExecResult` (seam S8 in `docs/interfaces.md`). Together with `gate/container.py` it is the only
code in the project that runs a shell on purpose, which is why it lives in `gate/` and not in
`compiler/` (see the hard rules in `AGENTS.md`).

There are two backends with the same interface. `TempDirExecutor`, here, runs on the host in a
temporary directory: fast, and fine for tests and for commands the policy already allowed.
`ContainerExecutor`, in `gate/container.py`, runs inside a Docker container with no network, as
an unprivileged user: the one to use for the bypass corpus and agent experiments. This module also
holds what the two share: the script around the command, the snapshot format, and the mapping
from a snapshot difference to effects.

**The sandbox.** `TempDirExecutor` creates a fresh directory with three roots inside it,
`workspace/`, `home/` and `tmp/`, and a private `.gate/` directory for its own files. The session's
workspace and home are those directories, named the way bash names them (on Windows, Git Bash
calls the temporary directory `/tmp`, so the names come from asking bash with `pwd -P`). `HOME`
and `TMPDIR` point into the sandbox, so `~` and temporary files land there too.

A temporary directory confines nothing on its own: an allowed command can still name an absolute
path outside it. The policy is what keeps commands inside; this sandbox only makes sure that the
files a policy mistake would damage are throwaway ones, and that the damage is visible in the
snapshot. For anything the policy has not vetted, use the container.

**How a command runs.** Each command runs in a fresh `bash --noprofile --norc`, reading a script
file rather than `-c`, so no quoting crosses a process boundary and the command's standard input is
not the script. The script is three lines of our own followed by the emitted command
(`command_script`):

    builtin cd -- '<session cwd>' || builtin exit 125
    builtin trap 'builtin pwd -P >'"'"'<.gate/cwd>'"'"'' EXIT
    <emitted command>

The session's tracked variables with known values are passed in the environment, and nothing
else from the developer's environment is, except `PATH` and, on Windows, the few variables
Windows programs need to start. So the shell sees exactly the variables the analysis saw, which is
what makes the session state the truth rather than a guess about a long-lived shell: a variable
the session marks unknown is simply absent when the next command runs.

**What it observes.** Before and after the command, it snapshots the three roots without
following symlinks, and `diff` maps the difference into `Effect` records: created entries are
`WRITE`, removed ones `DELETE`, a file that grew with its old content as a prefix is `APPEND`, any
other change of content or type is `WRITE` (a type change is also a `DELETE`), and gaining an
execute, setuid or setgid bit is `PRIV_CHANGE` (only where execute bits exist: not on a Windows
host). Every observed effect has a `Known` resolution, a target under one of the roots, and the
executed `Script` as its origin. `OBSERVABLE_KINDS` in `gate/types.py` lists these kinds; nothing
else can be observed this way.

**What it reports about the working directory.** The exit trap writes `pwd -P` to a file outside
the roots, and `ExecResult.cwd` is that path. If the command leaves without running the trap
(`exec`, `trap - EXIT`, being killed), `cwd` is None and the session keeps the directory it had.

Deliberately not handled here: network isolation, resource limits beyond a wall-clock timeout, and
processes the command leaves running in the background after it returns. The container handles
all three.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from compiler.syntax import Script
from compiler.types import Effect, EffectKind, Known, SessionState
from gate.types import ExecResult

DEFAULT_TIMEOUT = 30.0
DEFAULT_OUTPUT_LIMIT = 64 * 1024
HASH_LIMIT = 8 * 1024 * 1024  # files above this are compared by size and mtime, not content

_PRIV_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_ISUID | stat.S_ISGID
_WINDOWS_VARIABLES = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")


def quote(text: str) -> str:
    """Single-quote `text` for bash. Only for paths and text the gate writes itself."""
    return "'" + text.replace("'", "'\\''") + "'"


def command_script(emitted: str, cwd: PurePosixPath, cwd_file: PurePosixPath) -> str:
    """The script a backend runs: our three lines, then the emitted command. Shared by every
    executor so they agree on how the working directory is set and reported."""
    report = "builtin pwd -P >" + quote(str(cwd_file))
    return (
        f"builtin cd -- {quote(str(cwd))} || builtin exit 125\nbuiltin trap {quote(report)} EXIT\n{emitted}\n"
    )


@dataclass(frozen=True, slots=True)
class Entry:
    """One path in a snapshot."""

    kind: str  # "f" file, "d" directory, "l" symlink, "o" other
    size: int
    mode: int
    digest: str  # content hash, link target, or size-and-mtime for large files


# A snapshot maps each path under the observed roots, as bash names it, to what was there.
Snapshot = dict[PurePosixPath, Entry]

# Given a path and a length, the hash of the first `length` bytes of that file as it is now. Used
# only to tell an append from a rewrite, so each backend supplies its own way to read the file.
PrefixHash = Callable[[PurePosixPath, int], str]


class TempDirExecutor:
    """Runs commands in a throwaway directory tree. Use as a context manager, or call `close`."""

    def __init__(
        self,
        *,
        bash: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
    ) -> None:
        found = bash or shutil.which("bash")
        if found is None:
            raise RuntimeError("the executor needs bash, and none was found on PATH")
        self.bash = found
        self.timeout = timeout
        self.output_limit = output_limit
        self.root = Path(tempfile.mkdtemp(prefix="agentguard-"))
        self._real: dict[str, Path] = {}
        self._posix: dict[str, PurePosixPath] = {}
        for name in ("workspace", "home", "tmp", ".gate"):
            real = self.root / name
            real.mkdir()
            self._real[name] = real
            self._posix[name] = self._bash_name(real)

    # ------------------------------------------------------------------ the sandbox's roots

    @property
    def workspace(self) -> PurePosixPath:
        return self._posix["workspace"]

    @property
    def home(self) -> PurePosixPath:
        return self._posix["home"]

    @property
    def temp(self) -> PurePosixPath:
        return self._posix["tmp"]

    def real_path(self, path: PurePosixPath) -> Path | None:
        """The host path for a bash path under one of the roots, or None if it is outside them.
        For tests and for the bench, which need to put files in place before a run."""
        for name in ("workspace", "home", "tmp"):
            posix = self._posix[name]
            if path == posix or path.is_relative_to(posix):
                return self._real[name].joinpath(*path.relative_to(posix).parts)
        return None

    def initial_state(self) -> SessionState:
        """A fresh session: working directory at the workspace root, no variables, no history."""
        return SessionState(
            cwd=self.workspace, home=self.home, workspace=self.workspace, gate_root=self._posix[".gate"]
        )

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> TempDirExecutor:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ running a command

    def run(self, emitted: str, state: SessionState, origin: Script) -> ExecResult:
        gate_dir = self._real[".gate"]
        cwd_file = gate_dir / "cwd"
        cwd_file.unlink(missing_ok=True)
        script = command_script(emitted, state.cwd, self._posix[".gate"] / "cwd")
        (gate_dir / "command.sh").write_bytes(script.encode("utf-8"))

        before = self._snapshot()
        start = time.perf_counter()
        process = subprocess.Popen(
            [self.bash, "--noprofile", "--norc", str(self._posix[".gate"] / "command.sh")],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self._real["workspace"],
            env=self._environment(state),
            start_new_session=os.name == "posix",
        )
        timed_out = False
        try:
            out, err = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(process)
            out, err = process.communicate()
        duration = time.perf_counter() - start
        after = self._snapshot()

        stdout, cut_out = decode_output(out, self.output_limit)
        stderr, cut_err = decode_output(err, self.output_limit)
        try:
            reported = cwd_file.read_bytes()
        except OSError:
            reported = None
        return ExecResult(
            exit_code=None if timed_out else process.returncode,
            stdout=stdout,
            stderr=stderr,
            observed=frozenset(diff(before, after, origin, self._prefix_hash, posix_bits=os.name == "posix")),
            cwd=parse_cwd(reported),
            duration=duration,
            timed_out=timed_out,
            truncated=cut_out or cut_err,
        )

    def _environment(self, state: SessionState) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(state.home),
            "TMPDIR": str(self.temp),
            "LC_ALL": "C.UTF-8",
        }
        if os.name == "nt":
            env.update({k: os.environ[k] for k in _WINDOWS_VARIABLES if k in os.environ})
        env.update(known_variables(state))
        return env

    def _kill(self, process: subprocess.Popen[bytes]) -> None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
        process.kill()

    def _bash_name(self, real: Path) -> PurePosixPath:
        """What bash calls a host directory. Asked rather than computed, because Git Bash on
        Windows maps paths in ways only it knows (the temporary directory becomes `/tmp`)."""
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", "builtin pwd -P"],
            cwd=real,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
        )
        return PurePosixPath(result.stdout.decode("utf-8").rstrip("\n"))

    # ------------------------------------------------------------------ observing changes

    def _snapshot(self) -> Snapshot:
        snap: Snapshot = {}
        for name in ("workspace", "home", "tmp"):
            real_root, posix_root = self._real[name], self._posix[name]
            for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
                here = Path(dirpath)
                for entry in dirnames + filenames:
                    real = here / entry
                    snap[posix_root.joinpath(*real.relative_to(real_root).parts)] = _entry(real)
        return snap

    def _prefix_hash(self, path: PurePosixPath, length: int) -> str:
        real = self.real_path(path)
        return _hash(real, length) if real is not None else "outside"


# ---------------------------------------------------------------------- shared by every backend


def known_variables(state: SessionState) -> dict[str, str]:
    """The session variables a command's environment carries: those with a known value."""
    return {n: v for n, v in state.variables.items() if isinstance(v, str) and "\0" not in v}


def decode_output(data: bytes, limit: int) -> tuple[str, bool]:
    """Command output as text, cut to `limit` characters, and whether it was cut."""
    text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit], True
    return text, False


def diff(
    before: Snapshot, after: Snapshot, origin: Script, prefix_hash: PrefixHash, *, posix_bits: bool
) -> list[Effect]:
    """The effects that turn `before` into `after`; see the module docstring for the mapping.
    `posix_bits` says whether execute bits mean anything where the snapshots were taken."""

    def priv(entry: Entry) -> int:
        return _priv(entry) if posix_bits else 0

    def effect(kind: EffectKind, target: PurePosixPath) -> Effect:
        return Effect(kind, target, Known(), origin)

    effects = [effect(EffectKind.DELETE, path) for path in before.keys() - after.keys()]
    for path in after.keys() - before.keys():
        effects.append(effect(EffectKind.WRITE, path))
        if priv(after[path]):
            effects.append(effect(EffectKind.PRIV_CHANGE, path))
    for path in before.keys() & after.keys():
        old, new = before[path], after[path]
        if old.kind != new.kind:
            effects += [effect(EffectKind.DELETE, path), effect(EffectKind.WRITE, path)]
            continue
        if old.digest != new.digest and new.kind != "d":
            grew = new.kind == "f" and new.size > old.size and not old.digest.startswith("large:")
            appended = grew and prefix_hash(path, old.size) == old.digest
            effects.append(effect(EffectKind.APPEND if appended else EffectKind.WRITE, path))
        if priv(new) & ~priv(old):
            effects.append(effect(EffectKind.PRIV_CHANGE, path))
    return effects


def parse_cwd(data: bytes | None) -> PurePosixPath | None:
    """The directory the exit trap reported, or None if it did not run or wrote nonsense."""
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.endswith("\n") or "\n" in text[:-1]:
        return None
    cwd = PurePosixPath(text[:-1])
    if not cwd.is_absolute() or ".." in cwd.parts or str(cwd).startswith("//"):
        return None
    return cwd


def _entry(path: Path) -> Entry:
    try:
        info = path.lstat()
    except OSError:
        return Entry("o", 0, 0, "vanished")
    if stat.S_ISLNK(info.st_mode):
        try:
            return Entry("l", 0, info.st_mode, os.readlink(path))
        except OSError:
            return Entry("l", 0, info.st_mode, "unreadable")
    if stat.S_ISDIR(info.st_mode):
        return Entry("d", 0, info.st_mode, "")
    if not stat.S_ISREG(info.st_mode):
        return Entry("o", 0, info.st_mode, "")
    if info.st_size > HASH_LIMIT:
        return Entry("f", info.st_size, info.st_mode, f"large:{info.st_size}:{info.st_mtime_ns}")
    return Entry("f", info.st_size, info.st_mode, _hash(path, info.st_size))


def _hash(path: Path, length: int) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            digest.update(handle.read(length))
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def _priv(entry: Entry) -> int:
    """The privilege bits an entry has that matter. A directory's execute bits are how it is
    searched, not a grant, so only setuid and setgid count there."""
    if entry.kind == "l":
        return 0
    bits = entry.mode & _PRIV_BITS
    return bits & (stat.S_ISUID | stat.S_ISGID) if entry.kind == "d" else bits
