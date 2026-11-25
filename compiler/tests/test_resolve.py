"""Tests for the resolver in `compiler/resolve.py`.

Four groups:

1. Word expansion: tildes, tracked variables, field splitting, brace expansion, globs, and the
   honest `Unresolved` for everything else.
2. Session changes inside one script: `cd`, assignments, and everything that must make the
   state unknown rather than stale.
3. The argv oracle: for words the resolver can expand, bash passes exactly the same fields. This
   is the narrow exception in AGENTS.md: generated words only, `printf` only, in a temporary
   directory, in a test module.
4. Properties: resolving never raises on a parsed script and never changes the session.
"""

import shutil
import subprocess
from pathlib import PurePosixPath

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from compiler.parser import parse_source
from compiler.resolve import MAX_CWDS, Field, Fields, Unresolved, logical_join, resolve
from compiler.syntax import LexError, ParseError
from compiler.types import SessionState, Unknown

WS = PurePosixPath("/work/project")
HOME = PurePosixPath("/home/dev")
GATE = PurePosixPath("/opt/agentguard")


def state(**variables) -> SessionState:
    return SessionState(cwd=WS, home=HOME, workspace=WS, gate_root=GATE, variables=variables)


def commands(src: str, st: SessionState | None = None):
    return resolve(parse_source(src), st or state()).commands


def argv(src: str, st: SessionState | None = None, index: int = -1):
    """The texts bash would pass for the `index`-th command of `src`, or its Unresolved."""
    value = commands(src, st)[index].argv
    return value if isinstance(value, Unresolved) else [f.text for f in value]


def cwd(src: str, st: SessionState | None = None, index: int = -1):
    return commands(src, st)[index].cwd


# --------------------------------------------------------------------------- word expansion


def test_literal_words_pass_through():
    assert argv("ls -la 'a b' \"c\" d\\ e") == ["ls", "-la", "a b", "c", "d e"]


def test_tilde_uses_the_session_home():
    assert argv("cat ~ ~/x a~b") == ["cat", "/home/dev", "/home/dev/x", "a~b"]


def test_tilde_follows_a_tracked_home():
    # docs/interfaces.md S3: bash's tilde follows $HOME, not state.home.
    assert argv("cat ~/x", state(HOME="/other")) == ["cat", "/other/x"]


def test_tilde_with_unknown_home_is_unresolved():
    assert isinstance(argv("cat ~/x", state(HOME=Unknown("from $(...)"))), Unresolved)


def test_tilde_user_is_unresolved():
    assert isinstance(argv("cat ~root/x"), Unresolved)


def test_tracked_variable_expands():
    assert argv("cat $D/passwd ${D}/group", state(D="/etc")) == ["cat", "/etc/passwd", "/etc/group"]


def test_untracked_variable_is_unresolved_not_empty():
    # Never guessed and never read from os.environ (docs/interfaces.md S3).
    value = argv("rm -rf $UNTRACKED")
    assert isinstance(value, Unresolved) and "not tracked" in value.reason


def test_unknown_variable_keeps_its_reason():
    value = argv("rm $X", state(X=Unknown("assigned from $(cat list)")))
    assert isinstance(value, Unresolved) and "cat list" in value.reason


@pytest.mark.parametrize("word", ["${X:-d}", "${#X}", "$1", "$@", "${!X}", "$(ls)", "$((1+2))"])
def test_operator_forms_and_substitutions_are_unresolved(word):
    assert isinstance(argv(f"echo {word}", state(X="v")), Unresolved)


def test_unquoted_expansion_is_split_and_quoted_is_not():
    st = state(S="a  b\tc")
    assert argv('echo $S "$S"', st) == ["echo", "a", "b", "c", "a  b\tc"]


def test_unquoted_empty_expansion_vanishes_but_quoted_empty_stays():
    st = state(E="")
    assert argv("echo $E \"$E\" '' x", st) == ["echo", "", "", "x"]


def test_empty_variable_as_command_name_leaves_the_next_word_as_head():
    assert commands("$E ls", state(E=""))[0].head == "ls"


def test_custom_ifs_keeps_empty_fields_between_hard_delimiters():
    assert argv("printf %s $X", state(IFS=",", X="a,b,,c,")) == ["printf", "%s", "a", "b", "", "c"]


def test_unknown_ifs_makes_unquoted_expansions_unresolved():
    st = state(IFS=Unknown("set by read"), X="a b")
    assert isinstance(argv("echo $X", st), Unresolved)
    assert argv('echo "$X" lit', st) == ["echo", "a b", "lit"]


def test_unquoted_expansion_with_glob_characters_is_a_pattern():
    (field,) = commands("rm $G", state(G="*.o"))[0].argv[1:]
    assert field == Field("*.o", glob_at=0)


def test_glob_records_where_the_pattern_starts():
    fields = commands("rm build/*.o 'q*' b\\*")[0].argv[1:]
    assert fields == (Field("build/*.o", glob_at=6), Field("q*"), Field("b*"))


def test_brace_expansion():
    assert argv("echo x{a,b}y {1..3} {01..03} {a..c} {5..1..2} {,z}") == [
        "echo", "xay", "xby", "1", "2", "3", "01", "02", "03", "a", "b", "c", "5", "3", "1", "z",
    ]  # fmt: skip


@pytest.mark.parametrize("word", ["{~,x}/a", "{*,x}", "{a,{b,c}}", "{Z..a}", "{1..100000}", "{-01..2}"])
def test_brace_forms_we_do_not_interpret_are_unresolved(word):
    # `{~,x}` and `{*,x}` matter: bash tilde-expands and globs the items after brace expansion.
    assert isinstance(argv(f"echo {word}"), Unresolved)


def test_assignment_value_is_not_split_or_globbed():
    (cmd,) = commands("A='x  y'; B=$A*", state())[1:]
    assert cmd.env == (("B", "x  y*"),)


def test_redirect_target_must_be_one_field():
    (cmd,) = commands("echo hi > $F", state(F="a b"))
    assert isinstance(cmd.redirects[0].target, Unresolved)
    (cmd,) = commands("echo hi > ~/log")
    assert cmd.redirects[0].target == Field("/home/dev/log")


def test_heredoc_has_no_target():
    (cmd,) = commands("cat <<'EOF'\nbody\nEOF\n")
    assert cmd.redirects[0].target is None


# --------------------------------------------------------------------------- session changes in one script


def test_cd_then_and_runs_in_the_new_directory():
    assert cwd("cd build && rm *") == (WS / "build",)


def test_cd_then_semicolon_may_run_in_either_directory():
    # If the cd fails, rm runs where we started.
    assert cwd("cd build; rm *") == (WS, WS / "build")


def test_cd_then_or_runs_only_where_we_started():
    assert cwd("cd /tmp || cat x") == (WS,)


def test_cd_is_logical():
    assert cwd("cd ../other && ls") == (PurePosixPath("/work/other"),)
    assert cwd("cd /a/./b/../c && ls") == (PurePosixPath("/a/c"),)


def test_bare_cd_goes_home():
    assert cwd("cd && ls") == (HOME,)


def test_cd_we_cannot_follow_makes_cwd_unknown():
    for src in ["cd $Q && ls", "cd - && ls", "popd && ls", "cd a b && ls", "cd * && ls"]:
        assert isinstance(cwd(src), Unknown), src


def test_physical_cd_is_not_followed():
    # -P resolves symlinks, so the textual path can be wrong.
    assert isinstance(cwd("cd -P link/.. && rm x"), Unknown)


def test_cd_makes_pwd_and_oldpwd_unknown():
    st = state(PWD="/work/project", OLDPWD="/old")
    assert isinstance(argv('cd /tmp && echo "$PWD"', st), Unresolved)
    assert isinstance(argv('cd /tmp && echo "$OLDPWD"', st), Unresolved)


def test_cd_with_cdpath_set_is_not_followed():
    assert isinstance(cwd("cd sub && ls", state(CDPATH="/elsewhere")), Unknown)


def test_absolute_cd_from_unknown_cwd_is_known_again():
    assert cwd("eval x; cd /tmp && ls") == (PurePosixPath("/tmp"),)


def test_subshell_cd_does_not_leak():
    assert cwd("(cd /etc); cat x") == (WS,)
    assert cwd("(cd /etc && cat x)", index=1) == (PurePosixPath("/etc"),)


def test_pipeline_commands_run_in_child_shells():
    assert cwd("cd /etc | true; ls") == (WS,)


def test_backgrounded_statement_changes_nothing():
    assert cwd("cd /etc & ls") == (WS,)
    assert commands("cd /etc & ls")[0].background


def test_too_many_possible_directories_is_unknown():
    src = "; ".join(f"cd d{i}" for i in range(MAX_CWDS + 1)) + "; ls"
    assert isinstance(cwd(src), Unknown)


def test_bare_assignment_persists_and_prefix_assignment_does_not():
    assert argv("D=/tmp; cat $D", state(D="/etc")) == ["cat", "/tmp"]
    assert argv("D=/tmp cat $D", state(D="/etc")) == ["cat", "/etc"]
    assert argv("D=/tmp true; cat $D", state(D="/etc")) == ["cat", "/etc"]


def test_assignment_on_one_branch_only_is_unknown():
    assert isinstance(argv("true && D=/tmp; cat $D", state(D="/etc")), Unresolved)


def test_ifs_split_after_assignment_in_same_script():
    # The three-statement form of the IFS example in docs/policy-rules.md section 7.
    assert argv("IFS=,; CMD=rm,-rf,/; $CMD") == ["rm", "-rf", "/"]


def test_prefix_ifs_does_not_affect_the_same_command():
    # `IFS=, CMD=... $CMD` runs nothing: $CMD expands before the assignments apply.
    value = argv("IFS=, CMD=rm,-rf,/ $CMD")
    assert isinstance(value, Unresolved)


@pytest.mark.parametrize(
    "src",
    [
        "read D",
        "unset D",
        "export D=/x",
        "declare D",
        "mapfile D",
        "printf -v D x",
        "printf -vD x",
        "echo ${D:=x}",
    ],  # fmt: skip
)
def test_builtins_that_change_variables_invalidate_them(src):
    value = argv(f"{src}; cat $D", state(D="/etc"))
    assert isinstance(value, Unresolved), src


def test_printf_without_v_changes_nothing():
    assert argv("printf x; cat $D", state(D="/etc")) == ["cat", "/etc"]


def test_read_with_no_name_invalidates_reply():
    assert isinstance(argv("read; cat $REPLY", state(REPLY="/etc")), Unresolved)


@pytest.mark.parametrize(
    "src", ["eval cd /etc", "source f", ". f", "command cd /etc", "builtin cd /etc", "$C x"]
)
def test_opaque_commands_forget_everything(src):
    after = commands(f"{src}; cat $D", state(D="/etc", C="cd"))[-1]
    if src == "$C x":
        # $C is tracked, so this one is followed: it is `cd x`.
        assert after.cwd == (WS, WS / "x")
        return
    assert isinstance(after.cwd, Unknown)
    assert isinstance(after.argv, Unresolved)


def test_untracked_variable_still_unknown_after_eval():
    assert isinstance(argv("eval x; cat $NEW"), Unresolved)


def test_shopt_makes_later_globs_unresolved():
    # `shopt -u globskipdots` would let `.*` match `..`.
    assert isinstance(argv("shopt -u globskipdots; rm -rf .*"), Unresolved)
    assert argv("shopt -s nullglob; echo x") == ["echo", "x"]


def test_command_substitution_commands_are_resolved_first_in_a_child_shell():
    resolved = commands("echo $(cd /; ls $D) > $D/o", state(D="/etc"))
    assert [c.depth for c in resolved] == [1, 1, 0]
    assert resolved[1].cwd == (PurePosixPath("/"), WS)
    assert resolved[2].cwd == (WS,)
    assert resolved[2].redirects[0].target == Field("/etc/o")


def test_state_is_not_mutated():
    st = state(D="/etc")
    resolve(parse_source("D=/tmp; cd /; unset D"), st)
    assert st.cwd == WS and st.variables == {"D": "/etc"}


def test_logical_join():
    assert logical_join(WS, "..") == PurePosixPath("/work")
    assert logical_join(PurePosixPath("/"), "../..") == PurePosixPath("/")
    assert logical_join(WS, "/x//y/") == PurePosixPath("/x/y")


# --------------------------------------------------------------------------- the argv oracle

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not installed")

_ORACLE_VARIABLES = {"S": "a  b\tc", "E": "", "G": "*.o", "P": " lead trail ", "C": "x,y,,z"}
_ORACLE_WORDS = [
    "plain",
    "'a  b'",
    '"$S"',
    "$S",
    "$E",
    '"$E"',
    "$E''",
    "x$S.y",
    "$P",
    '"$P"$P',
    "$G",
    "'$G'",
    "*.nomatch",
    "pre{a,b}post",
    "{1..4..2}",
    "{08..11}",
    "~/x",
    "a=~/x",
    "$'tab\\there'",
]


def _bash_argv(words: str, cwd, ifs: str | None = None) -> list[str]:
    """What bash passes, with the same variables the resolver tracks. Over stdin, because on
    Windows `subprocess` rewrites backslashes in arguments."""
    lines = ["HOME=/home/dev"] + [f"{k}={_squote(v)}" for k, v in _ORACLE_VARIABLES.items()]
    if ifs is not None:
        lines.append(f"IFS={_squote(ifs)}")
    # A leading marker, because printf with no arguments still prints its format once.
    lines.append("printf '%s\\0' MARK " + words)
    out = subprocess.run(
        [BASH, "--noprofile", "--norc", "-s"],
        input="\n".join(lines).encode(),
        capture_output=True,
        check=True,
        cwd=cwd,
    ).stdout
    return out.decode().split("\0")[1:-1]


def _squote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _ours(words: str, ifs: str | None = None) -> list[str]:
    variables = dict(_ORACLE_VARIABLES, HOME="/home/dev")
    if ifs is not None:
        variables["IFS"] = ifs
    value = commands("printf '%s\\0' MARK " + words, state(**variables))[-1].argv
    assert not isinstance(value, Unresolved), value
    return [f.text for f in value[3:]]


@needs_bash
@pytest.mark.parametrize("word", _ORACLE_WORDS)
def test_bash_passes_the_fields_we_predict(word, tmp_path):
    # An empty directory: every glob matches nothing, so bash passes it as written.
    assert _bash_argv(word, tmp_path) == _ours(word), word


@needs_bash
@pytest.mark.parametrize("word", ["$C", '"$C"', "$C$E", "a,$C,b"])
def test_bash_splits_on_custom_ifs_as_we_do(word, tmp_path):
    assert _bash_argv(word, tmp_path, ifs=",") == _ours(word, ifs=","), word


# --------------------------------------------------------------------------- state changes we must follow
#
# From the review of #7: each script changes a variable or the directory in a way the first
# version missed. bash is asked what the last word really is (builtins and assignments only, then
# printf), and the resolver must either agree or say it does not know. A known but different
# value is the bug.

_STATE_CHANGES = [
    ("X=/tmp; E=; X=/etc $E; ", '"$X"'),
    ("x=/tmp; : $((x=5)); ", '"$x"'),
    ("x=y=5; y=/tmp; : $((x)); ", '"$y"'),
    ("i=0; y=/tmp; : ${a[i=1]}; ", '"$i"'),
    ("s=abc; i=0; : ${s: i=1}; ", '"$i"'),
    ("X=/tmp; declare -n r=X; r=/etc; ", '"$X"'),
    ("X=/tmp; let X=5; ", '"$X"'),
    ("OPTARG=/tmp; set -- -a /etc; getopts a: o; ", '"$OPTARG"'),
    ("OPTIND=7; set -- -a /etc; getopts a: o; ", '"$OPTIND"'),
]


def _bash_after(prelude: str, word: str, cwd) -> str:
    script = prelude + "printf '%s\\0' MARK " + word
    run = [BASH, "--noprofile", "--norc", "-s"]
    out = subprocess.run(run, input=script.encode(), capture_output=True, check=True, cwd=cwd).stdout
    return out.decode().split("\0")[1]


@pytest.mark.parametrize(("prelude", "word"), _STATE_CHANGES)
def test_state_changes_are_followed_or_unknown(prelude, word, tmp_path):
    value = commands(prelude + "printf '%s\\0' MARK " + word)[-1].words[-1]
    if isinstance(value, Unresolved):
        return
    predicted = [f.text for f in value.fields]
    if BASH is None:
        pytest.skip("bash is not installed")
    assert predicted == [_bash_after(prelude, word, tmp_path)], prelude


def test_empty_command_word_applies_prefix_assignments():
    # POSIX: if no command name results, the assignments affect the current shell.
    assert argv('X=/tmp; E=; X=/etc $E; echo "$X"', state()) == ["echo", "/etc"]


@pytest.mark.parametrize(
    "prelude",
    ["x=/tmp; : $((x=5)); ", "X=/tmp; declare -n r=x; r=1; ", "X=/tmp; let X=5; ", "local -rn r=X; "],
)
def test_arithmetic_namerefs_and_let_make_variables_unknown(prelude):
    assert isinstance(argv(prelude + 'echo "$x" "$X"', state(x="/tmp", X="/tmp")), Unresolved)


def test_arithmetic_on_plain_integers_keeps_other_variables():
    assert commands('n=3; y=/tmp; echo "$y" $((n+1))')[-1].words[1] == Fields((Field("/tmp"),))


def test_getopts_invalidates_optarg_and_optind():
    st = state(OPTARG="/tmp", OPTIND="1")
    assert isinstance(argv('getopts a: o; echo "$OPTARG"', st), Unresolved)
    assert isinstance(argv('getopts a: o; echo "$OPTIND"', st), Unresolved)


@pytest.mark.parametrize("rotate", ["pushd +1", "pushd -0", "popd +1"])
def test_directory_stack_rotation_is_not_followed(rotate):
    # bash: `cd /tmp; pushd /etc; pushd +1` ends in /tmp, not /etc/+1.
    assert isinstance(cwd(f"cd /tmp && pushd /etc && {rotate} && ls"), Unknown)


# --------------------------------------------------------------------------- properties

_FRAGMENTS = [
    "cd", "/tmp", "..", "x", "$D", '"$D"', "$E", "~", "*", "{a,b}", "{1..3}", "&&", "||", ";", "|", "!",
    "(", ")", "A=1", "D=$(pwd)", "IFS=,", "read", "unset", "eval", "${D:=x}", "$(cd /)", "&", ">", "f",
]  # fmt: skip


@given(st.lists(st.sampled_from(_FRAGMENTS), max_size=14).map(" ".join))
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_resolve_never_raises_on_a_parsed_script(src):
    try:
        script = parse_source(src)
    except (LexError, ParseError):
        return
    st_ = state(D="/etc", E="")
    resolved = resolve(script, st_)
    for command in resolved.commands:
        assert isinstance(command.cwd, Unknown) or all(p.is_absolute() for p in command.cwd)
        for value in command.words:
            assert isinstance(value, (Fields, Unresolved))
    assert st_.cwd == WS and dict(st_.variables) == {"D": "/etc", "E": ""}
