"""The knowledge table: what each known program does, given its arguments.

Takes in a program name and its arguments as the resolver expanded them. Gives back a list of
`Want`s, abstract effects that `compiler/effects.py` turns into `Effect`s once it knows the
working directory. A head that is not in `TABLE` is the caller's business: it yields a single
`UNKNOWN` effect, never nothing (`docs/policy-rules.md` §1).

The table is the largest assumption in the system (`docs/threat-model.md`, "The knowledge
table"), so every entry fails towards an effect, never towards silence:

- **Options are parsed, not ignored.** An option the entry does not list makes the command
  `UNKNOWN`: GNU tools accept any unambiguous prefix of a long option, so `sort --outp=f` is
  `sort --output=f` and writes a file. Prefixes are matched here the same way.
- **An argument we cannot see may be an option.** If a word is unresolved, or is a glob that can
  match a name starting with `-`, before `--`, then for each *dangerous* option of the entry (one
  that adds a target or an effect kind), the entry also reports that effect with an unknown
  target. `sort $X` may be `sort -o /etc/passwd`, so it carries a `WRITE` to an unknown path.
- **Indirect effects are not modelled.** `python t.py` is an `EXEC` of python and a `READ` of
  `t.py`. What `t.py` does is left to the sandbox, as the threat model says.

The heads are the starting list in `docs/policy-rules.md` §1, minus the ones whose effects depend
on configuration we cannot see. `pip`, `npm`, `make`, `pytest`, `docker`, `ssh`, `scp`, `tar` and
`zip` are deliberately absent for now and so escalate under R10. For example, `pytest
--basetemp=dir` deletes `dir`, and `pip install` writes wherever its configuration says. Each
should be added with its options modelled, driven by the benign corpus.
"""

from compiler.knowledge import files, network, shell  # noqa: F401  (each registers its entries)
from compiler.knowledge.base import (
    TABLE,
    Arg,
    AtHome,
    OnPath,
    OnTarget,
    Opts,
    Parsed,
    Run,
    Want,
    parse,
    unknown,
)
from compiler.knowledge.network import InRepo, host_of

__all__ = [
    "TABLE",
    "Arg",
    "AtHome",
    "InRepo",
    "OnPath",
    "OnTarget",
    "Opts",
    "Parsed",
    "Run",
    "Want",
    "host_of",
    "parse",
    "unknown",
]
