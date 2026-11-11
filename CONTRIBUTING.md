# Contributing

## Branches

- `main` is protected. Nobody pushes to it directly; every change arrives through a pull request.
- Each member works on their own branch named after themselves (for example `youssef`), or one branch per piece (`youssef/1a-parser`) to keep pull requests small.
- Bring `main` into your branch often (`git pull origin main`), at least before opening a PR.

```
git switch -c <your-name>          # once
# ... work, commit ...
git pull origin main               # sync before opening a PR
git push -u origin <your-name>
gh pr create --base main           # or open the PR on GitHub
```

## Pull requests

A PR can merge into `main` only when:

1. **CI is green.**
2. **The other member has approved it.** The author cannot approve their own PR.
3. **It is up to date with `main`.**

Keep PRs focused on one piece (see `TEAM.md`). If a PR changes `compiler/types.py` or `compiler/grammar.md`, say so in the title; those changes need both of us to agree.

## CI

`.github/workflows/ci.yml` runs on every PR and every push to `main`: `ruff check .`, `ruff format --check .` and `pytest`. CI is offline: it never downloads a model, so classifier tests use a stub.

Run the same checks locally before pushing:

```
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest
```

`ruff format .` fixes formatting for you.

## Commits

Use the format `<type>: <description>`, where type is one of `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`.

## Tests

Every change comes with a test. Every bypass fix comes with a regression test containing the command string and the expected verdict. Never commit real secrets, and keep destructive commands inside tests that run in a temporary directory.
