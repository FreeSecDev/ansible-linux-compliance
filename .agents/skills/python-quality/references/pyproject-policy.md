# pyproject policy

## Ruff

- Select broadly (for example pyflakes, pycodestyle, isort, bugbear, security, simplify, pyupgrade, naming, annotations, return, pathlib, comprehensions, logging, raise, tryceratops, perflint, ruff-specific).
- Every ignore sits in `pyproject.toml` with a reason and, when temporary, a Jira issue.
- Per-file ignores are scoped narrowly and justified (for example test-only assertions).

## Typing

- mypy: `strict = true`, no per-module relaxations without a reason.
- Pyright: strict mode for all first-party code.
- Third-party stubs are pinned in the lock files.

## Pylint and Bandit

- Disable lists carry reasons. Bandit skips are rare and tied to a documented finding.

## Coverage

- Branch coverage enabled, `fail_under` set to the policy threshold, source limited to first-party packages.
- Exclusion patterns listed with reasons.

## Versions

Tool versions are the ones pinned in `pyproject.toml` and the lock files; skills and docs refer to them by file, not by number.
