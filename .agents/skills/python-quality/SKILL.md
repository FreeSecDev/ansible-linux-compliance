---
name: python-quality
description: Python quality standards for FreeSecDev controller tooling (tools/reporting, tools) and the shared typing, testing and static analysis rules for module code. Use when writing or reviewing Python for typing, Ruff, Pylint, Bandit, mypy strict, Pyright strict, pytest coverage thresholds, exception design, resource handling or serialization. Enforces 95% overall and 100% security-logic branch coverage through Makefile targets.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Python quality

Strictly typed, small, well-tested Python with minimal dependencies. Controller tooling
may use modern Python; target-side module code additionally follows the module constraints.

## When to use

- Writing or changing Python in `tools/reporting/`, `tools/` or tests.
- Reviewing typing, exceptions, resource handling, serialization or logging in any Python.
- Changing `pyproject.toml` tool configuration, coverage settings or lint ignores.
- Adding a Python dependency.
- Justifying a coverage exclusion or a lint suppression.

## Inputs

- Jira issue key and the code or configuration under change.
- `pyproject.toml` and the Makefile targets for the quality tools.
- The Python version floor and tool versions pinned in `pyproject.toml` and the lock files.
- For target-side code, the constraints in the `ansible-modules` skill.

## Outputs

- Typed code and tests that pass every Makefile quality target.
- Justified entries in `pyproject.toml` for each lint ignore or coverage exclusion.
- Coverage report evidence in the pull request.

## Conventions

- Controller tooling (`tools/reporting/`, `tools/`) targets Python 3.12 or newer. Target-side code (modules and `module_utils`) follows `ansible-modules`: standard library only and the managed-host Python versions supported by the pinned ansible-core.
- Typing: `mypy --strict` and Pyright strict both pass. No untyped defs, no implicit `Any`, no blanket `type: ignore`.
- Ruff lint uses a broad rule selection; every ignore is justified next to its entry in `pyproject.toml`. Ruff format is the only formatter.
- Pylint and Bandit run with no new suppressions.
- No inline comments. Docstrings are allowed and expected on public objects.
- Prefer frozen, slotted dataclasses or validated models for data. Avoid mutable module-level state and unnecessary globals.
- Define structured exception types with a stable base class; never use bare `except`, `except Exception: pass` or silent swallowing.
- Use context managers for files, processes, temporary directories and network clients.
- All I/O has timeouts; retries are bounded with backoff and only for idempotent operations.
- Safe serialization only: `json`, `yaml.safe_load`, `tomllib`. Never `pickle`, `marshal` or `yaml.load`.
- Never log secrets, tokens or full host evidence; redact at the logging boundary.
- Minimal third-party dependencies; each new one needs a justification and goes through `dependency-management`.
- Tests: pytest with branch coverage. See [references/testing-and-coverage.md](references/testing-and-coverage.md) and [references/pyproject-policy.md](references/pyproject-policy.md).
- Run everything through the Makefile: `make lint-python`, `make typecheck`, `make test-unit`, `make test-coverage`, `make security`.

## Quality gates

- `make lint-python` (Ruff lint, Ruff format check, Pylint) passes.
- `make typecheck` (mypy strict and Pyright strict) passes.
- `make test-unit` passes and `make test-coverage` reports at least 95% overall with branch coverage.
- Security decision logic (validation, path confinement, outcome classification, escaping) has 100% line and branch coverage.
- `make security` (Bandit and dependency audit) passes with no unjustified suppression.
- Coverage exclusions are listed in `pyproject.toml` with a reason.

## Common failures

- Chasing the coverage number with tests that assert nothing or only call functions.
- Using `# type: ignore` or `# noqa` instead of fixing the cause; inline comments are banned anyway.
- Catching `Exception` to keep a pipeline green and losing the error.
- Mutable default arguments or module-level caches that leak between tests.
- Opening files or subprocess pipes without a context manager.
- `yaml.load`, `pickle` or `eval` on report or exception files.
- Invoking tools directly instead of the Makefile, producing results CI cannot reproduce.
- Logging an entire environment or host evidence dictionary.

## Security requirements

- Treat report files, exception files and scanner output as hostile input; validate with typed models.
- Escape everything rendered into HTML at the template boundary; tests cover hostile strings.
- No secrets in code, fixtures, logs or test output.
- Subprocess use in controller code is an explicit argument list, `shell=False`, with a timeout.

## Documentation requirements

- Docstrings on public modules, classes and functions state purpose, inputs, outputs and raised errors.
- Document every `pyproject.toml` ignore and exclusion in place and in `docs/` when it affects contributors.
- Record an ADR when changing the Python floor, a core tool or the coverage policy.

## Completion criteria

- All five Makefile targets pass in CI, not only locally.
- Thresholds are met without new unjustified exclusions or suppressions.
- New dependencies are approved and pinned.
- Jira issue links the pull request and the CI run.

## Interaction with other skills

- Target-side module rules come from the `ansible-modules` skill.
- Report parsing and rendering code is exercised with the `reporting-dashboard` skill.
- Adversarial and parser-related changes are reviewed through the `security-review` skill.
- Dependency additions follow the `dependency-management` skill.
- CI wiring of the Makefile targets is handled by the `github-actions` skill.
- Review acceptance uses the `code-review` skill.
